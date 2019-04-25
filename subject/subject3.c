#include "contiki.h"

#include "net/ipv6/uip-ds6.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"

#include <stdio.h>

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define ACS_UDP_PORT 4321
#define RESOURCE_UDP_PORT 1996

#define ID 5

static uint8_t authentication_requested = 0;
static uint8_t credentials_requested = 0;
static uint8_t resource_access_requested = 0;
static uint8_t security_association_established = 0;

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_resource;

uip_ipaddr_t resource_addr;
uip_ipaddr_t acs_addr;

PROCESS(hidra_subject,"HidraSubject");
AUTOSTART_PROCESSES(&hidra_subject);

static void
receiver_resource(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	printf("\nData received from: ");
	PRINT6ADDR(sender_addr);
	printf("\nAt port %d from port %d with length %d\n",
		  receiver_port, sender_port, datalen);
	printf("Data Rx: %.*s\n", datalen, data);
	if (resource_access_requested) {
		if(data[0]){
			printf("End of Successful Hidra Exchange.\n");
			security_association_established = 1;
		} else {
			printf("Received Non-Acknowledge: Unsuccessful hidra exchange.\n");
		}
	} else {
		printf("Unexpected message from resource\n");
	}
}

static void
send_access_request(void) {
	//Content of access request, all full bytes for simplicity
	// = id (1 byte) + action (1 byte) + system_reference (1 byte)
	const char action =  2;//PUT
	const char function =  18;
	const char response[3] = {ID, action, function};
	simple_udp_sendto(&unicast_connection_resource, response, strlen(response), &resource_addr);
	resource_access_requested = 1;
}

static void
receiver_acs(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	printf("\nData received from: ");
	PRINT6ADDR(sender_addr);
	printf("\nAt port %d from port %d with length %d\n",
		  receiver_port, sender_port, datalen);
	printf("Data Rx: %.*s\n", datalen, data);
	if (authentication_requested) {
		if (credentials_requested) {
				// Perform phase 3, the access request
				send_access_request();
		} else {
			// Perform phase 2
			const char response = ID;
			simple_udp_sendto(&unicast_connection_acs, &response, strlen(&response), &acs_addr);
			credentials_requested = 1;
		}
	} else {
		printf("Unexpected message from ACS\n");
	}
}

static void
start_hidra_protocol(void) {
	//TODO zou 15 bytes lang moeten zijn?! Maar nog geen crypto. Dat begint in ACS.
	const char response = ID;
	simple_udp_sendto(&unicast_connection_acs, &response, strlen(&response), &acs_addr);
	authentication_requested = 1;
}

static void
set_resource_address(void)
{
	uip_ip6addr(&resource_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 0x2);
}

static void
set_acs_address(void)
{
	uip_ip6addr(&acs_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0x1);
}

static void
set_global_address(void)
{
  static uip_ipaddr_t ipaddr;
  int i;
  uint8_t state;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  printf("IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
    }
  }
}

PROCESS_THREAD(hidra_subject, ev, data)
{
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);

	set_global_address();
	set_resource_address();
	set_acs_address();

	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);

	simple_udp_register(&unicast_connection_resource, RESOURCE_UDP_PORT,
						  NULL, RESOURCE_UDP_PORT,
						  receiver_resource);

	while(1) {
		PROCESS_WAIT_EVENT();

		if ((ev==sensors_event) && (data == &button_sensor)) {
			if (!security_association_established) {
				printf("Starting Hidra Protocol\n");
				start_hidra_protocol();
			}
		}
	}
	PROCESS_END();
}
