#include "contiki.h"
#include "lib/random.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"
#include "cfs/cfs.h"

#include <stdio.h>

#include "../tiny-AES-c/aes.h"

#include "../bit-operations.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define ACS_UDP_PORT 4321
#define RESOURCE_UDP_PORT 1996

//#define ID 3
static uint8_t subject_id = 0;

static uint8_t authentication_requested = 0;
static uint8_t credentials_requested = 0;
static uint8_t resource_access_requested = 0;
static uint8_t security_association_established = 0;

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_resource;

uip_ipaddr_t resource_addr;
uip_ipaddr_t acs_addr;

uint8_t subject_key[16] =
	{ (uint8_t) 0x7e, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

//TODO should be stored in file?
uint8_t credential_manager_key[16];
uint8_t credential_manager_nonce[8];

PROCESS(hidra_subject,"HidraSubject");
AUTOSTART_PROCESSES(&hidra_subject);

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

static uip_ipaddr_t *
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
  return &ipaddr;
}

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
}

PROCESS_THREAD(hidra_subject, ev, data)
{
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);
//	random_init();

	//use global address to deduce node-id
	subject_id = set_global_address()->u8[15];
	set_resource_address();
	set_acs_address();


	simple_udp_register(&unicast_connection_resource, RESOURCE_UDP_PORT,
						  NULL, RESOURCE_UDP_PORT,
						  receiver_resource);

	static int toggle = 0;
	while(1) {
		PROCESS_WAIT_EVENT();

		if ((ev==sensors_event) && (data == &button_sensor)) {
			printf("toggle: %d\n", toggle);
			if (toggle) {
				const char response = 0;
				simple_udp_sendto(&unicast_connection_resource, &response, sizeof(&response), &resource_addr);
				toggle = 0;
			} else {
				static uint8_t sesponse[53];
				sesponse[20] = 5;
				//Send message to credential manager
				simple_udp_sendto(&unicast_connection_resource, sesponse, sizeof(sesponse), &resource_addr);
				toggle = 1;
			}
		}

	}
	PROCESS_END();
}
