#include "contiki.h"
//#include "lib/random.h"
//#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"
//
//#include "net/rpl/rpl.h"
//
//#include <stdio.h>
//#include <string.h>
//
//#include "sys/node-id.h"

#include "policy.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define ACS_UDP_PORT 1234
#define SUBJECT_UDP_PORT 4321

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_subject;

uip_ipaddr_t send_addr;

char HID_CM_IND_SUCCESS = 0;
char HID_CM_IND_REQ_SUCCESS = 0;

struct policy policy;

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);
/*---------------------------------------------------------------------------*/
static void
handle_hidra_subject_exchanges(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	char *first_exchange = "HID_S_R_REQ";
	char first_exchange_len = strlen(first_exchange);

	//TODO nog beter strcmp() gebruiken? Of niet zeker van null termination overal?
	if (HID_CM_IND_REQ_SUCCESS && datalen == first_exchange_len && memcmp(data, first_exchange, first_exchange_len) == 0) {
		char *response = "HID_S_R_REP";
		simple_udp_sendto(c, response, strlen(response), sender_addr);
		HID_CM_IND_REQ_SUCCESS = 0;
		HID_CM_IND_SUCCESS = 0;
		printf("\n");
		printf("End of Hidra exchange with Subject\n");
	}
	else {
		printf("Did not receive from subject what was expected.");
	}
}
/*---------------------------------------------------------------------------*/
static void
receiver_subject(struct simple_udp_connection *c,
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
  printf("Data Rx: %*s\n", datalen, data); //datalen specification: because previous messages remain in buffer
  printf("\n");

  handle_hidra_subject_exchanges(c, sender_addr, data, datalen);

}
/*---------------------------------------------------------------------------*/
static void
set_up_hidra_association(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
	///////////////////////////////////////////////////////////////////////////////////
	// Test area outside Hidra association establishment: unpack policy into local policy. To be included in the protocol later

//	int i = 0;
//	for ( ; i < datalen ; i++) {
//		print_bits(data[i]);
//	}
	unpack_policy(data, datalen, &policy);

	//End of test area
	///////////////////////////////////////////////////////////////////////////////////

//	uint8_t *first_exchange = "HID_CM_IND";
//	char first_exchange_len = strlen(first_exchange);
//	uint8_t *second_exchange = "HID_CM_IND_REP";
//	char second_exchange_len = strlen(second_exchange);
//
//	if (datalen == first_exchange_len && memcmp(data, first_exchange, first_exchange_len) == 0) {
//		uint8_t *response = "HID_CM_IND_REQ";
//		simple_udp_sendto(c, response, strlen(response), sender_addr);
//		HID_CM_IND_SUCCESS = 1;
//	}
//	else if (HID_CM_IND_SUCCESS
//			&& datalen == second_exchange_len
//			&& memcmp(data, second_exchange, second_exchange_len) == 0) {
//		HID_CM_IND_REQ_SUCCESS = 1;
//		printf("\n");
//		printf("End of Hidra exchange with ACS\n");
//	}
//	else {
//		printf("Did not receive from ACS what was expected in the protocol.\n");
//	}
}
/*---------------------------------------------------------------------------*/
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
  printf("Data Rx: %*s\n", datalen, data);
  printf("\n");

  set_up_hidra_association(c, sender_addr, data, datalen);

}
/*---------------------------------------------------------------------------*/
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
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hidra_r, ev, data)
{ 
	PROCESS_BEGIN();

//	SENSORS_ACTIVATE(button_sensor);

//	set_send_address();
	set_global_address(); // TODO mag void zijn?

	// Register a sockets, with the correct host and remote ports
	// NULL parameter as the destination address to allow packets from any address. (fixed IPv6 address can be given)
	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);
	simple_udp_register(&unicast_connection_subject, SUBJECT_UDP_PORT,
							  NULL, SUBJECT_UDP_PORT,
							  receiver_subject);

	while(1) {
		// At the click of the button, a packet will be sent
//		PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));
//		printf("button pressed\n");
//		send_unicast();

		PROCESS_WAIT_EVENT();
	}
	
	PROCESS_END();
}


///////////////////
//POLICY RELATED DEFINITIONS

//
///////////////////
