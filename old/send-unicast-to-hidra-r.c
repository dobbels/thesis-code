/**
 * Does not create the RPL DAG and therefore does not become the network root.
 * Publishes service with number OWN_SERVICE_ID.
 */

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"
#include "servreg-hack.h"

#include "net/rpl/rpl.h"

#include <stdio.h>
#include <string.h>

#include "sys/node-id.h"

#include <stdio.h>
#include <string.h>

#include "dev/button-sensor.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define UDP_PORT 1234

static struct simple_udp_connection unicast_connection;

//Example of "setting ip address"
//uip_ipaddr_t ipaddr;
//struct uip_conn *c;
//
//uip_ipaddr(&ipaddr, 192,168,1,2);
//c = uip_connect(&ipaddr, UIP_HTONS(80));

uip_ipaddr_t resource_addr;


// Construct IPv4 address.
//#define uip_ipaddr(send_addr, 192, 0, 0, 1);
// Construct IPv6 address.
// TODO Bytes in decimals?
//#define uip_ip6addr(send_addr, 0xfd00, 0x0, 0x0, 0x0, 0xc30c, 0x0, 0x0, 0x1)


PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);
/*---------------------------------------------------------------------------*/
static void
receiver(struct simple_udp_connection *c,
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
  printf("Data Rx: %s\n", data);


  //TODO hier ga je wrs verschillenden soorten Hidra messages handlen adhv van de inhoud/poort waarop ze aankomen enz?!


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
static void
set_send_address(void)
{
	uip_ip6addr(&resource_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x212, 0x7402, 0x2, 0x202);

	printf("IPv6 send address: ");
    uip_debug_ipaddr_print(&resource_addr);
    printf("\n");
}
/*---------------------------------------------------------------------------*/
static void
send_unicast(void) //TODO om te vormen naar 'return unicast' voor antwoorden tijdens een protocol
{
	if(&resource_addr != NULL) {
		static unsigned int message_number;
		char buf[20];

		printf("Sending unicast to ");
		uip_debug_ipaddr_print(&resource_addr);
		printf("\n");
		sprintf(buf, "Message %d", message_number); //print into the buffer
		message_number++;

		// The same ports are used as were specified in the register-command
		printf("udp_conn: ");
		printf(((&unicast_connection)->udp_conn) != NULL);
		printf("\n");
		simple_udp_sendto(&unicast_connection, buf, strlen(buf) + 1, &resource_addr);
	} else {
		printf("No send_addr given\n");
	}
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hidra_r, ev, data)
{ 
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);

	set_send_address();
	set_global_address(); // TODO mag void zijn?

	// Register a socket, with host and remote port UDP_PORT
	// NULL parameter as the destination address to allow packets from any address. (fixed IPv6 address can be given)
	// Meerdere van deze listeners zijn mogelijk
	simple_udp_register(&unicast_connection, UDP_PORT,
						  NULL, UDP_PORT,
						  receiver);

	while(1) {
		// At the click of the button, a packet will be sent
		PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));
		printf("button pressed\n");
		send_unicast();
	}
	
	PROCESS_END();
}
