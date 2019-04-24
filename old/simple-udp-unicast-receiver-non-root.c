/**
 * Does not create the RPL DAG and therefore does not become the network root, hoping this will solve the problem of not receiving any packages.
 * Publishes another service than the hidra mote that is root
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

// TODO gebruik voor verschillenden services verschillenden SERVICE_ID en verschillenden poorten
#define UDP_PORT 1234
#define OWN_SERVICE_ID 190
#define OTHER_SERVICE_ID 190

static struct simple_udp_connection unicast_connection;
uip_ipaddr_t *ipaddr;
uip_ipaddr_t *resource_addr;


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
PROCESS_THREAD(hidra_r, ev, data)
{ 
	PROCESS_BEGIN();
	
	SENSORS_ACTIVATE(button_sensor);

	ipaddr = set_global_address();

	simple_udp_register(&unicast_connection, UDP_PORT,
						  NULL, UDP_PORT,
						  receiver);

	while(1) {
		// At the click of the button, a packet will be sent
		PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));
	}
	
	PROCESS_END();
}

