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
//static void
//set_global_address(void)
//{
//  uip_ipaddr_t ipaddr;
//  int i;
//  uint8_t state;
//
//  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
//  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
//  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);
//
//  printf("IPv6 addresses: ");
//  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
//    state = uip_ds6_if.addr_list[i].state;
//    if(uip_ds6_if.addr_list[i].isused &&
//       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
//      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
//      printf("\n");
//    }
//  }
//}
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
send_unicast(void) //TODO om te vormen naar 'return unicast' voor antwoorden tijdens een protocol
{
//	This function returns the address of the node offering a specific service.
//	If the service is not known, the function returns NULL.
//	If there are more than one nodes offering the service, this function
//	returns the address of the node that most recently announced its service.
	resource_addr = servreg_hack_lookup(OTHER_SERVICE_ID);

	if(resource_addr != NULL) {
		static unsigned int message_number;
		char buf[20];

		printf("Sending unicast to ");
		uip_debug_ipaddr_print(resource_addr);
		printf("\n");
		sprintf(buf, "Message %d", message_number);
		message_number++;
		simple_udp_sendto(&unicast_connection, buf, strlen(buf) + 1, resource_addr);
	} else {
		printf("Service %d not found\n", OTHER_SERVICE_ID);
	}
}
/*---------------------------------------------------------------------------*/
static void
create_rpl_dag(uip_ipaddr_t *ipaddr)
{
  struct uip_ds6_addr *root_if;

  root_if = uip_ds6_addr_lookup(ipaddr);
  if(root_if != NULL) {
    rpl_dag_t *dag;
    uip_ipaddr_t prefix;

    rpl_set_root(RPL_DEFAULT_INSTANCE, ipaddr);
    dag = rpl_get_any_dag();
    uip_ip6addr(&prefix, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
    rpl_set_prefix(dag, &prefix, 64);
    PRINTF("created a new RPL dag\n");
  } else {
    PRINTF("failed to create a new RPL DAG\n");
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(hidra_r, ev, data)
{ 
	PROCESS_BEGIN();
	
	SENSORS_ACTIVATE(button_sensor);

	servreg_hack_init();

	ipaddr = set_global_address();

	create_rpl_dag(ipaddr);

	servreg_hack_register(OWN_SERVICE_ID, ipaddr);

	// NULL parameter as the destination address to allow packets from any address.
	// Meerdere van deze listeners zijn mogelijk
	simple_udp_register(&unicast_connection, UDP_PORT,
						  NULL, UDP_PORT,
						  receiver);

	while(1) {
		// At the click of the button, a packet will be sent
		PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));

		send_unicast();
	}
	
	PROCESS_END();
}

