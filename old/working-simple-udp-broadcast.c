//Makefile toen het werkte:
//CONTIKI_PROJECT = hidra-r
//all: $(CONTIKI_PROJECT)
//
//UIP_CONF_IPV6=1
//CFLAGS+= -DUIP_CONF_IPV6_RPL
//
//#For some reason, without this line, motes do not receive UDP broadcast from eachother (which is not necessary at first, with only one HidraR mote, but maybe later on)
//APPS=servreg-hack
//
//CONTIKI = contiki
//include $(CONTIKI)/Makefile.include

// Ook makkelijk aant passen naar gebruik met button. Veel meer overzichtelijk.

#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "sys/etimer.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"


#include <stdio.h>
#include <string.h>

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"


#define UDP_PORT 1234

#define SEND_INTERVAL		(20 * CLOCK_SECOND)
#define SEND_TIME		(random_rand() % (SEND_INTERVAL))

static struct simple_udp_connection broadcast_connection;


PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

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
}

PROCESS_THREAD(hidra_r, ev, data)
{ 
	static struct etimer periodic_timer;
	static struct etimer send_timer;
	uip_ipaddr_t addr;

	PROCESS_BEGIN();
	
	//	NULL parameter as the destination address to allow packets from any address.
	simple_udp_register(&broadcast_connection, UDP_PORT,
						  NULL, UDP_PORT,
						  receiver);

	  etimer_set(&periodic_timer, SEND_INTERVAL);
	  while(1) {
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
		etimer_reset(&periodic_timer);
		etimer_set(&send_timer, SEND_TIME);

		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&send_timer));
		printf("Sending broadcast\n");
		uip_create_linklocal_allnodes_mcast(&addr);

		PRINT6ADDR(&addr);
		printf("\n");
		simple_udp_sendto(&broadcast_connection, "You can have access", 19, &addr);
	  }
	
	PROCESS_END();
}

