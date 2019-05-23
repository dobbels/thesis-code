#include "contiki.h"

#include "net/ip/uip.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6-nbr.h"

#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define SERVER_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

static struct simple_udp_connection unicast_connection_server;
static struct simple_udp_connection unicast_connection_subject;

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

static void
receiver_subject(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

}

static void
receiver_server(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

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

  return &ipaddr;
}

PROCESS_THREAD(hidra_r, ev, data)
{
	PROCESS_BEGIN();

//	SENSORS_ACTIVATE(button_sensor);

	set_global_address();

	// Register a sockets, with the correct host and remote ports
	// NULL parameter as the destination address to allow packets from any address. (fixed IPv6 address can be given)
	simple_udp_register(&unicast_connection_server, SERVER_UDP_PORT,
						  NULL, SERVER_UDP_PORT,
						  receiver_server);
	simple_udp_register(&unicast_connection_subject, SUBJECT_UDP_PORT,
							  NULL, SUBJECT_UDP_PORT,
							  receiver_subject);

	while(1) {
		PROCESS_WAIT_EVENT();
	}

	PROCESS_END();
}
