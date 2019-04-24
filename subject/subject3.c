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

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_resource;

uip_ipaddr_t resource_addr;

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

static void
receiver_resource(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

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
}

static void
set_resource_address(void)
{
	uip_ip6addr(&resource_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 0x2);
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

PROCESS_THREAD(hidra_r, ev, data)
{
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);

	set_global_address();
	set_resource_address();

	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);

	simple_udp_register(&unicast_connection_resource, RESOURCE_UDP_PORT,
						  NULL, RESOURCE_UDP_PORT,
						  receiver_resource);

	while(1) {
		PROCESS_WAIT_EVENT();

		if ((ev==sensors_event) && (data == &button_sensor)) {
			char *response = "COMMUNICATION TEST";
			simple_udp_sendto(&unicast_connection_resource, response, strlen(response), &resource_addr);
		}
	}

	PROCESS_END();
}
