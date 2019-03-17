/**
 *
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

#include "dev/button-sensor.h"

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

//TODO als te veel geheugen in gebruik: opslaan in APBR codificatie (je kan velden in struct een bepaald aantal bits geven = bitfields?) en op gebruik uitpakken
struct policy {
	unsigned char id;
	unsigned char effect : 1;
	struct rule *rules;
} policy;

struct rule {
	unsigned char id;
	unsigned char effect : 1;
	unsigned char periodicity;
	unsigned char iteration;
	unsigned char resource;
	unsigned char action : 3;
	struct expression *conditionset;
	struct obligation *obligationset;
};

struct expression {

};

struct obligation {

};

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

	uint8_t *first_exchange = "HID_S_R_REQ";
	char first_exchange_len = strlen(first_exchange);

	//TODO nog beter strcmp() gebruiken? Of niet zeker van null termination overal?
	if (HID_CM_IND_REQ_SUCCESS && datalen == first_exchange_len && memcmp(data, first_exchange, first_exchange_len) == 0) {
		uint8_t *response = "HID_S_R_REP";
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
         const uint8_t *data, //TODO vraag: hoe is deze data eigenlijk opgeslagen? Wrs is zo'n uint8_t een struct met een byte een pointer naar de volgende in de rij? -> zou heel leuk zijn om eindelijk die error weg te krijgen en te kunnen doorklikken naar die declaraties!
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
static unsigned char
get_mask_for(int nb_of_bits) {
	char mask;
	if (nb_of_bits == 1) {
		mask = 0x01;
	} else if (nb_of_bits == 2) {
		mask = 0x03;
	} else if (nb_of_bits == 3) {
		mask = 0x07;
	} else if (nb_of_bits == 4) {
		mask = 0x0f;
	} else if (nb_of_bits == 5) {
		mask = 0x1f;
	} else if (nb_of_bits == 6) {
		mask = 0x3f;
	} else if (nb_of_bits == 7) {
		mask = 0x7f;
	} else if (nb_of_bits == 8) {
		mask = 0xff;
	}
	return mask;
}
/*---------------------------------------------------------------------------*/
/*
 * The indices are bit indices in a byte array
 * Preconditions:
 * 	0 < end_index - start_index <= 8
 * 	indices are not out of bounds
 */
static unsigned char
get_bits_between(int start_index, int end_index, const uint8_t *data) {

	int start_block = start_index / 8;
	int end_block = (end_index - 1) / 8;
	int nb_of_bits = end_index - start_index;
	char mask1;
	char mask2;

	if (start_block == end_block) {
		mask1 = get_mask_for(nb_of_bits);
		return (data[start_block]>>(8-nb_of_bits)) & mask1;
	} else {
		int start_block_relative_index = start_index % 8;
		mask1 = get_mask_for(8 - start_block_relative_index);

		int end_block_relative_index = end_index % 8;
		mask2 = get_mask_for(end_block_relative_index);


		;

		return ((data[start_block] & mask1) |
				((data[end_block]>>(8-end_block_relative_index)) & mask2));
	}
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_bit(int index, const uint8_t *data) {
	return get_bits_between(index, index+1, data);
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_3_bits(int index, const uint8_t *data) {
	return get_bits_between(index, index+3, data);
}
/*---------------------------------------------------------------------------*/
static void
print_bits(unsigned char data) {
	printf("%d%d%d%d%d%d%d%d\n",
			(data >> 7) & 0x01,
			(data >> 6) & 0x01,
			(data >> 5) & 0x01,
			(data >> 4) & 0x01,
			(data >> 3) & 0x01,
			(data >> 2) & 0x01,
			(data >> 1) & 0x01,
			(data) & 0x01);
}
/*---------------------------------------------------------------------------*/
static void
handle_hidra_acs_exchanges(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	///////////////////////////////////////////////////////////////////////////////////
	// Test area: unpack policy into local policy. To be included in the protocol later

	int starting_index_next_structure = 0;
	// Unpack policy id and effect and check rule existence mask
	policy.id = data[0];
	policy.effect = get_bit(8, data); // to access the first bit
	if (get_bit(9, data)) { // TODO more efficiency? -> write (data[1] & 0x40) here
		unsigned char nb_of_rules = get_3_bits(10, data);
		//TODO
		while(nb_of_rules) {
			// decodify rule

			// increment starting_index_next_structure with the right amount
			nb_of_rules--;
		}
	} else {
		printf("There are no rules\n");
		policy.rules = NULL;
	}

	printf("%d\n", policy.id);
	printf("%d\n", policy.effect);
	print_bits(policy.effect);

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

  handle_hidra_acs_exchanges(c, sender_addr, data, datalen);

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

//	uip_ip6addr(&send_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 1);
//	uip_ip6addr(&send_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0x212, 0x7402, 0x2, 0x202);
	uip_ip6addr(&send_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0x1); // to the Java ACS Server

	printf("IPv6 send address: ");
    uip_debug_ipaddr_print(&send_addr);
    printf("\n");
}
/*---------------------------------------------------------------------------*/
static void
send_unicast(void)
{
	if(&send_addr != NULL) { // TODO hidra-r.c:116:16: warning: the comparison will always evaluate as ‘true’ for the address of ‘send_addr’ will never be NULL [-Waddress]
								// Maar zonder die pointer geeft het echt een error? wat als *(&send_addr), maakt dat een verschil?
								// Waarom is dit dan niet triviaal? addr = servreg_hack_lookup(SERVICE_ID);
	    						// 									if(addr != NULL) {
		static unsigned int message_number;
		char buf[20];

		printf("Sending unicast to ");
		uip_debug_ipaddr_print(&send_addr);
		printf("\n");
		sprintf(buf, "Message %d", message_number); //print into the buffer
		message_number++;

		// To send, the same ports are used as were specified in the register-command
		// Be mindful of strlen(buf) + 1 when unpacking messages -> deleted now TODO was there good reason for this?
		simple_udp_sendto(&unicast_connection_acs, buf, strlen(buf), &send_addr);
	} else {
		printf("No send_addr given\n");
	}
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

