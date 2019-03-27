#include "contiki.h"
#include "lib/random.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"
#include "servreg-hack.h" //TODO verwijder, net als servreg in Makefile

#include "net/rpl/rpl.h"

#include <stdio.h>
#include <string.h>

#include "sys/node-id.h"

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
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	///////////////////////////////////////////////////////////////////////////////////
	// Test area outside Hidra association establishment: unpack policy into local policy. To be included in the protocol later

	unpack_policy(data, datalen);

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
struct policy policy;

//TODO To include:
// System attribute reference table (max nb: 256)
// Request attribute reference table (max nb: 256)
// Local attribute reference table (max nb: 8)
// Expression functions table (max nb: 256)
// Task functions table (max nb: 256)
// Target resource table (max nb: 256)

static void
unpack_policy(const uint8_t *data, uint16_t datalen)
{
	int starting_index_next_structure = 0;
	// Unpack policy id and effect and check rule existence mask
	policy.id = data[0];
	policy.effect = get_bit(8, data); // to access the first bit
	if (get_bit(9, data)) { // TODO more efficiency? -> write (data[1] & 0x40) here
		uint8_t nb_of_rules = get_3_bits_from(10, data) + 1;
		uint8_t current_rule_index = 0;
		starting_index_next_structure = 13;
		while(nb_of_rules) {
			//TODO ? check every time if datalen*8 is still >= starting_index_next_structure

			// decodify rule and set starting_index_next_structure for the next rule
			starting_index_next_structure = unpack_rule(data, starting_index_next_structure,
					&policy.rules[current_rule_index]);

			nb_of_rules--;
			current_rule_index++;
		}
	} else {
		printf("There are no rules\n");
		policy.rules = NULL;
	}

	printf("%d\n", policy.id);
	printf("%d\n", policy.effect);
	print_bits(policy.effect);
}
/*---------------------------------------------------------------------------*/
static int
unpack_rule(const uint8_t *data, int bit_index, struct rule *rule)
{ //TODO verander nog rule_index door gewoon de juiste rule mee te geven als argument.
  // 	Dit is namelijk alleen mogelijk doordat je nu ff maar 1 policy hebt. Je moet sowieso pointer naar policy of juiste rule mee geven anders.
	rule->id = get_char_from(bit_index, data);
	bit_index += 8;

	rule->effect = get_bit(bit_index, data);
	bit_index += 1;

	rule->periodicity_mask = get_bit(bit_index, data);
	bit_index += 1;
	rule->iteration_mask = get_bit(bit_index, data);
	bit_index += 1;
	rule->resource_mask = get_bit(bit_index, data);
	bit_index += 1;
	rule->action_mask = get_bit(bit_index, data);
	bit_index += 1;
	rule->obligationset_mask = get_bit(bit_index, data);
	bit_index += 1;

	if (rule->periodicity_mask) {
		rule->periodicity = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (rule->iteration_mask) {
		rule->iteration = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (rule->resource_mask) {
		rule->resource = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (rule->action_mask) {
		rule->action = get_3_bits_from(bit_index, data);
		bit_index += 3;
	}

	uint8_t nb_of_expressions = get_3_bits_from(bit_index, data) + 1;
	bit_index += 3;
	uint8_t current_expression_index = 0;
	while(nb_of_expressions) {

		bit_index = unpack_expression(data, bit_index,
				&(rule->conditionset[current_expression_index]));

		nb_of_expressions--;
		current_expression_index++;
	}

	if (rule->obligationset_mask) {
		uint8_t nb_of_obligations = get_3_bits_from(bit_index, data) + 1;
		bit_index += 3;
		uint8_t current_obligation_index = 0;
		while(nb_of_obligations) {

			bit_index = unpack_obligation(data, bit_index,
					&(rule->obligationset[current_obligation_index]));

			nb_of_obligations--;
			current_obligation_index++;
		}
	}

	return bit_index;
}
/*---------------------------------------------------------------------------*/
static int
unpack_expression(const uint8_t *data, int bit_index, struct expression *exp)
{
//	uint8_t function;
	exp->function = get_char_from(bit_index, data);
	bit_index += 8;
//	struct attribute *inputset; // if == NULL, then no attributes where given
	if(get_bit(bit_index,data)) {
		bit_index += 1;
		uint8_t nb_of_inputs = get_3_bits_from(bit_index, data) + 1;
		bit_index += 3;
		uint8_t current_input_index = 0;
		while(nb_of_inputs) {

			bit_index = unpack_attribute(data, bit_index,
					&exp->inputset[current_input_index]);

			nb_of_inputs--;
			current_input_index++;
		}
	} else {
		bit_index += 1;
		exp->inputset = NULL;
	}

	return bit_index;

}
/*---------------------------------------------------------------------------*/
static int
unpack_obligation(const uint8_t *data, int bit_index, struct obligation *obl)
{
//	struct task task;
	bit_index = unpack_task(data, bit_index, &obl->task);
//	uint8_t fulfill_on : 2; // a value of 0 : on deny, 1 : on permit, 2 : 'always execute', 3 : undefined
	if (get_bit(bit_index, data)) {
		bit_index += 1;
		obl->fulfill_on = get_bit(bit_index, data);
		bit_index += 1;
	} else {
		bit_index += 1;
		// Always execute task
		obl->fulfill_on = 2;
	}

	return bit_index;
}
/*---------------------------------------------------------------------------*/
static int
unpack_task(const uint8_t *data, int bit_index, struct task *task)
{
	//	uint8_t function;
		task->function = get_char_from(bit_index, data);
		bit_index += 8;
	//	struct attribute *inputset; // if == NULL, then no attributes where given
		if(get_bit(bit_index,data)) {
			bit_index += 1;
			uint8_t nb_of_inputs = get_3_bits_from(bit_index, data) + 1;
			bit_index += 3;
			uint8_t current_input_index = 0;
			while(nb_of_inputs) {

				bit_index = unpack_attribute(data, bit_index,
						&task->inputset[current_input_index]);

				nb_of_inputs--;
				current_input_index++;
			}
		} else {
			bit_index += 1;
			task->inputset = NULL;
		}

		return bit_index;
}
/*---------------------------------------------------------------------------*/
static int
unpack_attribute(const uint8_t *data, int bit_index, struct attribute *attr)
{
//	uint8_t type : 3;
	attr->type = get_3_bits_from(bit_index, data);
	bit_index += 3;

	if (attr->type == 0) {
		// type : BOOLEAN
		//	uint8_t bool_value : 1;
		attr->bool_value = get_bit(bit_index, data);
		bit_index += 1;
	} else if (attr->type == 1) {
		// type : BYTE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
	} else if (attr->type == 2) {
		// type : INTEGER
		//	int int_value;
		attr->int_value = get_int_from(bit_index, data);
		bit_index += 32;
	} else if (attr->type == 3) {
		// type : FLOAT
		//	float float_value;
		attr->float_value = get_float_from(bit_index, data);
		bit_index += 32;
	} else if (attr->type == 4) { //TODO include a length specifier in codification? Is a lot easier in this calculation
		// type : STRING
		//	char *string_value;
		int nb_of_characters = 0;
		int bit_index_copy = bit_index;
		while(get_char_from(bit_index_copy, data) != '\0') {
			nb_of_characters += 1;
			bit_index_copy += 8;
		}
		printf("String attribute length : %d\n", nb_of_characters);
		char dest[nb_of_characters];
		int char_index = 0;
		while(get_char_from(bit_index, data) != '\0') {
			dest[char_index] = get_char_from(bit_index, data);
			bit_index += 8;
		}
		bit_index += 8; //TODO \0 character is 8 bits, right?

		memset(dest, '\0', sizeof(dest));

		strcpy(attr->string_value, dest);

		printf("String attribute : %s\n", attr->string_value);

		// TODO puts() is mss een handige methode om strings te printen. Voegt ook zelf een \n character toe
	} else if (attr->type == 5) {
		// type : REQUEST REFERENCE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
	} else if (attr->type == 6) {
		// type : SYSTEM REFERENCE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
	} else if (attr->type == 7) {
		// type : LOCAL REFERENCE
		//	uint8_t char_value : 3;
		attr->local_reference_value = get_3_bits_from(bit_index,data);
		bit_index += 3;
	} else {
		printf("Error while unpacking attribute\n");
	}

	return bit_index;
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_mask_for(int nb_of_bits) {
	char mask = 0;
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
static uint8_t
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

		return ((data[start_block] & mask1) |
				((data[end_block]>>(8-end_block_relative_index)) & mask2));
	}
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_bit(int index, const uint8_t *data) {
	return get_bits_between(index, index+1, data);
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_3_bits_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+3, data);
}
/*---------------------------------------------------------------------------*/
static uint8_t
get_char_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+8, data);
}
/*---------------------------------------------------------------------------*/
static int32_t
get_int_from(int index, const uint8_t *data) {
	int32_t result = (((int32_t)get_bits_between(index, index+8, data)) & 0xff) << 24 |
			((int32_t)get_bits_between(index+8, index+16, data)  & 0xff) << 16 |
			(get_bits_between(index+16, index+24, data)  & 0xff) << 8 |
			(get_bits_between(index+24, index+32, data) & 0xff);
	return result;
}
/*---------------------------------------------------------------------------*/
static float
get_float_from(int index, const uint8_t *data) {
	int32_t result = (((int32_t)get_bits_between(index, index+8, data)) & 0xff) << 24 |
				((int32_t)get_bits_between(index+8, index+16, data)  & 0xff) << 16 |
				(get_bits_between(index+16, index+24, data)  & 0xff) << 8 |
				(get_bits_between(index+24, index+32, data) & 0xff);
	return *((float*)&result);
}
/*---------------------------------------------------------------------------*/
static void
print_bits(uint8_t data) {
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
//
///////////////////
