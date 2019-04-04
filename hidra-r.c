#include "contiki.h"
#include "lib/random.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"

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
//TODO To include:
// System attribute reference table (max nb: 256)
// Request attribute reference table (max nb: 256)
// Local attribute reference table (max nb: 8)
// Expression functions table (max nb: 256)
// Task functions table (max nb: 256)
// Target resource table (max nb: 256)

static void
unpack_policy(const uint8_t *data, uint16_t datalen, struct policy *dest_policy)
{
//	printf("datalen : %d\n",datalen);
//	printf("Dus max bit index : %d\n",datalen*8 - 1);
	int starting_index_next_structure = 0;
	// Unpack policy id and effect and check rule existence mask
	dest_policy->id = data[0];
	dest_policy->effect = get_bit(8, data); // to access the first bit

	printf("policy.id : %d\n", dest_policy->id);
	printf("policy.effect : %d\n", dest_policy->effect);
	if (get_bit(9, data)) { // TODO more efficiency? -> write (data[1] & 0x40) here
		dest_policy->rule_existence = 1;
		dest_policy->max_rule_index = get_3_bits_from(10, data);
		uint8_t nb_of_rules = dest_policy->max_rule_index + 1;
//		printf("nb_of_rules : %d\n",nb_of_rules);

		// Allocate the necessary memory in the heap for the specified number of rules
		dest_policy->rules = malloc(nb_of_rules * sizeof(struct rule));

		uint8_t current_rule_index = 0;
		starting_index_next_structure = 13;
		while(nb_of_rules) {

//			printf("Next rule: \n");
//			printf("starting_index_next_structure :  %d\n", starting_index_next_structure);
			// decodify rule and set starting_index_next_structure for the next rule
			starting_index_next_structure = unpack_rule(data, starting_index_next_structure,
					&(dest_policy->rules[current_rule_index]));

			nb_of_rules--;
			current_rule_index++;
		}
	} else {
		printf("There are no rules\n");
		dest_policy->rule_existence = 0;
	}
}
/*---------------------------------------------------------------------------*/
static int
unpack_rule(const uint8_t *data, int bit_index, struct rule *rule)
{
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

	printf("\n");
	printf("rule->id : %d\n", rule->id);
	printf("rule->effect : %d\n", rule->effect);
	printf("mask '%d' for rule->periodicity : %d\n", rule->periodicity_mask, rule->periodicity);
	printf("mask '%d' for rule->iteration :  %d\n", rule->iteration_mask, rule->iteration);
	printf("mask '%d' for rule->resource : %d\n", rule->resource_mask, rule->resource);
	printf("mask '%d' for rule->action : %d\n", rule->action_mask, rule->action);
	printf("mask '%d' for rule->obligationset\n", rule->obligationset_mask);

	rule->max_condition_index = get_3_bits_from(bit_index, data);
	bit_index += 3;
	uint8_t nb_of_expressions = rule->max_condition_index + 1;
	printf("nb_of_expressions : %d\n", nb_of_expressions);

	rule->conditionset = malloc(nb_of_expressions * sizeof(struct expression));

	uint8_t current_expression_index = 0;
	while(nb_of_expressions) {

		bit_index = unpack_expression(data, bit_index,
				&(rule->conditionset[current_expression_index]));

		nb_of_expressions--;
		current_expression_index++;
	}

	if (rule->obligationset_mask) {
		rule->max_obligation_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_obligations = rule->max_obligation_index + 1;
		printf("nb_of_obligations : %d\n", nb_of_obligations);

		rule->obligationset = malloc(nb_of_obligations * sizeof(struct obligation));

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
	printf("\n");
	printf("exp->function : %d\n", exp->function);
//	struct attribute *inputset; // if == NULL, then no attributes where given
	if(get_bit(bit_index,data)) {
		bit_index += 1;
		exp->input_existence = 1;

		exp->max_input_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_inputs = exp->max_input_index + 1;

		exp->inputset = malloc(nb_of_inputs * sizeof(struct attribute));

		uint8_t current_input_index = 0;
		while(nb_of_inputs) {

			bit_index = unpack_attribute(data, bit_index,
					&exp->inputset[current_input_index]);

			nb_of_inputs--;
			current_input_index++;
		}
	} else {
		bit_index += 1;
		exp->input_existence = 0;
	}

//	printf("exp->inputset (pointer or NULL) : %d\n", exp->inputset);

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

	printf("\n");
	printf("obl->fulfill_on : %d\n", obl->fulfill_on);
	return bit_index;
}
/*---------------------------------------------------------------------------*/
static int
unpack_task(const uint8_t *data, int bit_index, struct task *task)
{
	//	uint8_t function;
		task->function = get_char_from(bit_index, data);
		bit_index += 8;
		printf("\n");
		printf("exp->function : %d\n", task->function);

	//	struct attribute *inputset; // if == NULL, then no attributes where given
		if(get_bit(bit_index,data)) {
			bit_index += 1;
			task->input_existence = 1;

			task->max_input_index = get_3_bits_from(bit_index, data);
			bit_index += 3;
			uint8_t nb_of_inputs = task->max_input_index + 1;

			task->inputset = malloc(nb_of_inputs * sizeof(struct attribute));

			uint8_t current_input_index = 0;
			while(nb_of_inputs) {

				bit_index = unpack_attribute(data, bit_index,
						&task->inputset[current_input_index]);

				nb_of_inputs--;
				current_input_index++;
			}
		} else {
			bit_index += 1;
			task->input_existence = 0;
		}

//		printf("exp->inputset (pointer or NULL) : %d\n", task->inputset);

		return bit_index;
}
/*---------------------------------------------------------------------------*/
static int
unpack_attribute(const uint8_t *data, int bit_index, struct attribute *attr)
{
//	uint8_t type : 3;
//	printf("\n");
//	printf("bit_index : %d\n", bit_index);
//	print_bits(get_char_from(bit_index, data));
//	print_bits(get_3_bits_from(bit_index, data));
//	printf("get_3_bits_from(bit_index, data) : %d\n", get_3_bits_from(bit_index, data));

//	uint8_t temp = get_3_bits_from(bit_index, data);
//	printf("temp : %d\n", temp);

	attr->type = get_3_bits_from(bit_index, data);
	bit_index += 3;

	printf("\n");
	printf("attr->type : %d\n", attr->type);

	if (attr->type == 0) {
		// type : BOOLEAN
		//	uint8_t bool_value : 1;
		attr->bool_value = get_bit(bit_index, data);
		bit_index += 1;
		printf("attr->bool_value : %d\n", attr->bool_value);
	} else if (attr->type == 1) {
		// type : BYTE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (BYTE) : %d\n", attr->char_value);
	} else if (attr->type == 2) {
		// type : INTEGER
		//	int int_value;
		attr->int_value = get_int16_from(bit_index, data);
		bit_index += 16;
		// TODO hidra-r.c:450:3: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘int32_t’ [-Wformat]
		printf("attr->int_value : %d\n", attr->int_value);
	} else if (attr->type == 3) {
		// type : FLOAT
		//	float float_value;
		printf("Warning: Float not yet supported by policy\n");
		attr->float_value = get_float_from(bit_index, data);
		bit_index += 32;
		// TODO hidra-r.c:456:3: warning: format ‘%f’ expects argument of type ‘double’, but argument 2 has type ‘float’ [-Wformat]
		// Normaal lukt die cast van float naar double wel?!
		printf("attr->float_value : %f\n", attr->float_value);
	} else if (attr->type == 4) { //TODO include a length specifier in codification? Is a lot easier in this calculation
		// type : STRING
		//	char *string_value;
		attr->string_length = get_3_bits_from(bit_index, data);
		int nb_of_characters = attr->string_length;
		bit_index += 3;
		printf("nb_of_characters : %d\n", nb_of_characters);

		attr->string_value = malloc(nb_of_characters * sizeof(attr->string_value));//TODO ipv sizeof(char). Eleganter dan hierboven, eigenlijk. Verander nog?

		int char_index;
		for (char_index = 0 ; char_index < nb_of_characters ; char_index++) {
			attr->string_value[char_index] = get_char_from(bit_index, data);
//			printf("attr->string_value[%d] %c\n",char_index, attr->string_value[char_index]);
			bit_index += 8;
		}

//		attr->string_value[nb_of_characters] = '\0';

		printf("attr->string_value : \"%s\"\n", attr->string_value);
//		puts(attr->string_value);
	} else if (attr->type == 5) {
		// type : REQUEST REFERENCE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (REQUEST) : %d\n", attr->char_value);
	} else if (attr->type == 6) {
		// type : SYSTEM REFERENCE
		//	uint8_t char_value;
		attr->char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (SYSTEM) : %d\n", attr->char_value);
	} else if (attr->type == 7) {
		// type : LOCAL REFERENCE
		//	uint8_t char_value : 3;
		attr->local_reference_value = get_3_bits_from(bit_index,data);
		bit_index += 3;
		printf("attr->local_reference_value (LOCAL) : %d\n", attr->local_reference_value);
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

//	printf("\n");
//	printf("start_index: %d\n",start_index);
//	printf("end_index: %d\n",end_index);
//	printf("start_block: %d\n",start_block);
//	printf("end_block: %d\n",end_block);
//	printf("nb_of_bits: %d\n",nb_of_bits);

	if (start_block == end_block) {
		mask1 = get_mask_for(nb_of_bits);
//		printf("mask1: %d\n",mask1);
//		printf("data[start_block]: %d\n",data[start_block]);
//		printf("(data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1: %d\n",(data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1);
		return (data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1;
	} else {
		int start_block_relative_index = start_index % 8;
		mask1 = get_mask_for(8 - start_block_relative_index);

		int end_block_relative_index = end_index % 8;
		mask2 = get_mask_for(end_block_relative_index);

		int nb_of_bits_in_next_block = end_block_relative_index;

		return ((data[start_block] & mask1) << nb_of_bits_in_next_block |
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
static int16_t
get_int16_from(int index, const uint8_t *data) {
	int16_t result = ((((int16_t)get_char_from(index, data)) & 0xff) << 8 |
			(get_char_from(index+8, data) & 0xff));
	printf("%d\n", result);
	return result;
}
/*---------------------------------------------------------------------------*/
static float
get_float_from(int index, const uint8_t *data) {
	int32_t result = (((int32_t)get_char_from(index, data)) & 0xff) << 24 |
				((int32_t)get_char_from(index+8, data)  & 0xff) << 16 |
				(get_char_from(index+16, data)  & 0xff) << 8 |
				(get_char_from(index+24, data) & 0xff);
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
