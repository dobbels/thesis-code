#include "contiki.h"

#include "lib/random.h"
#include "net/ip/uip.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6-nbr.h"

#include "net/ipv6/uip-ds6.h"
#include "dev/leds.h"
//#include "dev/button-sensor.h"
#include "simple-udp.h"

#include "lib/memb.h"
#include "cfs/cfs.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "policy.h"
#include "../../encoded-policy.h"
#include "../../bit-operations.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#include "rtimer.h"

unsigned long timestamp;

#define SERVER_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

#define MAX_NUMBER_OF_SUBJECTS 3

static struct simple_udp_connection unicast_connection_server;
static struct simple_udp_connection unicast_connection_subject;

uint8_t nb_of_associated_subjects;
struct associated_subjects * associated_subjects;
struct old_associated_subject test_subject;

MEMB(alloc_associated_subjects, struct associated_subject, MAX_NUMBER_OF_SUBJECTS);

struct associated_subject *
associate_new_subject(uint8_t subject_id)
{
	struct associated_subject * current_subject = memb_alloc(&alloc_associated_subjects);
	if(current_subject == NULL) {
		return NULL;
	}

	current_subject->id = subject_id;
	//printf("new subject id : %d\n", current_subject->id);
	return current_subject;
}

void
deassociate_subject(struct associated_subject *sub)
{
	memb_free(&alloc_associated_subjects, sub);
}


// For demo purposes
unsigned char battery_level = 249;
unsigned char nb_of_access_requests_made = 0;

// For demo purposes, no distinction between different references is made
struct reference {
	uint8_t id;
	uint8_t (*function_pointer) (void) ;
	//TODO could be useful later: void (*pointer)() means: function pointer with unspecified number of argument.
};

//Space currently reserved for 10 references
#define max_nb_of_references 5
struct reference_table {
	struct reference references[max_nb_of_references];
} reference_table;

static uint8_t
low_battery() {
	//printf("Checking battery level.\n");
	return (battery_level <= 50);
}

static uint8_t
log_request() {
	//printf("Logging, i.e. incrementing nb_of_access_requests_made.\n");
	nb_of_access_requests_made++;
	return (0);
}

static uint8_t
switch_light_on() {
	leds_off(LEDS_ALL);
	leds_on(LEDS_GREEN);
	return (0);
}

static void
initialize_reference_table()
{
	reference_table.references[0].id = 4;
	reference_table.references[0].function_pointer = &low_battery;
	reference_table.references[1].id = 9;
	reference_table.references[1].function_pointer = &log_request;
	reference_table.references[2].id = 18;
	reference_table.references[2].function_pointer = &switch_light_on;
}

static struct reference *
get_reference(uint8_t function)
{
	int reference_index = 0;
	for (; reference_index < max_nb_of_references; reference_index++) {
		if (reference_table.references[reference_index].id == function) {
			return &reference_table.references[reference_index];
		}
	}
	return NULL;
}

static uint8_t
execute(uint8_t function)
{
//	printf("Execute.\n");
	uint8_t (*func_ptr)(void) = get_reference(function)->function_pointer;
	if (*func_ptr == NULL) {
		printf("Something went wrong executing a function pointer.\n");
		return 0;
	} else {
		return (*func_ptr)();
	}
}

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

static uint8_t
condition_is_met(struct expression condition)
{
	uint8_t function = condition.function;
	//printf("check function: %d\n", function);
	uint8_t input_existence_mask = condition.input_existence;
	//printf("input_existence_mask: %d\n", input_existence_mask);

	if (input_existence_mask) {
		// Get attributes
		int attr_index = 0;
		struct attribute current_attribute;
		for (; attr_index < condition.max_input_index+1 ; attr_index++) {
			current_attribute = condition.inputset[attr_index];
			if (current_attribute.type == 4) {
				uint8_t nb_of_characters = current_attribute.string_length;
				char value[nb_of_characters];
				memcpy(value, current_attribute.string_value, nb_of_characters);
				//printf("nb_of_characters : %d\n", nb_of_characters);
			} else if (current_attribute.type == 1) {
				// type : BYTE
				//	uint8_t char_value;
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (BYTE) : %d\n", current_attribute.char_value);
			} else if (current_attribute.type == 5) {
				// type : REQUEST REFERENCE
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (REQUEST) : \n", current_attribute.char_value);
			} else if (current_attribute.type == 6) {
				// type : SYSTEM REFERENCE
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (SYSTEM) : %d\n", current_attribute.char_value);
			} else if (current_attribute.type == 7) {
				// type : LOCAL REFERENCE
				uint8_t byte = current_attribute.local_reference_value;
				//printf("attr->local_reference_value (LOCAL) : %d\n", current_attribute.local_reference_value);
			} else {
				//printf("Error unknown attribute\n");
			}
		}
		//Execute denying function so that obligation(s) have to be executed. Function calls are independent of the difference unpacked vs compressed.
		return execute(4);
	} else {
		return execute(function);
	}
}
/*---------------------------------------------------------------------------*/
static void
perform_task(struct task t)
{
	uint8_t function = t.function;
	//printf("perform function: %d\n", function);

	uint8_t input_existence_mask = t.input_existence;
	//printf("input_existence_mask: %d\n", input_existence_mask);

	if (input_existence_mask) {
		// Get attributes
		int attr_index = 0;
		struct attribute current_attribute;
		for (; attr_index < t.max_input_index+1 ; attr_index++) {
			current_attribute = t.inputset[attr_index];
			if (current_attribute.type == 4) {
				uint8_t nb_of_characters = current_attribute.string_length;
				char *value = current_attribute.string_value; //TODO dit is een deel dat wel sneller is door de indexing, want de string moet niet meer worden gekopieerd, toch?
				//printf("nb_of_characters : %d\n", nb_of_characters);
			} else if (current_attribute.type == 1) {
				// type : BYTE
				//	uint8_t char_value;
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (BYTE) : %d\n", current_attribute.char_value);
			} else if (current_attribute.type == 5) {
				// type : REQUEST REFERENCE
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (REQUEST) : \n", current_attribute.char_value);
			} else if (current_attribute.type == 6) {
				// type : SYSTEM REFERENCE
				uint8_t byte = current_attribute.char_value;
				//printf("attr->char_value (SYSTEM) : %d\n", current_attribute.char_value);
			} else if (current_attribute.type == 7) {
				// type : LOCAL REFERENCE
				uint8_t byte = current_attribute.local_reference_value;
				//printf("attr->local_reference_value (LOCAL) : %d\n", current_attribute.local_reference_value);
			} else {
				printf("Error unknown attribute\n");
			}
		}
		//Execute log_request function for simplicity. Function calls are independent of the difference unpacked vs compressed.
		execute(9);
	} else {
		execute(function);
	}
}

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

void
measure_policy_size(const uint8_t *data) {
	testing_local_policy_size = 1;
	policy_size_in_bytes = 0;

	policy_size_in_bytes += sizeof(struct policy);

	struct policy policy;

	unpack_policy(data, 0, &policy);

	printf("Final policy_size_in_bytes: %d\n", policy_size_in_bytes);
}

void
evaluate_unpacked_policy(struct policy current_policy) {
	unsigned char action = 2;
	unsigned char value = 18;
	// For no reason, multiple rules are allowed, but only one condition per rule and one obligation. For demo purposes, even these multiple rules shouldn't be necessary

	char all_rules_check_out = 1;
	char result_of_this_rule = 1; // to be able to decide whether to execute an obligation
	// Search for rule about this action TODO actually any rule without 'action' and with action == ANY should also be checked

	timestamp = RTIMER_NOW();
	if (current_policy.rule_existence == 0) {
		all_rules_check_out = current_policy.effect;
	} else {
		int rule_index = 0;
		struct rule current_rule = current_policy.rules[rule_index];
		for(; rule_index < current_policy.max_rule_index+1 ; rule_index++) {
			current_rule = current_policy.rules[rule_index];
			result_of_this_rule = 1;

			if (!current_rule.action_mask ||
					(current_rule.action_mask && current_rule.action == action)){

				//Check conditions
				int cond_index = 0;
				for(; cond_index < current_rule.max_condition_index + 1; cond_index++) {
					uint8_t result = condition_is_met(current_rule.conditionset[cond_index]);
					if (current_rule.effect == 0 && result) {
						//printf("Condition was met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else if (current_rule.effect == 1 && !result) {
						//printf("Condition was not met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else {
						//printf("All conditions for this rule: fine.\n");
					}
				}

				//Enforce obligations
				if (current_rule.obligationset_mask) {
					int obl_index = 0;
					struct obligation current_obl = current_rule.obligationset[obl_index];
					for(; obl_index < current_rule.max_obligation_index+1 ; obl_index++) {
						current_obl = current_rule.obligationset[obl_index];
						if (current_obl.fulfill_on == 2 ||
								current_obl.fulfill_on == result_of_this_rule) {
							perform_task(current_obl.task);
						}
					}
				}
			}
		}
	}
	//printf("all_rules_check_out: %d\n", all_rules_check_out);

	timestamp = RTIMER_NOW() - timestamp;
	printf("Unpacked evaluation time: %4lu rtimer ticks\n", timestamp);
}

static uint8_t
compressed_condition_is_met(uint8_t *policy, int * expression_bit_index)
{
	uint8_t function = get_char_from(*expression_bit_index, policy);
	*expression_bit_index += 8;

	uint8_t input_existence_mask = get_bit((*expression_bit_index)++, policy);

	if (input_existence_mask) {

		uint8_t max_input_index = get_3_bits_from(*expression_bit_index, policy);
		*expression_bit_index += 3;

		uint8_t current_input_index = 0;
		for (; current_input_index < max_input_index + 1 ; current_input_index++) {
			uint8_t type = get_3_bits_from(*expression_bit_index, policy);
			*expression_bit_index += 3;

			uint8_t byte_value;
			if (type == 1) {
				// type : BYTE
				//	uint8_t char_value;
				byte_value = get_char_from(*expression_bit_index, policy);
				*expression_bit_index += 8;
				//printf("byte_value (BYTE) : %d\n", byte_value);
			} else if (type == 4) { //TODO include a length specifier in codification? Is a lot easier in this calculation
				// type : STRING
				//	char *string_value;
				uint8_t string_length = get_3_bits_from(*expression_bit_index, policy);
				int nb_of_characters = string_length;
				*expression_bit_index += 3;
				//printf("nb_of_characters : %d\n", nb_of_characters);

				uint8_t string_value[nb_of_characters];
				int char_index;
				for (char_index = 0 ; char_index < nb_of_characters ; char_index++) {
					string_value[char_index] = get_char_from(*expression_bit_index, policy);
					*expression_bit_index += 8;
				}

				//printf("attr->string_value : \"%s\"\n", string_value);
			} else if (type == 5) {
				// type : REQUEST REFERENCE
				//	uint8_t char_value;
				byte_value = get_char_from(*expression_bit_index, policy);
				*expression_bit_index += 8;
				//printf("byte_value (REQUEST) : %d\n", byte_value);
			} else if (type == 6) {
				// type : SYSTEM REFERENCE
				//	uint8_t char_value;
				byte_value = get_char_from(*expression_bit_index, policy);
				*expression_bit_index += 8;
				//printf("byte_value (SYSTEM) : %d\n", byte_value);
			} else if (type == 7) {
				// type : LOCAL REFERENCE
				//	uint8_t char_value : 3;
				byte_value = get_3_bits_from(*expression_bit_index,policy);
				*expression_bit_index += 3;
				//printf("attr->local_reference_value (LOCAL) : %d\n", byte_value);
			} else {
				printf("Error unknown attribute\n");
			}
		}
		return execute(4);
	} else {
		return execute(function);
	}
}

static void
compressed_perform_task(uint8_t *policy, int * task_bit_index)
{
//	printf("Execute task\n");
	uint8_t function = get_char_from(*task_bit_index, policy);
	*task_bit_index += 8;

	uint8_t input_existence_mask = get_bit((*task_bit_index)++, policy);

	if (input_existence_mask) {

		uint8_t max_input_index = get_3_bits_from(*task_bit_index, policy);
		*task_bit_index += 3;

		uint8_t current_input_index = 0;
		for (; current_input_index < max_input_index + 1 ; current_input_index++) {
			uint8_t type = get_3_bits_from(*task_bit_index, policy);
			*task_bit_index += 3;

			uint8_t byte_value;
			if (type == 1) {
				// type : BYTE
				//	uint8_t char_value;
				byte_value = get_char_from(*task_bit_index, policy);
				*task_bit_index += 8;
				//printf("byte_value (BYTE) : %d\n", byte_value);
			} else if (type == 4) { //TODO include a length specifier in codification? Is a lot easier in this calculation
				// type : STRING
				//	char *string_value;
				uint8_t string_length = get_3_bits_from(*task_bit_index, policy);
				int nb_of_characters = string_length;
				*task_bit_index += 3;
				//printf("nb_of_characters : %d\n", nb_of_characters);

				uint8_t string_value[nb_of_characters];
				int char_index;
				for (char_index = 0 ; char_index < nb_of_characters ; char_index++) {
					string_value[char_index] = get_char_from(*task_bit_index, policy);
					*task_bit_index += 8;
				}

				//printf("attr->string_value : \"%s\"\n", string_value);
			} else if (type == 5) {
				// type : REQUEST REFERENCE
				//	uint8_t char_value;
				byte_value = get_char_from(*task_bit_index, policy);
				*task_bit_index += 8;
				//printf("byte_value (REQUEST) : %d\n", byte_value);
			} else if (type == 6) {
				// type : SYSTEM REFERENCE
				//	uint8_t char_value;
				byte_value = get_char_from(*task_bit_index, policy);
				*task_bit_index += 8;
//				printf("byte_value (SYSTEM) : %d\n", byte_value);
			} else if (type == 7) {
				// type : LOCAL REFERENCE
				//	uint8_t char_value : 3;
				byte_value = get_3_bits_from(*task_bit_index,policy);
				*task_bit_index += 3;
				//printf("attr->local_reference_value (LOCAL) : %d\n", byte_value);
			} else {
				printf("Error unknown attribute\n");
			}
		}
		execute(9);
	} else {
		execute(function);
	}
}

void
evaluate_compressed_policy(const uint8_t *data, uint16_t datalen) {
	unsigned char action = 2;
	unsigned char value = 18;

	char all_rules_check_out = 1;
	char result_of_this_rule = 1; // to be able to decide whether to execute an obligation

	struct associated_subject current_sub;

	memcpy(current_sub.policy, data, datalen);

	timestamp = RTIMER_NOW();

	// Search for rule about action PUT. TODO include action=ANY and rule without an action specified
	if (!get_bit(9, current_sub.policy)) {
		all_rules_check_out = get_policy_effect(current_sub.policy);
	} else {

		int current_rule_bit_index = 10;
		int rule_index = 0;
		uint8_t nb_of_rules = get_3_bits_from(current_rule_bit_index, data);
		current_rule_bit_index += 3;
		for (; rule_index < nb_of_rules + 1; rule_index++) {
			if (!rule_has_action(current_sub.policy, current_rule_bit_index) ||
					(rule_has_action(current_sub.policy, current_rule_bit_index)
							&& rule_get_action(current_sub.policy, current_rule_bit_index) == action)){

				//#bits(id)
				current_rule_bit_index += 8;

				uint8_t effect = get_bit(current_rule_bit_index++, data);

				int copy = current_rule_bit_index;
				//#bits(5 masks)
				current_rule_bit_index += 5;

				if (get_bit(copy++, current_sub.policy)) {
					current_rule_bit_index += 8;
				}

				if (get_bit(copy++, current_sub.policy)) {
					current_rule_bit_index += 8;
				}

				if (get_bit(copy++, current_sub.policy)) {
					current_rule_bit_index += 8;
				}

				if (get_bit(copy++, current_sub.policy)) {
					current_rule_bit_index += 3;
				}

				uint8_t has_at_least_one_obligation = get_bit(copy, current_sub.policy);

				uint8_t max_expressions_index = get_3_bits_from(current_rule_bit_index, current_sub.policy);
				//#bits(max_expression_index) = 3
				current_rule_bit_index += 3;
				int condition_index = 0;
				//Voor elke voorwaarde: check die en geef de nieuwe bit index terug
				for (; condition_index < max_expressions_index + 1; condition_index++ ) {
					//Check condition
					uint8_t condition_met = compressed_condition_is_met(current_sub.policy, &current_rule_bit_index);
					if (!condition_met && effect) {
						//printf("Condition was not met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else if (condition_met && !effect) {
						//printf("Condition was met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else {
						//printf("All conditions for this rule: fine.\n");
					}
				}

				//Enforce obligations
				if (has_at_least_one_obligation) {
					//Assumption: current_rule_bit_index is now at the very end of all the expression
					uint8_t max_obligations_index = get_3_bits_from(current_rule_bit_index, current_sub.policy);
					//#bits(max_expression_index) = 3
					current_rule_bit_index += 3;

					int obligation_index = 0;
					for (; obligation_index < max_obligations_index + 1; obligation_index++ ) {
						uint8_t has_fulfill_on = get_bit(current_rule_bit_index++, current_sub.policy);
						//Always execute task if obligation does not have fulfill_on specification
						if (!has_fulfill_on) {
							compressed_perform_task(current_sub.policy,&current_rule_bit_index);
						}
						//Check if existing fulfill_on matches rule outcome
						else if (get_bit(current_rule_bit_index++, current_sub.policy) == result_of_this_rule) {
							compressed_perform_task(current_sub.policy,&current_rule_bit_index);
						}
						else {
							//Increase past this obligation
							current_rule_bit_index = task_increase_index(current_sub.policy, current_rule_bit_index);
						}
					}
				}
			}
			result_of_this_rule = 1;
		}
	}
	timestamp = RTIMER_NOW() - timestamp;
	printf("Compressed evaluation time: %4lu rtimer ticks\n", timestamp);
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
	testing_local_policy_size = 1;
	policy_size_in_bytes = 0;

	policy_size_in_bytes += sizeof(struct policy);
//
//
	struct policy current_policy;
	unpack_policy(data, 0, &current_policy);
//
	printf("Final policy_size_in_bytes: %d\n", policy_size_in_bytes);
//
//	printf("\n");
//	printf("\n");

	uint8_t i = 10;
	while (i--) {
		printf("Test %d\n", 10-i);
		evaluate_compressed_policy(data, datalen);

		evaluate_unpacked_policy(current_policy);
	}
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
//	printf("result socket: %d\n", result);
	nb_of_associated_subjects = 0;

	initialize_reference_table();

//	uint8_t k[4];
//	int j;
//	for (j = 0 ; j < 4 ; j++) {
//		k[j] = random_rand() & 0xff;
//	}
//	for (j = 0 ; j < 24 ; j++) {
//		printf("get_char_from_with_mask %d == %d get_char_from(j, k) \n", get_2_bits_from(j, k), get_bits_between(j, j+2, k));
//	}
	printf("\n");

	while(1) {
		PROCESS_WAIT_EVENT();
	}

	PROCESS_END();
}
