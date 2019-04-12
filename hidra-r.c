#include "contiki.h"
//#include "lib/random.h"
//#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/leds.h"
#include "simple-udp.h"
//
//#include "net/rpl/rpl.h"
//
//#include <stdio.h>
//#include <string.h>
//
//#include "sys/node-id.h"

#include <stdlib.h>


#include "subject-associations.h"
#include "policy.h"
#include "encoded_policy.h"

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
char HID_S_R_REQ_SUCCESS = 0;

//struct policy policy;
struct old_associated_subjects *old_associated_subjects;
struct associated_subjects *associated_subjects;

// For demo purposes
unsigned char battery_level = 249;
unsigned char nb_of_access_requests_made = 0;

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
		HID_CM_IND_REQ_SUCCESS = 0; //TODO useless now?
		HID_CM_IND_SUCCESS = 0;
		HID_S_R_REQ_SUCCESS = 1;
		printf("\n");
		printf("End of Hidra exchange with Subject\n");
	}
	else {
		printf("Did not receive from subject what was expected.\n");
	}
}
/*---------------------------------------------------------------------------*/
static void
send_nack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr)
{
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	const char response = 0;
	simple_udp_sendto(c, &response, 1, sender_addr);
}
/*---------------------------------------------------------------------------*/
static void
send_ack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr)
{
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	const char response = 1;
	simple_udp_sendto(c, &response, 1, sender_addr);
}
/*---------------------------------------------------------------------------*/
static char
condition_is_met(struct expression condition)
{
	if (condition.function == 4) { //TODO look up right expression from table and use corresponding function?
		printf("Checking battery level.\n");
		return (battery_level <= 50);
	}
	printf("Something is wrong with the given condition.\n");
	return 0;
}
/*---------------------------------------------------------------------------*/
static void
perform_task(struct task t)
{
	// If function == "++" and system reference is "nb_of_access_requests_made"
	if (t.function == 9 && t.input_existence == 1 && t.inputset[0].type == 6 && t.inputset[0].char_value == 20) { //TODO look up right expression from table and use corresponding function?
		nb_of_access_requests_made++;
		printf("Incrementing the value of nb_of_access_requests_made to %d.\n", nb_of_access_requests_made);
		return;
	}
	printf("Error processing task.\n");
}
/*---------------------------------------------------------------------------*/
static void
handle_subject_access_request(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
	//unpack expected request format
	unsigned char sub_id = get_char_from(0, data);
	unsigned char action = get_3_bits_from(8, data);
	unsigned char type = get_3_bits_from(11, data);
	unsigned char value = get_char_from(14, data); // This depends on the type in a non-demo scenario

	// print request (if it is the expected demo request)
	if (action == 2 && type == 6 && value == 18) {
		printf("Receive a PUT light_switch_on request.\n");
	} else if (action == 2 && type == 6 && value == 19) {
		printf("Receive a PUT light_switch_off request.\n");
	} else {
		printf("Did not receive the expected demo-request.\n");
		send_nack(c, sender_addr);
		return;
	}

	// Search for first policy associated with this subject
	char exists = 0;
	struct old_associated_subject current_sub;
	int sub_index = 0;
	for (; sub_index < old_associated_subjects->nb_of_associated_subjects ; sub_index++) {
		current_sub = old_associated_subjects->subject_association_set[sub_index];
		if (current_sub.id == sub_id) {
			exists = 1;
			break;
		}
	}

	// For no reason, multiple rules are allowed, but only one condition per rule and one obligation. For demo purposes, even these multiple rules shouldn't be necessary
	if (exists) {
		char all_rules_check_out = 1;
		char result_of_this_rule = 1; // to be able to decide whether to execute an obligation
		// Search for rule about this action TODO actually any rule without 'action' and with action == ANY should also be checked
		struct policy current_policy = current_sub.policy;
		if (current_policy.rule_existence == 0) {
			all_rules_check_out = current_policy.effect;
		} else {
			int rule_index = 0;
			struct rule current_rule = current_policy.rules[rule_index];
			for(; rule_index < current_policy.max_rule_index+1 ; rule_index++) {
				current_rule = current_policy.rules[rule_index];
				result_of_this_rule = 1;

				if (current_rule.action_mask && current_rule.action == action){
					//Check condition
					if (current_rule.effect == 0 && condition_is_met(current_rule.conditionset[0])) {
						printf("Condition was met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else if (current_rule.effect == 1 && !condition_is_met(current_rule.conditionset[0])) {
						printf("Condition was not met, therefore, access is denied.\n");
						all_rules_check_out = 0;
						result_of_this_rule = 0;
					} else {
						printf("All conditions for this rule: fine.\n");
					}

					//Enforce obligations
					if (current_rule.obligationset_mask) {
						// demo assumption: only one obligation
						if (current_rule.obligationset[0].fulfill_on == 2 ||
								current_rule.obligationset[0].fulfill_on == result_of_this_rule) {
							perform_task(current_rule.obligationset[0].task);
						}
					}
				}
			}
		}
		// (Non)Acknowledge the subject and possibly perform operation
		if (all_rules_check_out) {
			if (value == 18) {
				//turn all leds on
				leds_on(7);
			} else if (value == 19) {
				//turn all leds off
				leds_off(7);
			} else {
				printf("Mistake somehow?\n");
			}
			send_ack(c, sender_addr);

			// Let's assume this operation requires a lot of battery
			if (battery_level > 50) {
				battery_level -= 50;
				printf("new battery level: %d\n", battery_level);
			}
		} else {
			printf("Request denied, because not all rules check out.\n");
			send_nack(c, sender_addr);
		}

	} else {
		// deny if no association with subject exists
		printf("Request denied, because no association with this subject exists.\n");
		send_nack(c, sender_addr);
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

  //TODO Dit kan je voor elke subject apart doen als je HID_S_R_REQ_SUCCESS bij zet in de struct.
  // -> done, nu nog gebruiken (als je nog ooit uitgepakte versie gebruikt)
  if (!HID_S_R_REQ_SUCCESS) { // Complete Hidra Security Association
	  printf("Data Rx: %.*s\n", datalen, data); //datalen specification: because previous messages remain in buffer
	  printf("\n");

	  handle_hidra_subject_exchanges(c, sender_addr, data, datalen);
  } else { // Handle subject request after completion of Hidra protocol
//	  printf("Data Rx: %.*s\n", datalen, data);
//	  int all = 0;
//	  for ( ; all < datalen ; all++) {
//		  print_bits(data[all]);
//	  }
	  printf("\n");

	  handle_subject_access_request(c, sender_addr, data, datalen);
  }
}
/*---------------------------------------------------------------------------*/
//TODO delete when prototype is finished (for e.g. ROM measurements)
//TODO also delete all if (testing_local_policy_size) {..} from policy.c in that case
static void
measure_policy_size(const uint8_t *data) {
	testing_local_policy_size = 1;
	old_associated_subjects->nb_of_associated_subjects++; //TODO Alleen als subject nog niet tot associatie behoort. Anders is het een update
	old_associated_subjects->subject_association_set = malloc(sizeof(struct old_associated_subject));
	if (testing_local_policy_size) {
	  printf("Test of policy_size_in_bytes before: %d\n", policy_size_in_bytes);
	  // Subject ID = 8 bits = 1 byte and should not be counted in the policy bytes
	  policy_size_in_bytes += (sizeof(struct old_associated_subject) - 1);
	  printf("And after: %d\n", policy_size_in_bytes);
	}

	unpack_policy(data, 0, &old_associated_subjects->subject_association_set->policy);

	printf("Final policy_size_in_bytes: %d\n", policy_size_in_bytes);
}
/*---------------------------------------------------------------------------*/
static void
old_set_up_hidra_association_with_acs(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{

	char *second_exchange = "HID_CM_IND_REP";
	char second_exchange_len = strlen(second_exchange);

	// If this is the first exchange with the ACS: extract subject id and policy
	if (!HID_CM_IND_SUCCESS) {
		old_associated_subjects->nb_of_associated_subjects++; //TODO Alleen als subject nog niet tot associatie behoort. Anders is het een update
		old_associated_subjects->subject_association_set = malloc(sizeof(struct old_associated_subject));

		old_associated_subjects->subject_association_set->id = data[0];
		int bit_index = 8;
		printf("associated_subjects->subject_association_set->id : %d\n", old_associated_subjects->subject_association_set->id);

		unpack_policy(data, bit_index, &old_associated_subjects->subject_association_set->policy);


		char *response = "HID_CM_IND_REQ";
		simple_udp_sendto(c, response, strlen(response), sender_addr);
		HID_CM_IND_SUCCESS = 1;
	}
	else if (HID_CM_IND_SUCCESS
			&& datalen == second_exchange_len
			&& memcmp(data, second_exchange, second_exchange_len) == 0) {
		HID_CM_IND_REQ_SUCCESS = 1;
		printf("\n");
		printf("End of Hidra exchange with ACS\n");
	}
	else {
		printf("Did not receive from ACS what was expected in the protocol.\n");
	}
}
/*---------------------------------------------------------------------------*/
static uint8_t
is_already_associated(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index].id == id) {
			result = 1;
		}
	}

	return result;
}
/*---------------------------------------------------------------------------*/
static uint8_t
hid_cm_ind_success(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index].id == id &&
				associated_subjects->subject_association_set[subject_index].hid_cm_ind_success) {
			result = 1;
		}
	}

	return result;
}
/*---------------------------------------------------------------------------*/
static void
set_up_hidra_association_with_acs(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen,
        int bit_index)
{
	uint8_t subject_id = get_char_from(bit_index, data);
	bit_index += 8;

	// If this is the first exchange with the ACS: extract subject id and policy
	if (!is_already_associated(subject_id)) {
		associated_subjects->nb_of_associated_subjects++;

		associated_subjects->subject_association_set = (struct associated_subject *)
//				realloc(
//						associated_subjects->subject_association_set,
				malloc(
						associated_subjects->nb_of_associated_subjects * sizeof(struct associated_subject) //TODO Warning: this makes the function only suitable for 1 subject
		);
		//TODO if (associated_subjects->subject_association_set != NULL) {} else handleAllocError();


		associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].id = subject_id;
		printf("associated_subjects->subject_association_set[%d].id : %d\n", associated_subjects->nb_of_associated_subjects-1, associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].id);

		// print policy, for debugging
//		printf("Policy on arrival: \n");
//		print_policy(data, bit_index);

		// get policy size in bytes //TODO not efficient. Is there a better way?


		// assign policy size //TODO if policy length measure => maybe win 1 byte
		associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy_size = datalen - (bit_index/8);
		printf("associated_subjects->subject_association_set[%d].policy_size: %d\n", associated_subjects->nb_of_associated_subjects-1, associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy_size);

		// malloc policy range with right number of bytes
		associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy =
				(uint8_t *) malloc(associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy_size * sizeof(uint8_t));

		// copy policy to allocated memory
		copy_policy(data,
				bit_index,
				associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy_size,
				associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].policy);

		// print policy, for debugging
		printf("Policy associated to subject %d : \n", subject_id);
		print_policy(data, bit_index);

		char *response = "HID_CM_IND_REQ";
		simple_udp_sendto(c, response, strlen(response), sender_addr);
		associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects-1].hid_cm_ind_success = 1;
	}
	else if (hid_cm_ind_success(subject_id)) { //TODO check if content of message checks out
		HID_CM_IND_REQ_SUCCESS = 1; //TODO set this flag for this subject, before doing request evaluation
		printf("\n");
		printf("End of Hidra exchange with ACS\n");
	}
	else {
		printf("Did not receive from ACS what was expected in the protocol.\n");
	}
}
/*---------------------------------------------------------------------------*/
static void
handle_policy_update(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen,
        int bit_index)
{
	uint8_t subject_id = get_char_from(bit_index, data);
	bit_index += 8;

	printf("Updating policy : \n");
	//Check if this subject is indeed found
	if (is_already_associated(subject_id)) {
		if (get_bits_between(bit_index, bit_index+4, data) == 0) {
			if (blacklist_subject(associated_subjects, subject_id)) {
				//Answer with success message
				send_ack(c, sender_addr);
			} else {
				//Answer with failure message
				send_nack(c, sender_addr);
			}
		} else {
			//Answer with failure message
			send_nack(c, sender_addr);
		}
	} else {
		//Answer with failure message
		send_nack(c, sender_addr);
	}
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
  printf("Data Rx: %.*s\n", datalen, data);
  printf("\n");

//printf("Data Rx: %.*s\n", datalen, data);
  int all = 0;
  for ( ; all < datalen ; all++) {
	  print_bits(data[all]);
  }
  int bit_index = 1;
  if (get_bit(0, data) == 0) {
	  set_up_hidra_association_with_acs(c, sender_addr, data, datalen, bit_index);
  } else {
	  //TODO check HID_CM_IND_REQ_SUCCESS for this subject
	  handle_policy_update(c, sender_addr, data, datalen, bit_index);
  }
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

	old_associated_subjects->nb_of_associated_subjects = 0;

	associated_subjects->nb_of_associated_subjects = 0;
	associated_subjects->subject_association_set = NULL;

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

//
///////////////////
