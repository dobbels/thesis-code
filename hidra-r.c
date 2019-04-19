#include "contiki.h"

#include "net/ipv6/uip-ds6.h"
#include "dev/leds.h"
#include "simple-udp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#include "policy.h"
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

//struct policy policy;
struct associated_subjects *associated_subjects;

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
#define max_nb_of_references 10
struct reference_table {
	struct reference references[max_nb_of_references];
} reference_table;

static uint8_t
lowBattery() {
	printf("Checking battery level.\n");
	return (battery_level <= 50);
}

static uint8_t
log_request() {
	printf("Logging, i.e. incrementing nb_of_access_requests_made.\n");
	nb_of_access_requests_made++;
	return (0);
}

static uint8_t
switch_light_on() {
	leds_on(7);
	return (0);
}

static uint8_t
switch_light_off() {
	leds_off(7);
	return (0);
}

static void
initialize_reference_table()
{
	reference_table.references[0].id = 4;
	reference_table.references[0].function_pointer = &lowBattery;
	reference_table.references[1].id = 9;
	reference_table.references[1].function_pointer = &log_request;
	reference_table.references[2].id = 18;
	reference_table.references[2].function_pointer = &switch_light_on;
	reference_table.references[3].id = 19;
	reference_table.references[3].function_pointer = &switch_light_off;
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

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);
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
static uint8_t
condition_is_met(uint8_t *policy, int expression_bit_index)
{
	uint8_t function = get_char_from(expression_bit_index, policy);
	expression_bit_index += 8;

	uint8_t input_existence_mask = get_bit(expression_bit_index, policy);
	if (input_existence_mask) {
		printf("Did not expect a function with arguments.\n");
	} else {
		uint8_t (*func_ptr)(void) = get_reference(function)->function_pointer;
		return (*func_ptr)();
	}

	printf("Something went wrong with condition %d.\n", function);
	return 0;
}
/*---------------------------------------------------------------------------*/
static void
perform_task(uint8_t *policy, int task_bit_index)
{
	uint8_t function = get_char_from(task_bit_index, policy);
	task_bit_index += 8;

	uint8_t input_existence_mask = get_bit(task_bit_index, policy);
	task_bit_index += 1;

	if (input_existence_mask) {
		printf("Did not expect a task with arguments.\n");
	} else {
		uint8_t (*func_ptr)(void) = get_reference(function)->function_pointer;
		(*func_ptr)();
		return;
	}
	printf("Error processing task %d.\n", function);
}
/*---------------------------------------------------------------------------*/
static void
handle_subject_access_request(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen,
        uint8_t sub_id,
        int bit_index)
{
	//Expected demo format: Action: PUT + Task: light_switch_x
	uint8_t action = get_3_bits_from(bit_index, data);
	bit_index += 3;
	uint8_t function = get_char_from(bit_index, data);
	bit_index += 3;
	uint8_t input_existence_mask = get_bit(bit_index, data);
	bit_index += 1;
	if (input_existence_mask) {
		printf("Error: Did not expect a task with arguments.\n");
	}


	// print request (if it is the expected demo request)
	if (action == 2 && function == 18) {
		printf("Receive a PUT light_switch_on request.\n");
	} else if (action == 2 && function == 19) {
		printf("Receive a PUT light_switch_off request.\n");
	} else {
		printf("Did not receive the expected demo-request.\n");
		send_nack(c, sender_addr);
		return;
	}

	// Search for first policy associated with this subject
	char exists = 0;
	struct associated_subject *current_sub;
	int sub_index = 0;
	for (; sub_index < associated_subjects->nb_of_associated_subjects ; sub_index++) {
		current_sub = &associated_subjects->subject_association_set[sub_index];
		if (current_sub->id == sub_id) {
			exists = 1;
			break;
		}
	}
	if (exists) {
		// Assumption for demo purposes: 1 single rule inside the policy
		char rule_checks_out = 1;

		// Search for rule about action PUT. TODO include action=ANY and rule without an action specified
		if (policy_has_at_least_one_rule(current_sub->policy)) {
			rule_checks_out = get_policy_effect(current_sub->policy);
		} else {
			// Assumption for demo purposes: 1 single rule inside the policy

			//#bits(id) + #bits(effect) + #bits(rule_mask) + #bits(rule_index) = 13
			int rule_bit_index = 13;
			if (rule_has_action(current_sub->policy, rule_bit_index)
					&& rule_get_action(current_sub->policy, rule_bit_index) == action){
				// Assumption for demo purposes: 1 single expression inside the rule
				int exp_bit_index = rule_get_first_exp_index(current_sub->policy,rule_bit_index);
				//Check condition
				if (rule_get_effect(current_sub->policy) == 0
						&& condition_is_met(current_sub->policy,exp_bit_index)) {
					printf("Condition was met, therefore, access is denied.\n");
					rule_checks_out = 0;
				} else if (rule_get_effect(current_sub->policy) == 1
						&& !condition_is_met(current_sub->policy,exp_bit_index)) {
					printf("Condition was not met, therefore, access is denied.\n");
					rule_checks_out = 0;
				} else {
					printf("All conditions for this rule: fine.\n");
				}
				//Enforce obligations
				if (rule_has_obligations(current_sub->policy, rule_bit_index)) {

					// Assumption for demo purposes: 1 single obligation inside the rule
					int obl_bit_index = rule_get_first_obl_index(current_sub->policy,rule_bit_index);

					if (!obligation_has_fulfill_on(current_sub->policy, rule_bit_index) ||
							obligation_get_fulfill_on(current_sub->policy, rule_bit_index)== rule_checks_out) {
						perform_task(current_sub->policy,obl_bit_index);

					}
				}
			}
		}

		// (Non)Acknowledge the subject and possibly perform operation

		//TODO als er een obligation is, voer die uit in de juiste gevallen

		if (rule_checks_out) {

			uint8_t (*func_ptr)(void) = get_reference(function)->function_pointer;
			(*func_ptr)();

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
handle_hidra_subject_exchanges(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen,
        uint8_t subject_id)
{

	if (hid_cm_ind_req_success(subject_id)) {
		char *response = "HID_S_R_REP";
		simple_udp_sendto(c, response, strlen(response), sender_addr);
		set_hid_s_r_req_success(subject_id, 1);
		printf("End of Hidra exchange with Subject\n");
		printf("\n");
	}
	else {
		printf("Did not receive from subject what was expected.\n");
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
  printf("Data Rx: %.*s\n", datalen, data);

  int bit_index = 1;
  uint8_t subject_id = get_char_from(bit_index, data);
  bit_index += 8;
  if (get_bit(0, data)) { //Hidra protocol message
	  if (is_already_assocation(subject_id) && !hid_s_r_req_success(subject_id)) {
		  handle_hidra_subject_exchanges(c, sender_addr, data, datalen, subject_id);
	  } else {
		  printf("Hidra protocol message from subject without proper preceding steps.\n");
	  }
  } else { //Access request
	  if (is_already_assocation(subject_id) && hid_s_r_req_success(subject_id)) { //TODO dubbel redundant, want hid_s_r_req_success omvat is_already_assocation en in handle_subject_access_request wordt nog eens (impliciet) gecheckt of subject associated is
		  handle_subject_access_request(c, sender_addr, data, datalen, subject_id, bit_index);
	  } else {
		  printf("Request denied, because no association with this subject exists.\n");
		  send_nack(c, sender_addr);
	  }
  }
}
/*---------------------------------------------------------------------------*/
static uint8_t
is_already_associated(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id) {
			result = 1;
		}
	}

	return result;
}
/*---------------------------------------------------------------------------*/
static void
set_hid_cm_ind_success(uint8_t id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id) {
			associated_subjects->subject_association_set[subject_index]->hid_cm_ind_success = bit;
		}
	}
}
/*---------------------------------------------------------------------------*/
static uint8_t
hid_cm_ind_success(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id &&
				associated_subjects->subject_association_set[subject_index]->hid_cm_ind_success) {
			result = 1;
		}
	}

	return result;
}
/*---------------------------------------------------------------------------*/
static void
set_hid_s_r_req_success(uint8_t id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id) {
			associated_subjects->subject_association_set[subject_index]->hid_s_r_req_succes = bit;
		}
	}
}
/*---------------------------------------------------------------------------*/
/**
 * Returns zero if the given id does not correspond to an associated subject
 * Returns zero if the associated subject has not completed the HID_S_R_REQ message exchange yet
 */
static uint8_t
hid_s_r_req_success(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id &&
				associated_subjects->subject_association_set[subject_index]->hid_s_r_req_succes) {
			result = 1;
		}
	}

	return result;
}
/*---------------------------------------------------------------------------*/
static void
set_hid_cm_ind_req_succes(uint8_t subject_id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id) {
			associated_subjects->subject_association_set[subject_index]->hid_cm_ind_req_success = bit;
		}
	}
}
/*---------------------------------------------------------------------------*/
static uint8_t
hid_cm_ind_req_succes(uint8_t subject_id)
{
	uint8_t result = 0;

	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id &&
				associated_subjects->subject_association_set[subject_index]->hid_cm_ind_req_success) {
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
		if (associated_subjects->nb_of_associated_subjects >= 10) {
			printf("Oops, the number of associated subjects is currently set to 10.\n");
		}
		associated_subjects->nb_of_associated_subjects++;

		struct associated_subject *current_subject = malloc(sizeof(struct associated_subject));
		//TODO if (associated_subjects->subject_association_set != NULL) {} else handleAllocError();

		associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects - 1] = current_subject;

		current_subject->id = subject_id;
		printf("associated_subjects->subject_association_set[%d]->id : %d\n", associated_subjects->nb_of_associated_subjects - 1, current_subject->id);

		// assign policy size - works as long as policy is last part of the message - this value might cause the copying of an unused zero-byte
		current_subject->policy_size = datalen - (bit_index/8);
		printf("associated_subjects->subject_association_set[%d]->policy_size: %d\n", associated_subjects->nb_of_associated_subjects-1, current_subject->policy_size);

		// malloc policy range with right number of bytes
		current_subject->policy = malloc(current_subject->policy_size * sizeof(uint8_t));

		// copy policy to allocated memory
		copy_policy(data,
				bit_index,
				current_subject->policy_size,
				current_subject->policy);

		// print policy, for debugging
		printf("Policy associated to subject %d : \n", subject_id);
		print_policy(current_subject->policy, 0);

		char *response = "HID_CM_IND_REQ";
		simple_udp_sendto(c, response, strlen(response), sender_addr);
		current_subject->hid_cm_ind_success = 1;
	}
	else if (hid_cm_ind_success(subject_id)) { //TODO check if content of message checks out
		set_hid_cm_ind_req_succes(subject_id, 1);
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
		if (get_3_bits_from(bit_index, data) == 0) {
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

  int bit_index = 1;
  if (get_bit(0, data) == 0) {
	  set_up_hidra_association_with_acs(c, sender_addr, data, datalen, bit_index);
  } else {
	  if (is_already_associated(get_char_from(bit_index, data))) {
		  handle_policy_update(c, sender_addr, data, datalen, bit_index);
	  } else {
		  printf("Trying to update a policy of a non-associated subject. \n");
	  }
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

	set_global_address(); // TODO mag void zijn?

	// Register a sockets, with the correct host and remote ports
	// NULL parameter as the destination address to allow packets from any address. (fixed IPv6 address can be given)
	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);
	simple_udp_register(&unicast_connection_subject, SUBJECT_UDP_PORT,
							  NULL, SUBJECT_UDP_PORT,
							  receiver_subject);

	associated_subjects->nb_of_associated_subjects = 0;

	initialize_reference_table();

	while(1) {
		// At the click of the button, a packet will be sent
//		PROCESS_WAIT_EVENT_UNTIL((ev==sensors_event) && (data == &button_sensor));
//		printf("button pressed\n");
//		send_unicast();

		PROCESS_WAIT_EVENT();
	}
	
	PROCESS_END();
}
