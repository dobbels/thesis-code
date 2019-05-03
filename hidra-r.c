#include "contiki.h"

#include "lib/random.h"

#include "net/ip/uip.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/leds.h"
#include "simple-udp.h"

#include "assert.h"//TODO delete

#include "cfs/cfs.h"

#include "tiny-AES-c/aes.h"

#include "sha.h"

//#include "avr-crypto-lib/hmac-sha1/hmac-sha1.h"

//#include "hmac-sha1/src/hmac/hmac.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

//#include "policy.h"
#include "encoded_policy.h"
#include "byte_operations.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

//#include "hmac-sha1.h"

#define ACS_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_subject;

uip_ipaddr_t resource_addr;

const uint8_t resource_key[16] =
	{ (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

const uint8_t text[46] = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
						0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x51,
						0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };

//Subject-specific file structure is a concatenation of:
//NonceSR
#define nonce_s_r_offset 0;

//General file structure is a concatenation of:
//Current last one-way key chain value Kr,cm
#define k_i_r_cm_offset 0;
//Nonce3
#define nonce3_offset (k_i_r_cm_offset + 16);

uint8_t any_previous_key_chain_value_stored = 0;

static void full_print_hex(uint8_t* str, uint8_t length);
static void print_hex(uint8_t* str, uint8_t len);
static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length);
void md5(uint8_t *initial_msg, size_t initial_len);

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
#define max_nb_of_references 5
struct reference_table {
	struct reference references[max_nb_of_references];
} reference_table;

static uint8_t
low_battery() {
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
	leds_off(LEDS_ALL);
	leds_on(LEDS_GREEN);
	return (0);
}

//static uint8_t
//switch_light_off() {
//	leds_off(LEDS_ALL);
//	return (0);
//}

static void
initialize_reference_table()
{
	reference_table.references[0].id = 4;
	reference_table.references[0].function_pointer = &low_battery;
	reference_table.references[1].id = 9;
	reference_table.references[1].function_pointer = &log_request;
	reference_table.references[2].id = 18;
	reference_table.references[2].function_pointer = &switch_light_on;
//	reference_table.references[3].id = 19;
//	reference_table.references[3].function_pointer = &switch_light_off;
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
//	printf("Printing function %d\n", function);
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

static void
send_nack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr)
{
	printf("Sending unicast to \n");
	uip_debug_ipaddr_print(sender_addr);
	printf("\n");

	const char response = 0;
	simple_udp_sendto(c, &response, 1, sender_addr);

	// This turns on the red light, whenever anything is non-acknowledged
	leds_off(LEDS_ALL);
	leds_on(LEDS_RED);
}

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

//static void
//set_hid_cm_ind_success(uint8_t id, uint8_t bit)
//{
//	int subject_index = 0;
//	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
//		if(associated_subjects->subject_association_set[subject_index]->id == id) {
//			associated_subjects->subject_association_set[subject_index]->hid_cm_ind_success = bit;
//		}
//	}
//}

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

static void
set_hid_cm_ind_req_success(uint8_t subject_id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id) {
			associated_subjects->subject_association_set[subject_index]->hid_cm_ind_req_success = bit;
		}
	}
}

static uint8_t
hid_cm_ind_req_success(uint8_t subject_id)
{
	uint8_t result = 0;

	int subject_index = 0;
	for (; subject_index < associated_subjects->nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id &&
				associated_subjects->subject_association_set[subject_index]->hid_cm_ind_req_success) {
			result = 1;
		}
	}
	return result;
}

static uint8_t
condition_is_met(uint8_t *policy, int expression_bit_index)
{
	uint8_t function = get_char_from(expression_bit_index, policy);
	expression_bit_index += 8;

	uint8_t input_existence_mask = get_bit(expression_bit_index, policy);
	if (input_existence_mask) {
		printf("(function: condition_is_met) Did not expect a function with arguments.\n");
	} else {
		return execute(function);
	}

	printf("Something went wrong with condition %d.\n", function);
	return 0;
}

static void
perform_task(uint8_t *policy, int task_bit_index)
{
	uint8_t function = get_char_from(task_bit_index, policy);
	task_bit_index += 8;

	uint8_t input_existence_mask = get_bit(task_bit_index, policy);
	task_bit_index += 1;

	if (input_existence_mask) {
		printf("(function: perform_task) Did not expect a task with arguments.\n");
	} else {
		execute(function);
		return;
	}
	printf("Error processing task %d.\n", function);
}

static void
handle_subject_access_request(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen,
        uint8_t sub_id,
        int bit_index)
{
	//Expected demo format: Action: PUT + Task: light_switch_x
	uint8_t action = get_char_from(bit_index, data);
	bit_index += 8;
	uint8_t function = get_char_from(bit_index, data);
	bit_index += 8;

	// print request (if it is the expected demo request)
	if (action == 2 && function == 18) {
		printf("Receive a PUT light_switch_on request from subject %d.\n", sub_id);
	} else if (action == 2 && function == 19) {
		printf("Receive a PUT light_switch_off request from subject %d.\n", sub_id);
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
		current_sub = associated_subjects->subject_association_set[sub_index];
		if (current_sub->id == sub_id) {
			exists = 1;
			break;
		}
	}
	if (exists) {
		// Assumption for demo purposes: 1 single rule inside the policy
		char rule_checks_out = 0;

//		printf(" : %d\n", );
		// Search for rule about action PUT. TODO include action=ANY and rule without an action specified
		if (!policy_has_at_least_one_rule(current_sub->policy)) {
			rule_checks_out = get_policy_effect(current_sub->policy);
		} else {
			// Assumption for demo purposes: 1 single rule inside the policy
			int rule_bit_index = 13;
			if (rule_has_action(current_sub->policy, rule_bit_index)
					&& rule_get_action(current_sub->policy, rule_bit_index) == action){
				// Assumption for demo purposes: 1 single expression inside the rule
				int exp_bit_index = rule_get_first_exp_index(current_sub->policy,rule_bit_index);
				//Check condition
				uint8_t condition_met = condition_is_met(current_sub->policy,exp_bit_index);
				if (!condition_met && rule_get_effect(current_sub->policy, rule_bit_index) == 0) {
					printf("Condition was met, therefore access is granted.\n");
					rule_checks_out = 1;
				} else if (condition_met && rule_get_effect(current_sub->policy, rule_bit_index) == 1) {
					printf("Condition was not met, therefore access is granted.\n");
					rule_checks_out = 1;
				} else {
					printf("Rule effect is %d, while condition result was %d => Access denied.\n", rule_get_effect(current_sub->policy, rule_bit_index), condition_is_met(current_sub->policy,exp_bit_index));
				}
				//Enforce obligations
				if (rule_has_at_least_one_obligation(current_sub->policy, rule_bit_index)) {

					// Assumption for demo purposes: 1 single obligation inside the rule
					int obl_bit_index = rule_get_first_obl_index(current_sub->policy,rule_bit_index);

					//Always execute task || Obligation has fulfill_on
					if (!obligation_has_fulfill_on(current_sub->policy, obl_bit_index)) {
						perform_task(current_sub->policy,obl_bit_index);
					}
					//Check if existing fulfill_on matches rule outcome
					else if (obligation_get_fulfill_on(current_sub->policy, obl_bit_index) == rule_checks_out) {
						perform_task(current_sub->policy,obl_bit_index);
					}
				}
			}
		}

		// Possibly perform operation and (non)acknowledge the subject
		if (rule_checks_out) {

			execute(function);

			send_ack(c, sender_addr);

			set_hid_s_r_req_success(sub_id, 1);

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
	printf("End of Hidra exchange with Subject\n");
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
  printf("\nData received from: ");
  PRINT6ADDR(sender_addr);
  printf("\nAt port %d from port %d with length %d\n",
		  receiver_port, sender_port, datalen);
//  printf("Data Rx: %.*s\n", datalen, data);

  int bit_index = 0;
  uint8_t subject_id = get_char_from(bit_index, data);
  bit_index += 8;

  if (is_already_associated(subject_id) && !hid_s_r_req_success(subject_id) && hid_cm_ind_req_success(subject_id)) {
	  handle_subject_access_request(c, sender_addr, data, datalen, subject_id, bit_index);
  } else {
	  printf("Request denied, because no association with this subject exists.\n");
	  send_nack(c, sender_addr);
  }
}

static void
construct_cm_ind_req(uint8_t *cm_ind_req) {
	const char * filename = "properties";
	//resource ID (2 bytes)
	cm_ind_req[0] = 0;
	cm_ind_req[1] = 2;
	//Nonce3 (8 bytes)
	uint16_t part_of_nonce = random_rand();
	cm_ind_req[2] = (part_of_nonce >> 8);
	cm_ind_req[3] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_ind_req[4] = (part_of_nonce >> 8);
	cm_ind_req[5] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_ind_req[6] = (part_of_nonce >> 8);
	cm_ind_req[7] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_ind_req[8] = (part_of_nonce >> 8);
	cm_ind_req[9] = part_of_nonce & 0xffff;

	//Store Nonce3 for later use
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_ind_req + 2, 8);
		cfs_close(fd_write);
		printf("Successfully written Nonce3 (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	   printf("ERROR: could not write Kscm to memory.\n");
	}

	//Compute and fill MAC
	//TODO
}

// TODO more realistic file per subject
//problem: filename based on subject id and this gave errors earlier. try to assign in one line const char * filename = "properties" + subject_id;, you get the idea
// => TODO voeg filename toe aan subject struct
//	+ schrijf functie om die makkelijk te getten
//	+ gebruik https://codereview.stackexchange.com/questions/29198/random-string-generator-in-c om filename te genereren
//		=> als dat niet werkt, hardcode dan voor demo


static void
process_cm_ind(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		uint8_t subject_id,
		const uint8_t *data,
		uint16_t datalen) {
	const char * subject_filename;
	//TODO PoC to PoC -> dit mag wat minder lelijk, maar is niet noodzakelijk. Je kan altijd pseudo code zetten en alleen belangrijkste code in bijlage
	if (subject_id == 3) {
		subject_filename = "properties3"; //TODO super illegaal?
	} else if (subject_id == 4) {
		subject_filename = "properties4";
	} else {
		subject_filename = "properties5";
	}
//	const char * subject_filename = &subject_id; //TODO werkt een enkele uint8_t als file name? Cast naar char?
	const char * filename = "properties";
	uint8_t cm_ind[62];
	printf("datalen 62 == %d\n", datalen);
	memcpy(cm_ind, data, datalen);
	printf("Full HID_CM_IND message: \n");
	full_print_hex(cm_ind, sizeof(cm_ind));

	if (associated_subjects->nb_of_associated_subjects >= 10) {
		printf("Oops, the number of associated subjects is currently set to 10.\n");
	}
	associated_subjects->nb_of_associated_subjects++;

	struct associated_subject *current_subject = malloc(sizeof(struct associated_subject));
	//TODO if (associated_subjects->subject_association_set != NULL) {} else handleAllocError();

	associated_subjects->subject_association_set[associated_subjects->nb_of_associated_subjects - 1] = current_subject;

	current_subject->id = subject_id;
	printf("new subject id : %d\n", current_subject->id);

	// assign policy size based on knowledge about the rest of the message
	current_subject->policy_size = datalen - 33;
	printf("new subject policy_size: %d\n", current_subject->policy_size);

	// malloc policy range with right number of bytes
	current_subject->policy = malloc(current_subject->policy_size * sizeof(uint8_t));

	// decrypt policy before storage
	xcrypt_ctr(resource_key, cm_ind+29, current_subject->policy_size);

	// copy decrypted policy to allocated memory
	memcpy(current_subject->policy, cm_ind + 29, current_subject->policy_size);

	// print policy, for debugging
	printf("Policy associated to subject %d : \n", subject_id);
	print_policy(current_subject->policy, 0);

	//Ignore lifetime value

	//Store NonceSR in file system
	int fd_write = cfs_open(subject_filename, CFS_WRITE);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_ind + 4, 8);
		cfs_close(fd_write);
		printf("Successfully written Nonce3 (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	   printf("ERROR: could not write Kscm to memory.\n");
	}

	//Store key chain value in file system
	if (!any_previous_key_chain_value_stored) {
		any_previous_key_chain_value_stored = 1; //=> on requests from next subjects, to do or not to do?

		//Request previous key chain value at credential manager
		uint8_t response[14];
		construct_cm_ind_req(response);
		//Send message to credential manager
		simple_udp_sendto(c, response, sizeof(response), sender_addr);

	} else {
		//TODO check if valid next value in keychain -> eigenlijk makkelijker om dit voor elke subject opnieuw te doen
		//TODO in Java: prepare to be able to skip steps 4.1 and 4.2 (for demo, hardcode this?)
		//TODO als je dit doet: zet hidra_succes boolean voor deze subject
	}

	fd_write = cfs_open(filename, CFS_WRITE);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_ind + 4, 8);
		cfs_close(fd_write);
		printf("Successfully written Nonce3 (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	   printf("ERROR: could not write Kscm to memory.\n");
	}

	//TODO only in case of success(?)
	current_subject->hid_cm_ind_success = 1;
}

static void
set_up_hidra_association_with_acs(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
	printf("Resource id 2 == %d \n", data[0]);
	uint8_t subject_id = data[1];

	// If this is the first exchange with the ACS: extract subject id and policy
	if (!is_already_associated(subject_id)) {
		process_cm_ind(c, sender_addr, subject_id, data, datalen);
	}
	else if (hid_cm_ind_success(subject_id)) { //TODO if steps 4.1 and 4.2 are not necessary, also set success + print this line
//		process_cm_ind_rep(data, datalen); TODO
		set_hid_cm_ind_req_success(subject_id, 1); //TODO hidra exchange success ipv ind_req. Die wordt nl. niet altijd gebruikt
		printf("\n");
		printf("End of Hidra exchange with ACS\n");
	}
	else {
		printf("Did not receive from ACS what was expected in the protocol.\n");
	}
}

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
//  printf("Data Rx: %.*s\n", datalen, data);
  printf("\n");
  printf("Subject id %d == 2, right?\n", data[2]);
  //The first byte indicates the purpose of this message from the trusted server
  if (data[0]) {
	  if (is_already_associated(data[2])) {
		  handle_policy_update(c, sender_addr, data+1, datalen-1, 0);
	  } else {
		  printf("Trying to update a policy of a non-associated subject. \n");
	  }
  } else {
	  set_up_hidra_association_with_acs(c, sender_addr, data+1, datalen-1);
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

	printf("Vector: \n");
	full_print_hex(text, sizeof(text));

	printf("Key: \n");
	full_print_hex(resource_key, sizeof(resource_key));

//	uint8_t digest[20];

	///////////////////////////////
//	uint32_t hash[5];
////	char *msg = "hi";
////	char *key = "hi";
//	bitstr m;
//	bitstr k;
//
//	m.d = text;
//	m.l[0] = 8*sizeof(text);
//	m.l[1] = 0;
//
//	k.d = resource_key;
//	k.l[0] = 8*sizeof(resource_key);
//	k.l[1] = 0;
//
//	hmac_sha1 (&k, &m, hash);
//	printf("hash after \n");
//	full_print_hex(hash, 20);

	 ////////////////////////////////


//	//Size : USHAMaxHashSize
	uint8_t digest[USHAMaxHashSize];
//	//TODO process result code, should be 0
	hmac (SHA1, text, sizeof(text), resource_key, sizeof(resource_key), digest);
	//TODO malloc might be the problem, according to internet

	printf("HMAC_SHA_1: \n");
	full_print_hex(digest, 20);

	uint32_t hashed = murmur3_32(digest, 20, 17);
	uint8_t hashed_array[4];
	hashed_array[0] = (hashed >> 24) & 0xff;
	hashed_array[1] = (hashed >> 16) & 0xff;
	hashed_array[2] = (hashed >> 8)  & 0xff;
	hashed_array[3] = hashed & 0xff;

	printf("Hashed HMAC_SHA_1: \n");
	full_print_hex(hashed_array, 4);

	while(1) {
//			PROCESS_WAIT_EVENT(); //TODO stond dit hier vroeger ook?
		}

	PROCESS_END();
}

static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length)
{
	uint8_t iv[16]  = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, in, length);
}

static void full_print_hex(uint8_t* str, uint8_t length) {
	printf("********************************\n");
	int i = 0;
	for (; i < (length/16) ; i++) {
		print_hex(str + i * 16, 16);
	}
	print_hex(str + i * 16, length%16);
	printf("********************************\n");
}

// prints string as hex
static void print_hex(uint8_t* str, uint8_t len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

//////////////////////////////////////////
//CODE FROM tiny AES PROJECT
/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/
/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),TODO
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k; //TODO warning: unsigned means unsigned int, but that has 2 bytes on Z1, with msp430-gcc, vs 4 bytes on other compilers
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey); 
  
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey); 

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = (Nr - 1); round > 0; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
  uint8_t buffer[AES_BLOCKLEN];

  unsigned i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {

      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        }
        ctx->Iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}

//END OF CODE FROM tiny AES PROJECT
/////////////////////////////////////////

//Hash to 32 bits from https://en.wikipedia.org/wiki/MurmurHash
//TODO if it doesn't work, try https://github.com/PeterScott/murmur3/blob/master/murmur3.c
//TODO doe seed = 17
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	uint32_t h = seed;
	if (len > 3) {
		const uint32_t* key_x4 = (const uint32_t*) key;
		size_t i = len >> 2;
		do {
			uint32_t k = *key_x4++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h = h * 5 + 0xe6546b64;
		} while (--i);
		key = (const uint8_t*) key_x4;
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		key = &key[i - 1];
		do {
			k <<= 8;
			k |= *key--;
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/////////////////////////TODO verwijder
//////////////////////////


uint8_t *rd32be (uint32_t * n, uint8_t * msg) {
  *n = *msg << 24;
  ++msg;
  *n |= *msg << 16;
  ++msg;
  *n |= *msg << 8;
  ++msg;
  *n |= *msg;
  return ++msg;
}                               /* libpk */

    /* do this outside b32 h[5]={ 0x67452301, 0xefcdab89, 0x98badcfe, */
    /* 0x10325476, 0xc3d2e1f0}; */

typedef struct {
  unsigned char *d;
  uint32_t l[2];
} bitstr;


typedef struct {
  uint32_t h[5];
  uint32_t l[2];
} hsh;

int hsh_rst (hsh * h) {

  h->h[0] = 0x67452301;
  h->h[1] = 0xefcdab89;
  h->h[2] = 0x98badcfe;
  h->h[3] = 0x10325476;
  h->h[4] = 0xc3d2e1f0;
  h->l[0] = 0;
  h->l[1] = 0;

  return 0;

}

int sha1_nxt (uint8_t * msg, uint32_t bits, hsh * h) {
  uint32_t w[80];
  int i, j, b;

  if (bits != 512)
    return 1;                   /* bad length */
  h->l[0] += bits;
  if (h->l[0] < bits) {
    h->l[1]++;
    if (!(h->l[1]))
      return 2;
  }                             /* msg size overflow */
  for (i = 0; i < 16; i++)
    msg = rd32be (w + i, msg);
  grind (w, h->h);
  return 0;
}

int sha1_end (uint8_t * msg, uint32_t bits, hsh * h) {
  uint32_t w[80];
  int i = 0, j, b;
  if (bits >= 512)
    return 1;                   /* cant end with this chunk size */
  if (bits) {                   /* do incomplete chunk */
    h->l[0] += bits;
    if (h->l[0] < bits) {
      h->l[1]++;
      if (!(h->l[1]))
        return 2;
    }                           /* msg size overflow */
    if (j = bits / 32) {        /* do all complete words */
      for (i = 0; i < j; i++)
        msg = rd32be (w + i, msg);
      bits %= 32;
    }
    b = bits;                   /* do final word */
    w[i] = 1 << (31 - bits);
    w[i] |= *msg << 24;
    ++msg;
    b -= 8;
    if (b > 0) {
      w[i] |= *msg << 16;
      ++msg;
      b -= 8;
      if (b > 0) {
        w[i] |= *msg << 8;
        ++msg;
        b -= 8;
        if (b > 0) {
          w[i] |= *msg;
          ++msg;
          b -= 8;
        }
      }
    }
    w[i] &= 0xffffffff << (31 - bits);
    i++;
    if (j >= 14) {
      if (i == 15)
        w[15] = 0;
      grind (w, h->h);
      i = 0;
    }

  }
  else {                        /* add final chunk having length */
    w[0] = 0x80000000;
    i = 1;
  }
  for (; i < 14; i++)
    w[i] = 0;                   /* fill with zero, leave 64 bits */
  w[i] = h->l[1];
  i++;
  w[i] = h->l[0];               /* fill last 64 bits with length */
  grind (w, h->h);
  h->l[0] = 0;
  h->l[1] = 0;
  return 0;
}

int sha1_finish (bitstr * msg, hsh * h) {
  bitstr p;

  p = *msg;
  while (p.l[1] || (p.l[0] >= 512)) {
    sha1_nxt (p.d, 512, h);     /* FIXME check return value? */
    p.d += 64;
    if (p.l[0] < 512) {
      if (p.l[1]) {
        p.l[1]--;
      }
      else
        return 1;               /* length underflow; FIXME redundant? */
    }
    p.l[0] -= 512;
  }
  sha1_end (p.d, p.l[0], h);    /* FIXME check return value? */
  return 0;
}

int sha1 (bitstr * msg, hsh * h) {
  int i;
  bitstr p;

  hsh_rst (h);
  return sha1_finish (msg, h);
}

uint32_t f (uint32_t t, uint32_t * a, uint32_t * w) {
  uint32_t temp = 0;
  uint32_t k[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };
  temp = ((a[0] << 5) | (a[0] >> 27)) + a[4] + w[t];
  switch (t / 20) {
  case 0:
    temp += k[0];
    temp += (a[1] & a[2]) | ((~a[1]) & a[3]);
    break;
  case 1:
    temp += k[1];
    temp += a[1] ^ a[2] ^ a[3];
    break;
  case 2:
    temp += k[2];
    temp += (a[1] & a[2]) | (a[1] & a[3]) | (a[2] & a[3]);
    break;
  case 3:
    temp += k[3];
    temp += a[1] ^ a[2] ^ a[3];
    break;
  }
  return temp;
}

int grind (uint32_t * w, uint32_t * h) {
  uint32_t t, temp;
  uint32_t a[5];
  for (t = 16; t < 80; t++) {
    temp = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
    w[t] = (temp << 1) | (temp >> 31);
  }
  for (t = 0; t < 5; t++)
    a[t] = h[t];
  for (t = 0; t < 80; t++) {
    temp = f (t, a, w);
    a[4] = a[3];
    a[3] = a[2];
    a[2] = (a[1] << 30) | (a[1] >> 2);
    a[1] = a[0];
    a[0] = temp;
  }
  for (t = 0; t < 5; t++)
    h[t] += a[t];
  return 0;
}


/* rfc3174
it all boiled down to reading big endian numbers correctly ;)
and realizing the you are not writing anything in big endian form :P
Wed Jul 16 00:32:21 IST 2014
*/


uint8_t *wr32be (uint32_t n, uint8_t * msg) {
  uint32_t mask = 0xff;
  *msg = n >> 24;
  ++msg;
  *msg = (n >> 16) & mask;
  ++msg;
  *msg = (n >> 8) & mask;
  ++msg;
  *msg = n & mask;
  return ++msg;
}                               /* libpk */

int hmac_sha1 (bitstr * key, bitstr * msg, uint32_t mac[5]) {
  uint32_t k[16] = { 0 };
  uint32_t o[16], i[16];
  uint32_t x;
  hsh h, fin;


  if (key->l[1] || key->l[0] > 512) {
    sha1 (key, &h);
    for (x = 0; x < 5; x++)
      wr32be (h.h[x], k + x);   /* FIXME: if wr32be works not */
  }
  else
    memcpy (k, key->d, key->l[0] / 8 + (key->l[0] % 8 && 1));

  for (x = 0; x < 16; x++) {
    o[x] = 0x5c5c5c5c ^ k[x];
    i[x] = 0x36363636 ^ k[x];
  }


  hsh_rst (&h);
  sha1_nxt (i, 512, &h);
  sha1_finish (msg, &h);
  for (x = 0; x < 5; x++)
    wr32be (h.h[x], h.h + x);   /* FIXME: if wr32be works not */
  hsh_rst (&fin);
  sha1_nxt (o, 512, &fin);
  sha1_end (h.h, 160, &fin);

  for (x = 0; x < 5; x++)
    mac[x] = fin.h[x];
  return 0;

}

/////////////////////////////:
