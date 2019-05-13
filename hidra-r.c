#include "contiki.h"

#include "lib/random.h"

#include "net/ip/uip.h"
#include "net/ipv6/uip-nd6.h"
#include "net/ipv6/uip-ds6-route.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/leds.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"

#include "lib/memb.h"
#include "cfs/cfs.h"

#include "tiny-AES-c/aes.h"

//#include "tinycrypt/lib/include/tinycrypt/hmac.h"
//#include "tinycrypt/lib/include/tinycrypt/sha256.h"
//#include "tinycrypt/lib/include/tinycrypt/constants.h"
//#include "tinycrypt/lib/include/tinycrypt/utils.h"
//#include "tinycrypt/tests/include/test_utils.h"

//#include "sha.h"

//#include "hmac/hmac_sha2.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

//#include "policy.h"
#include "encoded-policy.h"
#include "bit-operations.h"




// To print the IPv6 addresses in a friendlier way
//#include "debug.h"
//#define DEBUG DEBUG_PRINT
//#include "net/ip/uip-debug.h"

//#include "hmac-sha1.h"

#define SERVER_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

#define MAX_NUMBER_OF_SUBJECTS 3

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);
uint8_t same_mac(const uint8_t * hashed_value, uint8_t * array_to_check, uint8_t length_in_bytes);
void hmac_md5(const uint8_t key[16], const uint8_t *data, int data_len, uint8_t* digest);

static struct simple_udp_connection unicast_connection_server;
static struct simple_udp_connection unicast_connection_subject;

uip_ipaddr_t resource_addr;

uint8_t resource_key[16] =
	{ (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

uint8_t messaging_buffer[73];

//General file structure is a concatenation of: //TODO dit kan veel beter door ze hier te declareren en in het programma te initialiseren. Dan kan je wel relatief tov elkaar indexen
//Current last one-way key chain value Kr,cm
uint8_t k_i_r_cm_offset = 0;
//Pending subject number
uint8_t sub_offset = 16;
//Nonce3
uint8_t nonce3_offset = 17;


uint8_t any_previous_key_chain_value_stored = 0;

static void full_print_hex(const uint8_t* str, uint8_t length);
static void print_hex(const uint8_t* str, uint8_t len);
static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length);
uint8_t is_next_in_chain(uint8_t * next, uint8_t *initial_msg, size_t initial_len);

uint8_t nb_of_associated_subjects;
struct associated_subjects * associated_subjects;

MEMB(alloc_associated_subjects, struct associated_subject, MAX_NUMBER_OF_SUBJECTS);

struct associated_subject *
associate_new_subject(uint8_t subject_id)
{
	struct associated_subject * current_subject = memb_alloc(&alloc_associated_subjects);
	if(current_subject == NULL) {
		return NULL;
	}

	current_subject->id = subject_id;
//	printf("new subject id : %d\n", current_subject->id);
	return current_subject;
}

void
deassociate_subject(struct associated_subject *sub)
{
	memb_free(&alloc_associated_subjects, sub);

}

MEMB(policies, struct policy, MAX_NUMBER_OF_SUBJECTS);

struct policy *
store_policy(struct associated_subject * subject, uint8_t *policy_to_copy)
{
	struct policy * policy = memb_alloc(&policies);
	if(policy == NULL) {
		return NULL;
	}
	memcpy(policy->content, policy_to_copy, subject->policy_size);
	subject->policy = policy->content;
	return policy;
}

void
delete_policy(struct policy *p)
{
	memb_free(&policies, p);
}

struct nonce_sr {
   uint8_t content[8];
};

/*
 * Change policy related to subject with general DENY.
 * If no associated subject exists with subject_id, return failure = 0
 */
uint8_t
blacklist_subject(struct associated_subjects *assocs, uint8_t subject_id)
{
	uint8_t result = 0;

	int subject_index = 0;
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
//		printf("assocs->subject_association_set[subject_index]->id: %d\n", assocs->subject_association_set[subject_index]->id);
		if(assocs->subject_association_set[subject_index]->id == subject_id) {
			uint8_t policy_id = get_char_from(0, assocs->subject_association_set[subject_index]->policy);

			//Set enough memory to zero for the new policy (TODO actually redundant?)
			memset(assocs->subject_association_set[subject_index]->policy, 0, 2);

			// Same policy id
			assocs->subject_association_set[subject_index]->policy[0] = policy_id;
			// Deny everything, no extra rules.
			assocs->subject_association_set[subject_index]->policy[1] = 0;
			assocs->subject_association_set[subject_index]->policy_size = 2;

			result = 1;
			// print policy, for debugging
//			printf("After blacklist: \n");
//			print_policy(assocs->subject_association_set[subject_index]->policy, 0);
		}
	}
	return result;
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
	uint8_t (*func_ptr)(void) = get_reference(function)->function_pointer;
	if (*func_ptr == NULL) {
//		printf("Something went wrong executing a function pointer.\n");
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
//	printf("Sending NACK \n");

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
//	printf("Sending ACK to \n");

	const char response = 1;
	simple_udp_sendto(c, &response, 1, sender_addr);
}

static uint8_t
is_already_associated(uint8_t id)
{
	uint8_t result = 0;

	int subject_index = 0;

	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
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
//	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
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

	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
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
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
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

	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == id &&
				associated_subjects->subject_association_set[subject_index]->hid_s_r_req_succes) {
			result = 1;
		}
	}

	return result;
}

static void
set_fresh_information(uint8_t subject_id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id) {
			associated_subjects->subject_association_set[subject_index]->fresh_information = bit;
		}
	}
}

static uint8_t
fresh_information(uint8_t subject_id)
{
	uint8_t result = 0;

	int subject_index = 0;
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id &&
				associated_subjects->subject_association_set[subject_index]->fresh_information) {
			result = 1;
		}
	}
	return result;
}

static void
set_hid_cm_ind_req_success(uint8_t subject_id, uint8_t bit)
{
	int subject_index = 0;
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
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
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id &&
				associated_subjects->subject_association_set[subject_index]->hid_cm_ind_req_success) {
			result = 1;
		}
	}
	return result;
}

static uint8_t *
get_session_key(uint8_t subject_id) {

	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			return associated_subjects->subject_association_set[sub_index]->session_key;
		}
	}
	return NULL;
}

static void
set_session_key(uint8_t subject_id, uint8_t * key)
{	
	int subject_index = 0;
	for (; subject_index < nb_of_associated_subjects ; subject_index++) {
		if(associated_subjects->subject_association_set[subject_index]->id == subject_id) {
			memcpy(
				associated_subjects->subject_association_set[subject_index]->session_key, 
				key,
				16
			);
		}
	}
}

static uint8_t *
get_nonce_sr(uint8_t subject_id) {

//	printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			printf("associated_subjects->subject_association_set[sub_index]->nonce_sr: \n");
			full_print_hex(associated_subjects->subject_association_set[sub_index]->nonce_sr, 8);
			return associated_subjects->subject_association_set[sub_index]->nonce_sr;
		}
	}
	return NULL;
}

static uint8_t
set_nonce_sr(uint8_t subject_id, uint8_t *nonce) {

	printf("nonce: \n");
	full_print_hex(nonce, 8);

//	printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			memcpy(
					associated_subjects->subject_association_set[sub_index]->nonce_sr,
					nonce,
					8
					);
			return 1;
		}
	}
	return 0;
}

static uint8_t
condition_is_met(uint8_t *policy, int expression_bit_index)
{
	uint8_t function = get_char_from(expression_bit_index, policy);
	expression_bit_index += 8;

	uint8_t input_existence_mask = get_bit(expression_bit_index, policy);
	if (input_existence_mask) {
//		printf("(function: condition_is_met) Did not expect a function with arguments.\n");
	} else {
		return execute(function);
	}

//	printf("Something went wrong with condition %d.\n", function);
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
//		printf("(function: perform_task) Did not expect a task with arguments.\n");
	} else {
		execute(function);
		return;
	}
//	printf("Error processing task %d.\n", function);
}

//Expectation: data points to value behind sub_id in the message. Data before the hash is padded to fit a full byte
static uint8_t
handle_subject_access_request(const uint8_t *data,
        uint16_t datalen,
        uint8_t sub_id)
{
	printf("Handling subject %d access request\n", sub_id);
	uint8_t * session_key = get_session_key(sub_id);
	if (session_key == NULL) {
		printf("Error: retrieving session key");
	}

	//Assumption: access request is not longer than 73 bytes
	memcpy(messaging_buffer, data, datalen);

//	printf("Full encrypted message: ");
//	full_print_hex(messaging_buffer, datalen);

	//Decrypt whole message
	xcrypt_ctr(session_key, messaging_buffer, datalen);

	printf("Full message: ");
	full_print_hex(messaging_buffer, datalen);

	//Check validity
	uint32_t hashed;
	hashed = murmur3_32(messaging_buffer, 3, 17);
	if ((messaging_buffer[3] == ((hashed >> 24) & 0xff)) && (messaging_buffer[4] == ((hashed >> 16) & 0xff)) &&
	(messaging_buffer[5] == ((hashed >> 8)  & 0xff)) && (messaging_buffer[6] == (hashed & 0xff))) {
		//Expected demo format: Action: PUT + Task: light_switch_x TODO is veranderd!
		uint8_t action = messaging_buffer[0];
		uint8_t function = messaging_buffer[1];

		if (get_bit(2*8, messaging_buffer)){
			printf("Error: This demo does not expect any inputs\n");
		}

		// print request (if it is the expected demo request)
		if (action == 2 && function == 18) {
			printf("Receive a PUT light_switch_on request from subject %d.\n", sub_id);
		} else if (action == 2 && function == 19) {
			printf("Receive a PUT light_switch_off request from subject %d.\n", sub_id);
		} else {
			printf("Did not receive the expected demo-request.\n");
			return 0;
		}

		// Search for first policy associated with this subject
		char exists = 0;
		struct associated_subject *current_sub;
		int sub_index = 0;
		for (; sub_index < nb_of_associated_subjects ; sub_index++) {
			current_sub = associated_subjects->subject_association_set[sub_index];
			if (current_sub->id == sub_id) {
				exists = 1;
				break;
			}
		}
		if (exists) {
			// Assumption for demo purposes: 1 single rule inside the policy
			char rule_checks_out = 0;

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
//						printf("Condition was met, therefore access is granted.\n");
						rule_checks_out = 1;
					} else if (condition_met && rule_get_effect(current_sub->policy, rule_bit_index) == 1) {
//						printf("Condition was not met, therefore access is granted.\n");
						rule_checks_out = 1;
					} else {
//						printf("Rule effect is %d, while condition result was %d => Access denied.\n", rule_get_effect(current_sub->policy, rule_bit_index), condition_is_met(current_sub->policy,exp_bit_index));
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

				// Let's assume this operation requires a lot of battery
				if (battery_level > 50) {
					battery_level -= 50;
					printf("new battery level: %d\n", battery_level);
				}
				return 1;
			} else {
				printf("Request denied, because not all rules check out.\n");
				return 0;
			}

		} else {
			// deny if no association with subject exists
			printf("Request denied, because no association with this subject exists.\n");
			return 0;
		}
	} else {
		printf("Request denied, hash does not match.\n");
		return 0;
	}
}

static uint8_t
process_s_r_req(struct simple_udp_connection *c,
        const uip_ipaddr_t *sender_addr,
        const uint8_t *data,
		uint16_t datalen) {
//	static uint8_t messaging_buffer[60];
	printf("datalen %d == 60?\n", datalen);
	memcpy(messaging_buffer, data, 60);
	printf("Full HID_S_R_REQ message: \n");
	full_print_hex(messaging_buffer, 60);

	printf("of which is encrypted ticketR: \n");
	full_print_hex(messaging_buffer, 26);

	printf("Encrypted ticketR, bit 8: \n");
	full_print_hex(messaging_buffer + 8, 1);

	//Decrypt Ticket with resource key
	xcrypt_ctr(resource_key, messaging_buffer, 26);

	printf("Decrypted ticketR: \n");
	full_print_hex(messaging_buffer, 26);

	printf("Decrypted ticketR, bit 8: \n");
	full_print_hex(messaging_buffer + 8, 1);


	//Check subject id for association existence and protocol progress
	uint8_t subject_id = messaging_buffer[17];
	if (is_already_associated(subject_id) && hid_cm_ind_success(subject_id) && fresh_information(subject_id)) {
		// Assumption: no access control attributes to check

		static uint8_t ksr[16];
		memcpy(ksr, messaging_buffer, 16);
		printf("Ksr: \n");
		full_print_hex(ksr, 16);

		printf("AuthNR before decryption: \n");
		full_print_hex(messaging_buffer + 26, 26);

		// Use Ksr to decrypt AuthNr
		xcrypt_ctr(ksr, messaging_buffer + 26, 26);

		printf("AuthNR after decryption: \n");
		full_print_hex(messaging_buffer + 26, 26);


		// Check NonceSR from AuthNr against stored value
		uint8_t * nonce_sr_from_storage = get_nonce_sr(subject_id);
		if (nonce_sr_from_storage == NULL) {
			printf("Error: retrieving nonceSR\n");
			return 0;
		}

		printf("nonce = messaging_buffer + 28: \n");
		full_print_hex(messaging_buffer + 28, 8);

		if (memcmp(nonce_sr_from_storage, messaging_buffer + 28, 8) != 0) {
			printf("Error: wrong NonceSR in AuthNr.\n");
			return 0;
		}

		// Check NonceSR in the ticket against this same value
		if (memcmp(nonce_sr_from_storage, messaging_buffer + 18, 8) != 0){
			printf("Error: wrong NonceSR in ticketR.\n");
			return 0;
		}

		// Check subject id again
		if (memcmp(&subject_id, messaging_buffer + 27, 1) != 0) {
			printf("Error: wrong subject id in AuthNr.\n");
			return 0;
		}

		// Accept and store subkey/session key (in memory allocated for this subject)
		set_session_key(subject_id, messaging_buffer + 36);

		set_hid_s_r_req_success(subject_id, 1);

//		printf("Constructing HID_S_R_REP message\n");
		static uint8_t s_r_rep[32];
		//Put NonceSR
		memcpy(s_r_rep, nonce_sr_from_storage, 8);

		//Put session key
		memcpy(s_r_rep + 8, messaging_buffer + 36, 16);

		//Put Nonce4
		memcpy(s_r_rep + 24, messaging_buffer + 52, 8);

		//Encrypt with ksr
		xcrypt_ctr(messaging_buffer, s_r_rep, sizeof(s_r_rep));

		// send this message
		simple_udp_sendto(c, s_r_rep, 32, sender_addr);
		return 1;
	} else {
		return 0;
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
	printf("Received data from subject with length %d\n", datalen);
	// Rough demo separator between access request and key establishment request

//	//Only to test responsiveness, delete later:
//	if (datalen == 53) {
//		send_nack(c, sender_addr);
//	} else
	if (datalen > 20) {
		//TODO handle response
		uint8_t result = process_s_r_req(c, sender_addr, data, datalen);
		if (!result) {
			send_nack(c, sender_addr);
		}
	} else {
		uint8_t subject_id = data[0];
		//TODO check nog booleans, maar lijkt wel te kloppen?
		if (hid_s_r_req_success(subject_id) && fresh_information(subject_id)) {
			if (handle_subject_access_request(data+1, datalen-1, subject_id)){
				send_ack(c, sender_addr);
			} else {
				send_nack(c, sender_addr);
			}
		} else {
			printf("Request denied, because no association with this subject exists.\n");
			send_nack(c, sender_addr);
		}
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

//	printf("Nonce3: \n");
//	full_print_hex(cm_ind_req+2, 8);
	//Store Nonce3 for later use
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_ind_req + 2, 8);
		cfs_close(fd_write);
		printf("Successfully written Nonce3 (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
//	   printf("Error: could not write Nonce3 to memory.\n");
	}

	//Compute and fill MAC
	uint8_t array_with_key[20];
	memcpy(array_with_key, resource_key, 16);
	memcpy(array_with_key + 16, cm_ind_req, 4);
	//Differences between murmur3 implementations => always take the first 20 bytes as a comparison for now.
	uint32_t hashed = murmur3_32(array_with_key, 20, 17);

	cm_ind_req[10] = (hashed >> 24) & 0xff;
	cm_ind_req[11] = (hashed >> 16) & 0xff;
	cm_ind_req[12] = (hashed >> 8)  & 0xff;
	cm_ind_req[13] = hashed & 0xff;

//	printf("Resulting hash: \n");
//	full_print_hex(cm_ind_req+10, 4);
}

static uint8_t
process_cm_ind(uint8_t subject_id,
		const uint8_t *data,
		uint16_t datalen) {
	const char * filename = "properties";
	// Enough room for a 40 byte policy
//	static uint8_t messaging_buffer[73];
//	printf("datalen %d, so policy is of length %d\n", datalen, datalen - 33);
	memcpy(messaging_buffer, data, datalen);
//	printf("Full HID_CM_IND message: \n");
//	full_print_hex(messaging_buffer, sizeof(messaging_buffer));

	uint8_t need_to_request_next_key = 0;

	if(same_mac(messaging_buffer + datalen - 4, messaging_buffer + 2, datalen - 6)) {
		if (nb_of_associated_subjects >= 10) {
//			printf("Oops, the number of associated subjects is currently set to 10.\n");
		}
		nb_of_associated_subjects++;

		struct associated_subject *current_subject = associate_new_subject(subject_id);

		if (current_subject == NULL) {
//			printf("Error in associate_new_subject(subject_id)\n");
		}

		associated_subjects->subject_association_set[nb_of_associated_subjects - 1] = current_subject;

		// assign policy size based on knowledge about the rest of the message
		current_subject->policy_size = datalen - 33;
//		printf("new subject policy_size: %d\n", current_subject->policy_size);

		// decrypt policy before storage
		xcrypt_ctr(resource_key, messaging_buffer + 29, current_subject->policy_size);

		// allocate memory and copy decrypted policy
		struct policy *p =  store_policy(current_subject, messaging_buffer + 29);
		if(p == NULL) {
//			printf("Error in store_policy()\n");
		}

		// print policy, for debugging
//		printf("Policy associated to subject %d : \n", subject_id);
//		print_policy(current_subject->policy, 0);

		//Ignore lifetime value

		//Store nonce_sr for this subject
		uint8_t n = set_nonce_sr(current_subject->id, messaging_buffer + 4);
		if(n == 0) {
			printf("Error in set_nonce_sr()\n");
		}

//		printf("Nonce_sr:\n");
//		full_print_hex(current_subject->nonce_sr, 8);

		if (!any_previous_key_chain_value_stored) {
			any_previous_key_chain_value_stored = 1; //=> on requests from next subjects, to do or not to do?
			current_subject->fresh_information = 0;

//			printf("Kircm: \n");
//			full_print_hex(messaging_buffer + 13, 16);
			//Write this value to file system
			int fd_write = cfs_open(filename, CFS_WRITE);
			if(fd_write != -1) {
				int n = cfs_write(fd_write, messaging_buffer + 13, 16);
				cfs_close(fd_write);
//				printf("Successfully written Kircm (%i bytes) to %s\n", n, filename);
//				printf("\n");
			} else {
//			   printf("Error: could not write Kircm to memory.\n");
			}

			//Write subject id to file system to update freshness later on
			fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
			if(fd_write != -1) {
				int n = cfs_write(fd_write, &subject_id, 1);
				cfs_close(fd_write);
//				printf("Successfully written subject id (%i bytes) to %s\n", n, filename);
//				printf("\n");
			} else {
//			   printf("Error: could not write subject id to memory.\n");
			}
			need_to_request_next_key = 1;
		} else {

			//This is not handled in the demo
//			printf("Error: key chain value shouldn't exist\n");

		}


		//TODO only in case of success(?)
		current_subject->hid_cm_ind_success = 1;
	} else {
//		printf("Incorrect MAC code\n");
	}
	return need_to_request_next_key;
}

static uint8_t
process_cm_ind_rep(const uint8_t *data,
		uint16_t datalen) {
	const char * filename = "properties";
	printf("datalen %d == 22?\n", datalen);
	printf("Processing HID_CM_IND_REP message\n");

	// MAC calculation
	uint8_t for_mac[4];
	memcpy(for_mac, data, 2);
	//Get nonce 3 from storage
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	   cfs_seek(fd_read, nonce3_offset, CFS_SEEK_SET);
	   cfs_read(fd_read, for_mac + 2, 2);
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read nonce from memory.\n");
	 }

	if(same_mac(data + 18, for_mac, 4)) {
		//Check key chain value with stored value
		static uint8_t new_key[16];
		memcpy(new_key, data + 2, 16);
		static uint8_t old_key[16];
		fd_read = cfs_open(filename, CFS_READ);
		if(fd_read!=-1) {
		  cfs_read(fd_read, old_key, 16);
		  cfs_close(fd_read);
		} else {
		  printf("Error: could not read nonce from memory.\n");
		}

		printf("new_key: \n");
		full_print_hex(new_key, 16);
		printf("old_key: \n");
		full_print_hex(old_key, 16);

		if (is_next_in_chain(old_key, new_key, 16)) {
			//Get pending subject number for file system and update freshness
			uint8_t subject_id;
			fd_read = cfs_open(filename, CFS_READ);
			if(fd_read!=-1) {
				cfs_seek(fd_read, sub_offset, CFS_SEEK_SET);
				cfs_read(fd_read, &subject_id, 1);
				cfs_close(fd_read);
				printf("Setting freshness of subject %d\n", subject_id);
				set_fresh_information(subject_id, 1);
				return 1;
			} else {
				printf("Error: could not read subect id from memory.\n");
				return 0;
			}
		} else {
			printf("Error: Not a correct key, therefore subject information is not fresh \n");
			return 0;
		}
	} else {
		printf("Incorrect MAC code\n");
		return 0;
	}
}

static uint8_t
set_up_hidra_association_with_server(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		const uint8_t *data,
        uint16_t datalen)
{
//	printf("Resource id 2 == %d \n", data[1]);

	if (datalen < 33) {
		if (process_cm_ind_rep(data, datalen)) {
			send_ack(c, sender_addr);
		} else {
			send_nack(c, sender_addr);
		}
		//Clean up for next demo association (as it is at the moment)
		any_previous_key_chain_value_stored = 0;

		const char * filename = "properties";
		cfs_remove(filename);
//		printf("\n");
//		printf("End of Hidra exchange with ACS\n");
		return 1;
	}

//	printf("Subject id 3 == %d \n", data[3]);
	uint8_t subject_id = data[3];

	// If this is the first exchange with the ACS: extract subject id and policy
	if (!is_already_associated(subject_id)) {
		if (process_cm_ind(subject_id, data, datalen)) {
			//Request previous key chain value at credential manager
			static uint8_t response[14];
			construct_cm_ind_req(response);
			//Send message to credential manager
			simple_udp_sendto(c, response, sizeof(response), sender_addr);
		} else {
			printf("Processed HID_CM_IND and did not need HID_CM_IND_REQ to request new key.\n");
		}
	}
	else {
		printf("Did not receive from ACS what was expected in the protocol.\n");
	}
	return 1;
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

//	printf("Updating policy : \n");
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
receiver_server(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
//  printf("\nData received from: ");
//  PRINT6ADDR(sender_addr);
//  printf("\nAt port %d from port %d with length %d\n",
//		  receiver_port, sender_port, datalen);
//  printf("\n");
  //The first byte indicates the purpose of this message from the trusted server
  if (data[0]) {
	  if (is_already_associated(data[2])) {
		  handle_policy_update(c, sender_addr, data+1, datalen-1, 0);
	  } else {
//		  printf("Trying to update a policy of a non-associated subject. \n");
	  }
  } else {
	  set_up_hidra_association_with_server(c, sender_addr, data+1, datalen-1);
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

//  printf("IPv6 addresses: ");
//  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
//    state = uip_ds6_if.addr_list[i].state;
//    if(uip_ds6_if.addr_list[i].isused &&
//       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
//      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
//      printf("\n");
//    }
//  }

  return &ipaddr;
}

//void
//test_hmac() {
//
//	static const uint8_t text[43] =
//	{
//			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
//			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
//			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
//	};
//
//	printf("Vector: \n");
//	full_print_hex(text, sizeof(text));
//
//	printf("Key: \n");
//	full_print_hex(resource_key, sizeof(resource_key));
//
//	static uint8_t digest[256];
//	static uint8_t result;
//	result = hmac (SHA256, text, sizeof(text), resource_key, sizeof(resource_key), digest);
//	if (result != 0) {
//		printf("Error: processing hmac. \n");
//	}
//
//	printf("HMAC_SHA256: \n");
//	full_print_hex(digest, 32);
//
//	static uint32_t hashed;
//	hashed = murmur3_32(digest, 32, 17);
//	uint8_t hashed_array[4];
//	hashed_array[0] = (hashed >> 24) & 0xff;
//	hashed_array[1] = (hashed >> 16) & 0xff;
//	hashed_array[2] = (hashed >> 8)  & 0xff;
//	hashed_array[3] = hashed & 0xff;
//
//	printf("Hashed HMAC_SHA256: \n");
//	full_print_hex(hashed_array, 4);
//}

//void
//test_hmac_sha2() {
//
////	static uint8_t text[43] =
////	{
////			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
////			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
////			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
////	};
//	static uint8_t text[48] =
//		{
//				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
//				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
//				0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
//		};
//
//	printf("Vector: \n");
//	full_print_hex(text, sizeof(text));
//
//	printf("Key: \n");
//	full_print_hex(resource_key, sizeof(resource_key));
//
//	//TODO wat als je mac_size kleiner maakt? Minder global geheugen alleen. Maar is dat even veilig? Geen idee
//	static uint8_t digest[256];
//
//	hmac_sha256(resource_key, 16,
//	          text, sizeof(text),
//	          digest, sizeof(digest));
//
//	printf("HMAC_SHA256: \n");
//	full_print_hex(digest, 32); //TODO weird: is only partially (none of the hex numbers)? Like networking is just 'not executed'
//
//	static uint32_t hashed;
//	hashed = murmur3_32(digest, 32, 17);
//	uint8_t hashed_array[4];
//	hashed_array[0] = (hashed >> 24) & 0xff;
//	hashed_array[1] = (hashed >> 16) & 0xff;
//	hashed_array[2] = (hashed >> 8)  & 0xff;
//	hashed_array[3] = hashed & 0xff;
//
//	printf("Hashed HMAC_SHA256: \n");
//	full_print_hex(hashed_array, 4);
//}

///////////////////


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
	int result = simple_udp_register(&unicast_connection_subject, SUBJECT_UDP_PORT,
							  NULL, SUBJECT_UDP_PORT,
							  receiver_subject);
//	printf("result socket: %d\n", result);
	nb_of_associated_subjects = 0;

	initialize_reference_table();

//	test_hmac();

//	test_hmac_sha2();


//	static const uint8_t data[43] =
//	        	{
//	        			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
//	        			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c,
//	        			0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd
//	        	};

//	static const uint8_t data[8] =
//	        	{
//	        			0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
//	        	};
//
//
//	uint8_t digest[16];
//	memset(digest, 0, 16);
//	hmac_md5(resource_key, data, sizeof(data), digest);
//
//	full_print_hex(digest, 16);

	static int loop_counter = 0;
	while(1) {
		printf("loop_counter: %d\n",loop_counter);
		PROCESS_WAIT_EVENT();
		loop_counter++;
	}

	PROCESS_END();
}

static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length)
{
	static uint8_t iv[16]  = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, in, length);
}

static void full_print_hex(const uint8_t* str, uint8_t length) {
	printf("********************************\n");
	int i = 0;
	for (; i < (length/16) ; i++) {
		print_hex(str + i * 16, 16);
	}
	print_hex(str + i * 16, length%16);
	printf("********************************\n");
}

// prints string as hex
static void print_hex(const uint8_t* str, uint8_t len)
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

//Assumption about length of hash: 4
//Quick fix: mac is hash of (resource_key | message)
uint8_t
same_mac(const uint8_t * hashed_value, uint8_t * array_to_check, uint8_t length_in_bytes) {
	uint8_t array_with_key[length_in_bytes + 16];
	memcpy(array_with_key, resource_key, 16);
	memcpy(array_with_key + 16, array_to_check, length_in_bytes);
//	printf("Array before hash: \n");
//	full_print_hex(array_with_key, length_in_bytes + 16);
//	printf("Length: %d\n", sizeof(array_with_key));
	//Differences between murmur3 implementations => always take the first 20 bytes as a comparison for now.
	uint32_t hashed = murmur3_32(array_with_key, 20, 17);
	uint8_t hashed_array[4];
	hashed_array[0] = (hashed >> 24) & 0xff;
	hashed_array[1] = (hashed >> 16) & 0xff;
	hashed_array[2] = (hashed >> 8)  & 0xff;
	hashed_array[3] = hashed & 0xff;
//	printf("Result should be: \n");
//	full_print_hex(hashed_value, 4);
//	printf("Actual hash: \n");
//	full_print_hex(hashed_array, 4);
	return (hashed_array[0] == hashed_value[0] &&
			hashed_array[1] == hashed_value[1] &&
			hashed_array[2] == hashed_value[2] &&
			hashed_array[3] == hashed_value[3]);
}

//Hash to 32 bits from https://en.wikipedia.org/wiki/MurmurHash
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	printf("Values to hash\n");
	full_print_hex(key, len);
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

//////////////////HMAC MD5

//Source: https://download.samba.org/pub/unpacked/junkcode/lsakey/

/*
   Unix SMB/CIFS implementation.
   HMAC MD5 code for use in NTLMv2
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Tridgell 1992-2000

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* taken direct from rfc2104 implementation and modified for suitable use
 * for ntlmv2.
 */

#include <ctype.h>
#include <sys/types.h>
//#include <sys/mman.h>
//#include <sys/stat.h>
//#include <unistd.h>
//#include <fcntl.h>

struct MD5Context {
	uint32_t buf[4];
	uint32_t bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct MD5Context MD5_CTX;

#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

typedef struct
{
        struct MD5Context ctx;
        uint8_t k_ipad[65];
        uint8_t k_opad[65];

} HMACMD5Context;

void hmac_md5_init_rfc2104(const uint8_t*  key, int key_len, HMACMD5Context *ctx);
void hmac_md5_init_limK_to_64(const uint8_t* key, int key_len,HMACMD5Context *ctx);
void hmac_md5_update(const uint8_t* text, int text_len, HMACMD5Context *ctx);
void hmac_md5_final(uint8_t *digest, HMACMD5Context *ctx);

void arcfour(uint8_t *data, int len, const uint8_t *key, int key_len);

void cred_hash2(uint8_t *out, const uint8_t *in, const uint8_t *key, int forw);
void des_crypt56(uint8_t *out, const uint8_t *in, const uint8_t *key, int forw);

static void MD5Transform(uint32_t buf[4], uint32_t const in[16]);

/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse(unsigned char *buf, unsigned longs)
{
    uint32_t t;
    do {
	t = (uint32_t) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
	    ((unsigned) buf[1] << 8 | buf[0]);
	*(uint32_t *) buf = t;
	buf += 4;
    } while (--longs);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5Init(struct MD5Context *ctx)
{
    ctx->buf[0] = 0x67452301;
    ctx->buf[1] = 0xefcdab89;
    ctx->buf[2] = 0x98badcfe;
    ctx->buf[3] = 0x10325476;

    ctx->bits[0] = 0;
    ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5Update(struct MD5Context *ctx, unsigned char const *buf, unsigned len)
{
    register uint32_t t;

    /* Update bitcount */

    t = ctx->bits[0];
    if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
	ctx->bits[1]++;		/* Carry from low to high */
    ctx->bits[1] += len >> 29;

    t = (t >> 3) & 0x3f;	/* Bytes already in shsInfo->data */

    /* Handle any leading odd-sized chunks */

    if (t) {
	unsigned char *p = (unsigned char *) ctx->in + t;

	t = 64 - t;
	if (len < t) {
	    memmove(p, buf, len);
	    return;
	}
	memmove(p, buf, t);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += t;
	len -= t;
    }
    /* Process data in 64-byte chunks */

    while (len >= 64) {
	memmove(ctx->in, buf, 64);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	buf += 64;
	len -= 64;
    }

    /* Handle any remaining bytes of data. */

    memmove(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5Final(unsigned char digest[16], struct MD5Context *ctx)
{
    unsigned int count;
    unsigned char *p;

    /* Compute number of bytes mod 64 */
    count = (ctx->bits[0] >> 3) & 0x3F;

    /* Set the first char of padding to 0x80.  This is safe since there is
       always at least one byte free */
    p = ctx->in + count;
    *p++ = 0x80;

    /* Bytes of padding needed to make 64 bytes */
    count = 64 - 1 - count;

    /* Pad out to 56 mod 64 */
    if (count < 8) {
	/* Two lots of padding:  Pad the first block to 64 bytes */
	memset(p, 0, count);
	byteReverse(ctx->in, 16);
	MD5Transform(ctx->buf, (uint32_t *) ctx->in);

	/* Now fill the next block with 56 bytes */
	memset(ctx->in, 0, 56);
    } else {
	/* Pad block to 56 bytes */
	memset(p, 0, count - 8);
    }
    byteReverse(ctx->in, 14);

    /* Append length in bits and transform */
    ((uint32_t *) ctx->in)[14] = ctx->bits[0];
    ((uint32_t *) ctx->in)[15] = ctx->bits[1];

    MD5Transform(ctx->buf, (uint32_t *) ctx->in);
    byteReverse((unsigned char *) ctx->buf, 4);
    memmove(digest, ctx->buf, 16);
    memset(ctx, 0, sizeof(ctx));	/* In case it's sensitive */
}

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
	( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5Transform(uint32_t buf[4], uint32_t const in[16])
{
    register uint32_t a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}
/***********************************************************************
 the rfc 2104 version of hmac_md5 initialisation.
***********************************************************************/
void hmac_md5_init_rfc2104(const uint8_t*  key, int key_len, HMACMD5Context *ctx)
{
        int i;

        /* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64)
	{
		uint8_t tk[16];
                struct MD5Context tctx;

                MD5Init(&tctx);
                MD5Update(&tctx, key, key_len);
                MD5Final(tk, &tctx);

                key = tk;
                key_len = 16;
        }

        /* start out by storing key in pads */
        ZERO_STRUCT(ctx->k_ipad);
        ZERO_STRUCT(ctx->k_opad);
        memcpy( ctx->k_ipad, key, key_len);
        memcpy( ctx->k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++)
	{
                ctx->k_ipad[i] ^= 0x36;
                ctx->k_opad[i] ^= 0x5c;
        }

        MD5Init(&ctx->ctx);
        MD5Update(&ctx->ctx, ctx->k_ipad, 64);
}

/***********************************************************************
 the microsoft version of hmac_md5 initialisation.
***********************************************************************/
void hmac_md5_init_limK_to_64(const uint8_t* key, int key_len,
			HMACMD5Context *ctx)
{
        /* if key is longer than 64 bytes truncate it */
        if (key_len > 64)
	{
                key_len = 64;
        }

	hmac_md5_init_rfc2104(key, key_len, ctx);
}

/***********************************************************************
 update hmac_md5 "inner" buffer
***********************************************************************/
void hmac_md5_update(const uint8_t* text, int text_len, HMACMD5Context *ctx)
{
        MD5Update(&ctx->ctx, text, text_len); /* then text of datagram */
}

/***********************************************************************
 finish off hmac_md5 "inner" buffer and generate outer one.
***********************************************************************/
void hmac_md5_final(uint8_t *digest, HMACMD5Context *ctx)

{
        struct MD5Context ctx_o;
        MD5Final(digest, &ctx->ctx);

	MD5Init(&ctx_o);
	MD5Update(&ctx_o, ctx->k_opad, 64);
        MD5Update(&ctx_o, digest, 16);
        MD5Final(digest, &ctx_o);
}

/***********************************************************
 single function to calculate an HMAC MD5 digest from data.
 use the microsoft hmacmd5 init method because the key is 16 bytes.
************************************************************/
void hmac_md5(const uint8_t key[16], const uint8_t *data, int data_len, uint8_t* digest)
{
	HMACMD5Context ctx;
	hmac_md5_init_limK_to_64(key, 16, &ctx);
	if (data_len != 0)
	{
		hmac_md5_update(data, data_len, &ctx);
	}
	hmac_md5_final(digest, &ctx);
}

