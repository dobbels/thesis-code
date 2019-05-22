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

#include "../../tiny-AES-c/aes.h"

#include "../../tinycrypt/lib/include/tinycrypt/hmac.h"
#include "../../tinycrypt/lib/include/tinycrypt/sha256.h"
#include "../../tinycrypt/lib/include/tinycrypt/constants.h"
#include "../../tinycrypt/lib/include/tinycrypt/utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../../encoded-policy.h"
#include "../../bit-operations.h"

#define SERVER_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

#define MAX_NUMBER_OF_SUBJECTS 3

uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);
void compute_mac(uint8_t *key, const uint8_t *data, uint8_t datalen, uint8_t * final_digest);
uint8_t same_mac(const uint8_t * hashed_value, uint8_t * array_to_check, uint8_t length_in_bytes, uint8_t *key);

static void store_access_counter(uint8_t subject_id, uint8_t * nonce);
static void get_access_counter_increment(uint8_t subject_id, uint8_t * nonce);
static uint8_t new_nonce_is_greater_than_counter(uint8_t subject_id, uint8_t * nonce);

static uint8_t * get_session_key(uint8_t subject_id);
static void set_session_key(uint8_t subject_id, uint8_t * key);

static struct simple_udp_connection unicast_connection_server;
static struct simple_udp_connection unicast_connection_subject;

uip_ipaddr_t resource_addr;

uint8_t resource_key[16] =
	{ (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

// Enough room for a largest Hidra message
uint8_t messaging_buffer[65];

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
void md5(uint8_t * digest, uint8_t *initial_msg, size_t initial_len);

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
	//printf("new subject id : %d\n", current_subject->id);
	return current_subject;
}

void
deassociate_subject(struct associated_subject *sub)
{
	memb_free(&alloc_associated_subjects, sub);
}

//MEMB(policies, struct policy, MAX_NUMBER_OF_SUBJECTS);
//
//struct policy *
//store_policy(struct associated_subject * subject, uint8_t *policy_to_copy)
//{
//	struct policy * policy = memb_alloc(&policies);
//	if(policy == NULL) {
//		return NULL;
//	}
//	memcpy(policy->content, policy_to_copy, subject->policy_size);
//	subject->policy = policy->content;
//	return policy;
//}
//
//void
//delete_policy(struct policy *p)
//{
//	memb_free(&policies, p);
//}

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
	//printf("Sending NACK \n");

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
	//printf("Sending ACK to \n");

	const char response = 1;
	simple_udp_sendto(c, &response, 1, sender_addr);
}

static void
send_access_nack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		uint8_t subject_id)
{
	//printf("Sending NACK \n");

	//Construct 3 bytes : (zero-byte) = 1 byte + (access counter+1) = 2 bytes
	uint8_t response[3];
	response[0] = 0;
	get_access_counter_increment(subject_id, response + 1);

	//Encrypt with session key
	xcrypt_ctr(get_session_key(subject_id), response, 3);

	simple_udp_sendto(c, response, sizeof(response), sender_addr);

	// This turns on the red light, whenever anything is non-acknowledged
	leds_off(LEDS_ALL);
	leds_on(LEDS_RED);
}

static void
send_access_ack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr,
		uint8_t * subject_id)
{
	//printf("Sending ACK to \n");

	//Construct 3 bytes : (zero-byte) = 1 byte + (access counter+1) = 2 bytes
	uint8_t response[3];
	response[0] = 1;
	get_access_counter_increment(subject_id, response + 1);

	//Encrypt with session key
	xcrypt_ctr(get_session_key(subject_id), response, 3);

	simple_udp_sendto(c, response, sizeof(response), sender_addr);
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

	//printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			//printf("associated_subjects->subject_association_set[sub_index]->nonce_sr: \n");
			full_print_hex(associated_subjects->subject_association_set[sub_index]->nonce_sr, 8);
			return associated_subjects->subject_association_set[sub_index]->nonce_sr;
		}
	}
	return NULL;
}

static uint8_t
set_nonce_sr(uint8_t subject_id, uint8_t *nonce) {

	//printf("nonce: \n");
	full_print_hex(nonce, 8);

	//printf("subject_id: %d\n", subject_id);
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

static void
store_access_counter(uint8_t subject_id, uint8_t * nonce) {
	//printf("Storing access counter: \n");
	full_print_hex(nonce, 2);

	//printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			associated_subjects->subject_association_set[sub_index]->access_counter = ((*nonce) << 8) | ((*(nonce+1)));
		}
	}
}

static void
get_access_counter_increment(uint8_t subject_id, uint8_t * nonce) {
	//printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			associated_subjects->subject_association_set[sub_index]->access_counter++;
			*nonce = associated_subjects->subject_association_set[sub_index]->access_counter >> 8;
			*(nonce+1) = (associated_subjects->subject_association_set[sub_index]->access_counter & 0xff);
			//printf("Get access counter increment: \n");
			full_print_hex(nonce, 2);
		}
	}
}

static uint8_t
new_nonce_is_greater_than_counter(uint8_t subject_id, uint8_t * nonce) {
	//printf("New counter: \n");
	full_print_hex(nonce, 2);

	//printf("subject_id: %d\n", subject_id);
	int sub_index = 0;
	for (; sub_index < nb_of_associated_subjects ; sub_index++) {
		if (associated_subjects->subject_association_set[sub_index]->id == subject_id) {
			//printf("(associated_subjects->subject_association_set[sub_index]->access_counter >> 8): %d\n", (associated_subjects->subject_association_set[sub_index]->access_counter >> 8));
			//printf("*nonce: %d\n", *nonce);
			//printf("(associated_subjects->subject_association_set[sub_index]->access_counter & 0xff): %d\n", (associated_subjects->subject_association_set[sub_index]->access_counter & 0xff));
			//printf("*(nonce+1): %d\n", *(nonce+1));
			if ((associated_subjects->subject_association_set[sub_index]->access_counter >> 8) > *nonce) {
				return 0;
			} else if (((associated_subjects->subject_association_set[sub_index]->access_counter >> 8) == *nonce) &&
				((associated_subjects->subject_association_set[sub_index]->access_counter & 0xff) >= *(nonce+1))) {
					return 0;
			}
		}
	}
	return 1;
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

	printf("Error: Something went wrong with condition %d.\n", function);
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

//Expectation: data points to value behind sub_id in the message. Data before the hash is padded to fit a full byte
static uint8_t
handle_subject_access_request(const uint8_t *data,
        uint16_t datalen,
        uint8_t sub_id)
{
	//printf("Handling subject %d access request\n", sub_id);
	uint8_t * session_key = get_session_key(sub_id);
	if (session_key == NULL) {
		printf("Error: retrieving session key");
	}

	// Encrypt-and-MAC (E&M) => Decrypt-and-MAC
	xcrypt_ctr(session_key, data + 2, datalen - 6);

	uint8_t mac[4];
	compute_mac(session_key, data, datalen - 4, mac);

	if (memcmp(data + datalen - 4, mac, 4) == 0) {

		int bit_index = 16;
		uint8_t action = get_bits_between(bit_index, bit_index + 2, data);
		bit_index += 2;
		uint8_t function = get_char_from(bit_index, data);
		bit_index += 8;

		if (get_bit(bit_index, data)){
			printf("Error: This demo does not expect any inputs\n");
		}

		if (new_nonce_is_greater_than_counter(sub_id, data + 4)) {
			store_access_counter(sub_id, data + 4);

			// print request (if it is the expected demo request)
			if (action == 2 && function == 18) {
				//printf("Receive a PUT light_switch_on request from subject %d.\n", sub_id);
			} else if (action == 2 && function == 19) {
				//printf("Receive a PUT light_switch_off request from subject %d.\n", sub_id);
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
						//printf("new battery level: %d\n", battery_level);
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
			printf("This is an old message, therefore it is discarded.\n");
			return -1;
		}
	} else {
		printf("Request denied, MAC does not match.\n");
		return 0;
	}
}

static uint8_t
process_s_r_req(struct simple_udp_connection *c,
        const uip_ipaddr_t *sender_addr,
        const uint8_t *data,
		uint16_t datalen) {
//	static uint8_t messaging_buffer[60];
	//printf("datalen %d == 60?\n", datalen);
	memcpy(messaging_buffer, data, 60);
	//printf("Full HID_S_R_REQ message: \n");
	full_print_hex(messaging_buffer, 60);

	//printf("of which is encrypted ticketR: \n");
	full_print_hex(messaging_buffer, 26);

	//printf("Encrypted ticketR, bit 8: \n");
	full_print_hex(messaging_buffer + 8, 1);

	//Decrypt Ticket with resource key
	xcrypt_ctr(resource_key, messaging_buffer, 26);

	//printf("Decrypted ticketR: \n");
	full_print_hex(messaging_buffer, 26);

	//printf("Decrypted ticketR, bit 8: \n");
	full_print_hex(messaging_buffer + 8, 1);


	//Check subject id for association existence and protocol progress
	uint8_t subject_id = messaging_buffer[17];
	if (is_already_associated(subject_id) && hid_cm_ind_success(subject_id) && fresh_information(subject_id)) {
		// Assumption: no access control attributes to check

		static uint8_t ksr[16];
		memcpy(ksr, messaging_buffer, 16);
		//printf("Ksr: \n");
		full_print_hex(ksr, 16);

		//printf("AuthNR before decryption: \n");
		full_print_hex(messaging_buffer + 26, 26);

		// Use Ksr to decrypt AuthNr
		xcrypt_ctr(ksr, messaging_buffer + 26, 26);

		//printf("AuthNR after decryption: \n");
		full_print_hex(messaging_buffer + 26, 26);


		// Check NonceSR from AuthNr against stored value
		uint8_t * nonce_sr_from_storage = get_nonce_sr(subject_id);
		if (nonce_sr_from_storage == NULL) {
			printf("Error: retrieving nonceSR\n");
			return 0;
		}

		//printf("nonce = messaging_buffer + 28: \n");
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

		//Store access counter for freshness of future accesses
		uint8_t zero[2];
		memset(zero,0,2);
		store_access_counter(subject_id, zero);

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
	//printf("Received data from subject %d with length %d\n", data[1], datalen);
	full_print_hex(data, datalen);
	// Rough demo separator between access request and key establishment request
	if (datalen > 20) {
		//TODO handle response
		uint8_t result = process_s_r_req(c, sender_addr, data, datalen);
		if (!result) {
			send_nack(c, sender_addr);
		}
	} else {
		uint8_t subject_id = data[1];
		if (hid_s_r_req_success(subject_id) && fresh_information(subject_id)) {
			uint8_t result = handle_subject_access_request(data, datalen, subject_id);
			if (result == -1) {
				printf("Old message => ignored.\n");
			} else if (result) {
				send_access_ack(c, sender_addr, subject_id);
			} else {
				send_access_nack(c, sender_addr, subject_id);
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

	//Store Nonce3 for later use
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_ind_req + 2, 8);
		cfs_close(fd_write);
		//printf("Successfully written Nonce3 (%i bytes) to %s\n", n, filename);
		//printf("\n");
	} else {
	   printf("Error: could not write Nonce3 to memory.\n");
	}

	//Compute and fill MAC
	static uint8_t array_to_mac[10]; //TODO should be doable without the extra array?
	memcpy(array_to_mac, cm_ind_req, 10);

	compute_mac(resource_key, array_to_mac, sizeof(array_to_mac), cm_ind_req + 10);
}

static uint8_t
process_cm_ind(uint8_t subject_id,
		const uint8_t *data,
		uint16_t datalen) {
	const char * filename = "properties";

//	static uint8_t messaging_buffer[73];
//	printf("datalen %d, so policy is of length %d\n", datalen, datalen - 33);
	memcpy(messaging_buffer, data, datalen);
	//printf("Full HID_CM_IND message: \n");
	full_print_hex(messaging_buffer, sizeof(messaging_buffer));

	uint8_t need_to_request_next_key = 0;

	if(same_mac(messaging_buffer + datalen - 4, messaging_buffer + 2, datalen - 6, resource_key)) {
		if (nb_of_associated_subjects >= 10) {
			printf("Oops, the number of associated subjects is currently set to 10.\n");
		}
		nb_of_associated_subjects++;

		struct associated_subject *current_subject = associate_new_subject(subject_id);

		if (current_subject == NULL) {
			printf("Error in associate_new_subject(subject_id)\n");
		}

		associated_subjects->subject_association_set[nb_of_associated_subjects - 1] = current_subject;

		// assign policy size based on knowledge about the rest of the message
		current_subject->policy_size = datalen - 33;

		// decrypt policy before storage
		xcrypt_ctr(resource_key, messaging_buffer + 29, current_subject->policy_size);

		// allocate memory and copy decrypted policy
//		struct policy *p =  store_policy(current_subject, messaging_buffer + 29);
//		if(p == NULL) {
//			printf("Error in store_policy()\n");
//		}

		memcpy(current_subject->policy, messaging_buffer + 29, current_subject->policy_size);

		//Ignore lifetime value

		//Store nonce_sr for this subject
		uint8_t n = set_nonce_sr(current_subject->id, messaging_buffer + 4);
		if(n == 0) {
			printf("Error in set_nonce_sr()\n");
		}

		if (!any_previous_key_chain_value_stored) {
			current_subject->fresh_information = 0;

			//Write this value to file system
			int fd_write = cfs_open(filename, CFS_WRITE);
			if(fd_write != -1) {
				int n = cfs_write(fd_write, messaging_buffer + 13, 16);
				cfs_close(fd_write);
				//printf("Successfully written Kircm (%i bytes) to %s\n", n, filename);
				//printf("\n");
			} else {
			   printf("Error: could not write Kircm to memory.\n");
			}
			any_previous_key_chain_value_stored = 1; //=> on requests from next subjects, to do or not to do?

			//Write subject id to file system to update freshness later on
			fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
			if(fd_write != -1) {
				int n = cfs_write(fd_write, &subject_id, 1);
				cfs_close(fd_write);
				//printf("Successfully written subject id (%i bytes) to %s\n", n, filename);
				//printf("\n");
			} else {
			   printf("Error: could not write subject id to memory.\n");
			}
			need_to_request_next_key = 1;
		} else {

			//This is not handled in the demo
			printf("Error: key chain value shouldn't exist\n");

		}


		//TODO only in case of success(?)
		current_subject->hid_cm_ind_success = 1;
	} else {
		printf("Incorrect MAC code\n");
	}
	return need_to_request_next_key;
}

static uint8_t
process_cm_ind_rep(const uint8_t *data,
		uint16_t datalen) {
	const char * filename = "properties";
	//printf("datalen %d == 22?\n", datalen);
	//printf("Processing HID_CM_IND_REP message\n");

	// MAC calculation
	static uint8_t for_mac[26];
	memcpy(for_mac, data, 2);
	//Get nonce 3 from storage
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	   cfs_seek(fd_read, nonce3_offset, CFS_SEEK_SET);
	   cfs_read(fd_read, for_mac + 2, 8);
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read nonce from memory.\n");
	 }
	memcpy(for_mac + 10, data + 2, 16);

	if(same_mac(data + 18, for_mac, 26, resource_key)) {
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

		//printf("new_key: \n");
		full_print_hex(new_key, 16);
		//printf("old_key: \n");
		full_print_hex(old_key, 16);

		static uint8_t next_key[16];
		md5(next_key, new_key, 16);
		//printf("next_key: \n");
		full_print_hex(next_key, 16);

		if (memcmp(old_key, next_key, 16) == 0) {
//		if (is_next_in_chain(old_key, new_key, 16)) {
			//Get pending subject number for file system and update freshness
			uint8_t subject_id;
			fd_read = cfs_open(filename, CFS_READ);
			if(fd_read!=-1) {
				cfs_seek(fd_read, sub_offset, CFS_SEEK_SET);
				cfs_read(fd_read, &subject_id, 1);
				cfs_close(fd_read);
				//printf("Setting freshness of subject %d\n", subject_id);
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
		printf("\n");
		printf("End of Hidra exchange with ACS\n");
		return 1;
	}

	//printf("Subject id is %d \n", data[3]);
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
			set_fresh_information(subject_id, 1);
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
  //The first byte indicates the purpose of this message from the trusted server
  if (data[0]) {
	  if (is_already_associated(data[2])) {
		  handle_policy_update(c, sender_addr, data+1, datalen-1, 0);
	  } else {
		  printf("Trying to update a policy of a non-associated subject. \n");
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

	while(1) {
		PROCESS_WAIT_EVENT();
	}

	PROCESS_END();
}

//Expects a digest of 4 bytes
void compute_mac(uint8_t *key, const uint8_t *data, uint8_t datalen, uint8_t * final_digest) {
	static struct tc_hmac_state_struct h;

	(void)memset(&h, 0x00, sizeof(h));
	(void)tc_hmac_set_key(&h, key, 16);

	static uint8_t digest[32];

	(void)tc_hmac_init(&h);
	(void)tc_hmac_update(&h, data, datalen);
	(void)tc_hmac_final(digest, TC_SHA256_DIGEST_SIZE, &h);

	uint32_t hashed = murmur3_32(digest, 32, 17);

	final_digest[0] = (hashed >> 24) & 0xff;
	final_digest[1] = (hashed >> 16) & 0xff;
	final_digest[2] = (hashed >> 8)  & 0xff;
	final_digest[3] = hashed & 0xff;
}

//Assumption about length of hash: 4
uint8_t
same_mac(const uint8_t * hashed_value, uint8_t * array_to_check, uint8_t length_in_bytes, uint8_t *key) {
	static uint8_t digest[4];
	compute_mac(key, array_to_check, length_in_bytes, digest);

	return (digest[0] == hashed_value[0] &&
			digest[1] == hashed_value[1] &&
			digest[2] == hashed_value[2] &&
			digest[3] == hashed_value[3]);
}

static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length)
{
	static uint8_t iv[16]  = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
	struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, in, length);
}

static void full_print_hex(const uint8_t* str, uint8_t length) {
//	printf("********************************\n");
//	int i = 0;
//	for (; i < (length/16) ; i++) {
//		print_hex(str + i * 16, 16);
//	}
//	print_hex(str + i * 16, length%16);
//	printf("********************************\n");
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
  uint32_t i, j, k; //TODO warning: if AES stops working, put back to 'unsigned', but this shouldn't make a difference
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
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	//printf("Values to hash\n");
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

/////////////////TINYCRYPT HMAC SHA256

/* utils.c - TinyCrypt platform-dependent run-time operations */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#define MASK_TWENTY_SEVEN 0x1b

uint32_t _copy(uint8_t *to, uint32_t to_len,
		   const uint8_t *from, uint32_t from_len)
{
	if (from_len <= to_len) {
		(void)memcpy(to, from, from_len);
		return from_len;
	} else {
		return TC_CRYPTO_FAIL;
	}
}

void _set(void *to, uint8_t val, uint32_t len)
{
	(void)memset(to, val, len);
}

/*
 * Doubles the value of a byte for values up to 127.
 */
uint8_t _double_byte(uint8_t a)
{
	return ((a<<1) ^ ((a>>7) * MASK_TWENTY_SEVEN));
}

int _compare(const uint8_t *a, const uint8_t *b, size_t size)
{
	const uint8_t *tempa = a;
	const uint8_t *tempb = b;
	uint8_t result = 0;

	uint32_t i;
	for (i = 0; i < size; i++) {
		result |= tempa[i] ^ tempb[i];
	}
	return result;
}


/* sha256.c - TinyCrypt SHA-256 crypto hash algorithm implementation */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

static void compress(uint32_t *iv, const uint8_t *data);

int tc_sha256_init(TCSha256State_t s)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	/*
	 * Setting the initial state values.
	 * These values correspond to the first 32 bits of the fractional parts
	 * of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17
	 * and 19.
	 */
	_set((uint8_t *) s, 0x00, sizeof(*s));
	s->iv[0] = 0x6a09e667;
	s->iv[1] = 0xbb67ae85;
	s->iv[2] = 0x3c6ef372;
	s->iv[3] = 0xa54ff53a;
	s->iv[4] = 0x510e527f;
	s->iv[5] = 0x9b05688c;
	s->iv[6] = 0x1f83d9ab;
	s->iv[7] = 0x5be0cd19;

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_update(TCSha256State_t s, const uint8_t *data, size_t datalen)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0 ||
	    data == (void *) 0) {
		return TC_CRYPTO_FAIL;
	} else if (datalen == 0) {
		return TC_CRYPTO_SUCCESS;
	}

	while (datalen-- > 0) {
		s->leftover[s->leftover_offset++] = *(data++);
		if (s->leftover_offset >= TC_SHA256_BLOCK_SIZE) {
			compress(s->iv, s->leftover);
			s->leftover_offset = 0;
			s->bits_hashed += (TC_SHA256_BLOCK_SIZE << 3);
		}
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_final(uint8_t *digest, TCSha256State_t s)
{
	uint32_t i;

	/* input sanity check: */
	if (digest == (uint8_t *) 0 ||
	    s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	s->bits_hashed += (s->leftover_offset << 3);

	s->leftover[s->leftover_offset++] = 0x80; /* always room for one byte */
	if (s->leftover_offset > (sizeof(s->leftover) - 8)) {
		/* there is not room for all the padding in this block */
		_set(s->leftover + s->leftover_offset, 0x00,
		     sizeof(s->leftover) - s->leftover_offset);
		compress(s->iv, s->leftover);
		s->leftover_offset = 0;
	}

	/* add the padding and the length in big-Endian format */
	_set(s->leftover + s->leftover_offset, 0x00,
	     sizeof(s->leftover) - 8 - s->leftover_offset);
	s->leftover[sizeof(s->leftover) - 1] = (uint8_t)(s->bits_hashed);
	s->leftover[sizeof(s->leftover) - 2] = (uint8_t)(s->bits_hashed >> 8);
	s->leftover[sizeof(s->leftover) - 3] = (uint8_t)(s->bits_hashed >> 16);
	s->leftover[sizeof(s->leftover) - 4] = (uint8_t)(s->bits_hashed >> 24);
	s->leftover[sizeof(s->leftover) - 5] = (uint8_t)(s->bits_hashed >> 32);
	s->leftover[sizeof(s->leftover) - 6] = (uint8_t)(s->bits_hashed >> 40);
	s->leftover[sizeof(s->leftover) - 7] = (uint8_t)(s->bits_hashed >> 48);
	s->leftover[sizeof(s->leftover) - 8] = (uint8_t)(s->bits_hashed >> 56);

	/* hash the padding and length */
	compress(s->iv, s->leftover);

	/* copy the iv out to digest */
	for (i = 0; i < TC_SHA256_STATE_BLOCKS; ++i) {
		uint32_t t = *((uint32_t *) &s->iv[i]);
		*digest++ = (uint8_t)(t >> 24);
		*digest++ = (uint8_t)(t >> 16);
		*digest++ = (uint8_t)(t >> 8);
		*digest++ = (uint8_t)(t);
	}

	/* destroy the current state */
	_set(s, 0, sizeof(*s));

	return TC_CRYPTO_SUCCESS;
}

/*
 * Initializing SHA-256 Hash constant words K.
 * These values correspond to the first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes between 2 and 311.
 */
static const uint32_t k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ROTR(uint32_t a, uint32_t n)
{
	return (((a) >> n) | ((a) << (32 - n)));
}

#define Sigma0(a)(ROTR((a), 2) ^ ROTR((a), 13) ^ ROTR((a), 22))
#define Sigma1(a)(ROTR((a), 6) ^ ROTR((a), 11) ^ ROTR((a), 25))
#define sigma0(a)(ROTR((a), 7) ^ ROTR((a), 18) ^ ((a) >> 3))
#define sigma1(a)(ROTR((a), 17) ^ ROTR((a), 19) ^ ((a) >> 10))

#define Ch(a, b, c)(((a) & (b)) ^ ((~(a)) & (c)))
#define Maj(a, b, c)(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

static inline uint32_t BigEndian(const uint8_t **c)
{
	uint32_t n = 0;

	n = (((uint32_t)(*((*c)++))) << 24);
	n |= ((uint32_t)(*((*c)++)) << 16);
	n |= ((uint32_t)(*((*c)++)) << 8);
	n |= ((uint32_t)(*((*c)++)));
	return n;
}

static void compress(uint32_t *iv, const uint8_t *data)
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t s0, s1;
	uint32_t t1, t2;
	uint32_t work_space[16];
	uint32_t n;
	uint32_t i;

	a = iv[0]; b = iv[1]; c = iv[2]; d = iv[3];
	e = iv[4]; f = iv[5]; g = iv[6]; h = iv[7];

	for (i = 0; i < 16; ++i) {
		n = BigEndian(&data);
		t1 = work_space[i] = n;
		t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
		t2 = Sigma0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	for ( ; i < 64; ++i) {
		s0 = work_space[(i+1)&0x0f];
		s0 = sigma0(s0);
		s1 = work_space[(i+14)&0x0f];
		s1 = sigma1(s1);

		t1 = work_space[i&0xf] += s0 + s1 + work_space[(i+9)&0xf];
		t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
		t2 = Sigma0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	iv[0] += a; iv[1] += b; iv[2] += c; iv[3] += d;
	iv[4] += e; iv[5] += f; iv[6] += g; iv[7] += h;
}

/* hmac.c - TinyCrypt implementation of the HMAC algorithm */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */


static void rekey(uint8_t *key, const uint8_t *new_key, uint32_t key_size)
{
	const uint8_t inner_pad = (uint8_t) 0x36;
	const uint8_t outer_pad = (uint8_t) 0x5c;
	uint32_t i;

	for (i = 0; i < key_size; ++i) {
		key[i] = inner_pad ^ new_key[i];
		key[i + TC_SHA256_BLOCK_SIZE] = outer_pad ^ new_key[i];
	}
	for (; i < TC_SHA256_BLOCK_SIZE; ++i) {
		key[i] = inner_pad; key[i + TC_SHA256_BLOCK_SIZE] = outer_pad;
	}
}

int tc_hmac_set_key(TCHmacState_t ctx, const uint8_t *key,
		    uint32_t key_size)
{
	/* Input sanity check */
	if (ctx == (TCHmacState_t) 0 ||
	    key == (const uint8_t *) 0 ||
	    key_size == 0) {
		return TC_CRYPTO_FAIL;
	}

	const uint8_t dummy_key[TC_SHA256_BLOCK_SIZE];
	struct tc_hmac_state_struct dummy_state;

	if (key_size <= TC_SHA256_BLOCK_SIZE) {
		/*
		 * The next three calls are dummy calls just to avoid
		 * certain timing attacks. Without these dummy calls,
		 * adversaries would be able to learn whether the key_size is
		 * greater than TC_SHA256_BLOCK_SIZE by measuring the time
		 * consumed in this process.
		 */
		(void)tc_sha256_init(&dummy_state.hash_state);
		(void)tc_sha256_update(&dummy_state.hash_state,
				       dummy_key,
				       key_size);
		(void)tc_sha256_final(&dummy_state.key[TC_SHA256_DIGEST_SIZE],
				      &dummy_state.hash_state);

		/* Actual code for when key_size <= TC_SHA256_BLOCK_SIZE: */
		rekey(ctx->key, key, key_size);
	} else {
		(void)tc_sha256_init(&ctx->hash_state);
		(void)tc_sha256_update(&ctx->hash_state, key, key_size);
		(void)tc_sha256_final(&ctx->key[TC_SHA256_DIGEST_SIZE],
				      &ctx->hash_state);
		rekey(ctx->key,
		      &ctx->key[TC_SHA256_DIGEST_SIZE],
		      TC_SHA256_DIGEST_SIZE);
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_init(TCHmacState_t ctx)
{

	/* input sanity check: */
	if (ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

  (void) tc_sha256_init(&ctx->hash_state);
  (void) tc_sha256_update(&ctx->hash_state, ctx->key, TC_SHA256_BLOCK_SIZE);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_update(TCHmacState_t ctx,
		   const void *data,
		   uint32_t data_length)
{

	/* input sanity check: */
	if (ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	(void)tc_sha256_update(&ctx->hash_state, data, data_length);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_final(uint8_t *tag, uint32_t taglen, TCHmacState_t ctx)
{

	/* input sanity check: */
	if (tag == (uint8_t *) 0 ||
	    taglen != TC_SHA256_DIGEST_SIZE ||
	    ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	(void) tc_sha256_final(tag, &ctx->hash_state);

	(void)tc_sha256_init(&ctx->hash_state);
	(void)tc_sha256_update(&ctx->hash_state,
			       &ctx->key[TC_SHA256_BLOCK_SIZE],
				TC_SHA256_BLOCK_SIZE);
	(void)tc_sha256_update(&ctx->hash_state, tag, TC_SHA256_DIGEST_SIZE);
	(void)tc_sha256_final(tag, &ctx->hash_state);

	/* destroy the current state */
	_set(ctx, 0, sizeof(*ctx));

	return TC_CRYPTO_SUCCESS;
}
