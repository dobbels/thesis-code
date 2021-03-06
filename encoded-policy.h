#ifndef ENCODED_POLICY_H_INCLUDED
#define ENCODED_POLICY_H_INCLUDED

struct associated_subjects {
	struct associated_subject *subject_association_set[3];
};

struct associated_subject {
	uint8_t id;
	uint8_t hid_cm_ind_success :1;
	uint8_t hid_cm_ind_req_success :1;
	uint8_t hid_s_r_req_succes :1;
	uint8_t fresh_information : 1;
	uint8_t policy_size; // in bytes. Only uint8_t, because datalen in UDP will never exceed 127 bytes.
	uint8_t policy[40];
	uint8_t nonce_sr[8];
	uint8_t session_key[16];
	uint16_t access_counter;
};

uint8_t blacklist_subject(struct associated_subjects *assocs, uint8_t subject_id);

uint8_t policy_has_at_least_one_rule(uint8_t *policy);

uint8_t get_policy_effect(uint8_t *policy);

uint8_t rule_get_effect(uint8_t *policy, int bit_index);

uint8_t rule_has_action(uint8_t *policy, int bit_index);

uint8_t rule_has_at_least_one_obligation(uint8_t *policy, int bit_index);

uint8_t rule_get_action(uint8_t *policy, int bit_index);

uint8_t obligation_has_fulfill_on(uint8_t *policy, int bit_index);

uint8_t obligation_get_fulfill_on(uint8_t *policy, int bit_index);

int rule_get_first_exp_index(uint8_t *policy, int bit_index);

int rule_get_first_obl_index(uint8_t *policy, int bit_index);

int expression_increase_index(uint8_t *data, int bit_index);

int task_increase_index(const uint8_t *data, int bit_index);

int attribute_increase_index(const uint8_t *data, int bit_index);

void copy_policy(const uint8_t *data, int bit_index, uint8_t policy_size, uint8_t *destination);

void print_policy(uint8_t *policy, int bit_index);

int print_rule(const uint8_t *data, int bit_index);

int print_expression(const uint8_t *data, int bit_index);

int print_obligation(const uint8_t *data, int bit_index);

int print_task(const uint8_t *data, int bit_index);

int print_attribute(const uint8_t *data, int bit_index);

uint8_t get_mask_for(int nb_of_bits);

uint8_t get_bits_between(int start_index, int end_index, const uint8_t *data);

uint8_t get_bit(int index, const uint8_t *data);

uint8_t get_3_bits_from(int index, const uint8_t *data);

uint8_t get_char_from(int index, const uint8_t *data);

int16_t get_int16_from(int index, const uint8_t *data);

float get_float_from(int index, const uint8_t *data);

void print_bits(uint8_t data);

#endif /* POLICY_H_INCLUDED */
