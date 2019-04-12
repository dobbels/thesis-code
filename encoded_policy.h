#ifndef ENCODED_POLICY_H_INCLUDED
#define ENCODED_POLICY_H_INCLUDED

struct associated_subjects {
	uint8_t nb_of_associated_subjects;
	struct associated_subject *subject_association_set[10]; //TODO static (temporary) solution, because realloc refuses to work
};

struct associated_subject {
	uint8_t id;
	uint8_t hid_cm_ind_success :1;
	uint8_t hid_cm_ind_req_success :1;
	uint8_t hid_s_r_req_succes :1;
	uint8_t policy_size; // in bytes. Only uint8_t, because datalen in UDP will never exceed 127 bytes, so uint16_t is not necessary
	uint8_t *policy;
};

uint8_t blacklist_subject(struct associated_subjects *assocs, uint8_t subject_id);

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
