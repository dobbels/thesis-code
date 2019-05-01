#ifndef BYTE_OPERATIONS_H_INCLUDED
#define BYTE_OPERATIONS_H_INCLUDED

uint8_t get_mask_for(int nb_of_bits);

uint8_t get_bits_between(int start_index, int end_index, const uint8_t *data);

uint8_t get_bit(int index, const uint8_t *data);

uint8_t get_3_bits_from(int index, const uint8_t *data);

uint8_t get_char_from(int index, const uint8_t *data);

int16_t get_int16_from(int index, const uint8_t *data);

float get_float_from(int index, const uint8_t *data);

void print_bits(uint8_t data);

#endif /* POLICY_H_INCLUDED */
