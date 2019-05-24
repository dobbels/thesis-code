#include <stdio.h>
#include <stdlib.h>

uint8_t
get_mask_for(int nb_of_bits) {
	char mask = 0;
	if (nb_of_bits == 1) {
		/* 0b00000001 */
		mask = 0x01;
	} else if (nb_of_bits == 2) {
		/* 0b00000011 */
		mask = 0x03;
	} else if (nb_of_bits == 3) {
		/* 0b00000111 */
		mask = 0x07;
	} else if (nb_of_bits == 4) {
		/* 0b00001111 */
		mask = 0x0f;
	} else if (nb_of_bits == 5) {
		/* 0b00011111 */
		mask = 0x1f;
	} else if (nb_of_bits == 6) {
		/* 0b00111111 */
		mask = 0x3f;
	} else if (nb_of_bits == 7) {
		/* 0b01111111 */
		mask = 0x7f;
	} else if (nb_of_bits == 8) {
		/* 0b11111111 */
		mask = 0xff;
	}
	return mask;
}

/*
 * The indices are bit indices in a byte array
 * Preconditions:
 * 	0 < end_index - start_index <= 8
 * 	indices are not out of bounds
 */
uint8_t
get_bits_between(int start_index, int end_index, const uint8_t *data) {

	int start_block = start_index / 8;
	int end_block = (end_index - 1) / 8;
	int nb_of_bits = end_index - start_index;
	char mask1;
	char mask2;

	if (start_block == end_block) {
		mask1 = get_mask_for(nb_of_bits);
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

uint8_t
get_bit(int index, const uint8_t *data) {
//	return !!(data[((index) / 8)] & (  1 << (7 - ((index) % 8) )));
	return get_bits_between(index, index+1, data);
}

uint8_t
get_3_bits_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+3, data);
}

uint8_t
get_char_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+8, data);
}

int16_t
get_int16_from(int index, const uint8_t *data) {
	int16_t result = ((((int16_t)get_char_from(index, data)) & 0xff) << 8 |
			(get_char_from(index+8, data) & 0xff));
	printf("%d\n", result);
	return result;
}

void
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
