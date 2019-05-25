#include <stdio.h>
#include <stdlib.h>

uint8_t
get_mask_for(int nb_of_bits) {
	uint8_t mask;
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
//uint8_t
//get_bits_between(int start_index, int end_index, const uint8_t *data) {
//
//	int start_block = start_index / 8;
//	int end_block = (end_index - 1) / 8;
//	int nb_of_bits = end_index - start_index;
//	char mask1;
//	char mask2;
//
//	if (start_block == end_block) {
//		mask1 = get_mask_for(nb_of_bits);
//		return (data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1;
//	} else {
//		int start_block_relative_index = start_index % 8;
//		mask1 = get_mask_for(8 - start_block_relative_index);
//
//		int end_block_relative_index = end_index % 8;
//		mask2 = get_mask_for(end_block_relative_index);
//
//		int nb_of_bits_in_next_block = end_block_relative_index;
//
//		return ((data[start_block] & mask1) << nb_of_bits_in_next_block |
//				((data[end_block]>>(8-end_block_relative_index)) & mask2));
//	}
//}

uint8_t
get_bit(int index, const uint8_t *data) {
	return !!(data[((index) / 8)] & (  1 << (7 - ((index) % 8) )));
}

uint8_t
get_3_bits_from(int index, const uint8_t *data) {
	uint8_t relative_index = index % 8;
	if ((relative_index) < 6) {
		return ((data[index / 8]>>(8-(relative_index + 3)) & 0x07));
	} else {
		uint8_t start_block = index / 8;
		uint8_t nb_of_bits_in_next_block = (relative_index)-5;
		if (nb_of_bits_in_next_block == 1) {
			return ((((data[(start_block)]  & 0x03) << nb_of_bits_in_next_block)) |
				((data[start_block+1] >> (8-nb_of_bits_in_next_block))));
		} else {
			return ((((data[(start_block)] & 0x01) << nb_of_bits_in_next_block)) |
				((data[start_block+1] >> (8-nb_of_bits_in_next_block))));
		}

	}
}

uint8_t
get_2_bits_from(int index, const uint8_t *data) {
	uint8_t relative_index = index % 8;
	if ((relative_index) < 7) {
		return ((data[index / 8]>>(8-(relative_index + 2)) & 0x03));
	} else {
		uint8_t start_block = index / 8;
		uint8_t nb_of_bits_in_next_block = (relative_index)-5;
		return ((((data[(start_block)]  & 0x01) << 1)) |
			((data[start_block+1] >> (7))));

	}
}

uint8_t
get_char_from(int index, const uint8_t *data) {
	if ((index % 8) == 0) {
		return data[index / 8];
	} else {
		uint8_t start_block = index / 8;
		uint8_t nb_of_bits_in_next_block = index % 8;
		return ((data[(start_block)] << nb_of_bits_in_next_block) |
				((data[start_block+1]>>(8-nb_of_bits_in_next_block))));
	}
}

//Get k bits from int number
//return (((1 << k) - 1) & (number >> (p - 1)));

uint8_t
get_char_from_with_mask(int index, const uint8_t *data) {
	if ((index % 8) == 0) {
		return data[index / 8];
	} else {
		uint8_t start_block = index / 8;
		uint8_t nb_of_bits_in_next_block = index % 8;
		return ((data[(start_block)] & get_mask_for(8 - nb_of_bits_in_next_block)) << nb_of_bits_in_next_block |
				((data[start_block+1]>>(8-nb_of_bits_in_next_block)) & get_mask_for(nb_of_bits_in_next_block)));
	}
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
