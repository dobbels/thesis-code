#include "contiki.h"

struct policy {
	unsigned char id;
	unsigned char effect : 1;
	struct rule *rules;
} policy;

struct rule { //TODO alleen in header declareren? Of daar herhalen?
	unsigned char id;
	unsigned char effect : 1;
	unsigned char periodicity_mask : 1;
	unsigned char periodicity;
	unsigned char iteration_mask : 1;
	unsigned char iteration;
	unsigned char resource_mask : 1;
	unsigned char resource;
	unsigned char action_mask : 1;
	unsigned char action : 3;
	struct expression *conditionset;// TODO is aantal altijd af te leiden / te berekenen of best een variabele toevoegen?
	unsigned char obligationset_mask : 1;
	struct obligation *obligationset;
};

struct expression {
	unsigned char function;
	struct attribute *inputset; // if == NULL, then no attributes where given
};

struct obligation {
	struct task task;
	unsigned char fulfill_on : 2; // a value of 0 : on deny, 1 : on permit, 2 : 'always execute', 3 : undefined
};

struct task {
	unsigned char function;
	struct attribute *inputset; // if == NULL, then no attributes where given
};

struct attribute {
	unsigned char type : 3;
	unsigned char bool_value : 1;
	char *string_value;
	int int_value;
	float float_value;
	unsigned char char_value;
};

//TODO To include:
// System attribute reference table (max nb: 256)
// Request attribute reference table (max nb: 256)
// Local attribute reference table (max nb: 8)
// Expression functions table (max nb: 256)
// Task functions table (max nb: 256)
// Target resource table (max nb: 256)

static void
unpack_policy(const uint8_t *data, uint16_t datalen)
{
	int starting_index_next_structure = 0;
	// Unpack policy id and effect and check rule existence mask
	policy.id = data[0];
	policy.effect = get_bit(8, data); // to access the first bit
	if (get_bit(9, data)) { // TODO more efficiency? -> write (data[1] & 0x40) here
		unsigned char nb_of_rules = get_3_bits_from(10, data) + 1;
		char current_rule_index = 0;
		starting_index_next_structure = 13;
		while(nb_of_rules) {
			//TODO ? check every time if datalen*8 is still >= starting_index_next_structure

			// decodify rule and set starting_index_next_structure for the next rule
			starting_index_next_structure = unpack_rule(data, starting_index_next_structure, current_rule_index);

			nb_of_rules--;
			current_rule_index++;
		}
	} else {
		printf("There are no rules\n");
		policy.rules = NULL;
	}

	printf("%d\n", policy.id);
	printf("%d\n", policy.effect);
	print_bits(policy.effect);
}
/*---------------------------------------------------------------------------*/
static void
unpack_rule(const uint8_t *data, int bit_index, char rule_index)
{
	policy.rules[rule_index].id = get_char_from(bit_index, data);
	bit_index += 8;

	policy.rules[rule_index].effect = get_bit(bit_index, data);
	bit_index += 1;

	policy.rules[rule_index].periodicity_mask = get_bit(bit_index, data);
	bit_index += 1;
	policy.rules[rule_index].iteration_mask = get_bit(bit_index, data);
	bit_index += 1;
	policy.rules[rule_index].resource_mask = get_bit(bit_index, data);
	bit_index += 1;
	policy.rules[rule_index].action_mask = get_bit(bit_index, data);
	bit_index += 1;
	policy.rules[rule_index].obligationset_mask = get_bit(bit_index, data);
	bit_index += 1;

	if (policy.rules[rule_index].periodicity_mask) {
		policy.rules[rule_index].periodicity = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (policy.rules[rule_index].iteration_mask) {
		policy.rules[rule_index].iteration = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (policy.rules[rule_index].resource_mask) {
		policy.rules[rule_index].resource = get_char_from(bit_index, data);
		bit_index += 8;
	}

	if (policy.rules[rule_index].action_mask) {
		policy.rules[rule_index].action = get_3_bits_from(bit_index, data);
		bit_index += 3;
	}

	unsigned char nb_of_expressions = get_3_bits_from(10, data) + 1;
	bit_index += 3;
	char current_expression_index = 0;
	while(nb_of_expressions) {

		bit_index = unpack_expression(data, bit_index, current_expression_index);

		nb_of_expressions--;
		current_expression_index++;
	}

	if (policy.rules[rule_index].obligationset_mask) {
		unsigned char nb_of_obligations = get_3_bits_from(10, data) + 1;
		bit_index += 3;
		char current_obligation_index = 0;
		while(nb_of_obligations) {

			bit_index = unpack_obligation(data, bit_index, current_obligation_index);

			nb_of_obligations--;
			current_obligation_index++;
		}
	}
}
/*---------------------------------------------------------------------------*/
static void
unpack_expression(const uint8_t *data, int bit_index, char rule_index)
{
//	unsigned char function;

//	struct attribute *inputset; // if == NULL, then no attributes where given

}
/*---------------------------------------------------------------------------*/
static void
unpack_obligation(const uint8_t *data, int bit_index, char rule_index)
{
//	struct task task;
//	unsigned char fulfill_on : 2; // a value of 0 : on deny, 1 : on permit, 2 : 'always execute', 3 : undefined
}
/*---------------------------------------------------------------------------*/
static void
unpack_task(const uint8_t *data, int bit_index, char rule_index)
{
	// zie expr
}
/*---------------------------------------------------------------------------*/
static void
unpack_attribute(const uint8_t *data, int bit_index)
{
//	unsigned char type : 3;
//	unsigned char bool_value : 1;
//	char *string_value;
//	int int_value;
//	float float_value;
//	unsigned char char_value;
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_mask_for(int nb_of_bits) {
	char mask;
	if (nb_of_bits == 1) {
		mask = 0x01;
	} else if (nb_of_bits == 2) {
		mask = 0x03;
	} else if (nb_of_bits == 3) {
		mask = 0x07;
	} else if (nb_of_bits == 4) {
		mask = 0x0f;
	} else if (nb_of_bits == 5) {
		mask = 0x1f;
	} else if (nb_of_bits == 6) {
		mask = 0x3f;
	} else if (nb_of_bits == 7) {
		mask = 0x7f;
	} else if (nb_of_bits == 8) {
		mask = 0xff;
	}
	return mask;
}
/*---------------------------------------------------------------------------*/
/*
 * The indices are bit indices in a byte array
 * Preconditions:
 * 	0 < end_index - start_index <= 8
 * 	indices are not out of bounds
 */
static unsigned char
get_bits_between(int start_index, int end_index, const uint8_t *data) {

	int start_block = start_index / 8;
	int end_block = (end_index - 1) / 8;
	int nb_of_bits = end_index - start_index;
	char mask1;
	char mask2;

	if (start_block == end_block) {
		mask1 = get_mask_for(nb_of_bits);
		return (data[start_block]>>(8-nb_of_bits)) & mask1;
	} else {
		int start_block_relative_index = start_index % 8;
		mask1 = get_mask_for(8 - start_block_relative_index);

		int end_block_relative_index = end_index % 8;
		mask2 = get_mask_for(end_block_relative_index);

		return ((data[start_block] & mask1) |
				((data[end_block]>>(8-end_block_relative_index)) & mask2));
	}
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_bit(int index, const uint8_t *data) {
	return get_bits_between(index, index+1, data);
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_3_bits_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+3, data);
}
/*---------------------------------------------------------------------------*/
static unsigned char
get_char_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+8, data);
}

/*---------------------------------------------------------------------------*/
static void
print_bits(unsigned char data) {
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
