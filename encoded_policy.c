#include <stdio.h>
#include <stdlib.h>

#include "policy.h"
#include "encoded_policy.h"

/*
 * Change policy related to subject with general DENY.
 * If no associated subject exists with subject_id, return failure = 0
 */
uint8_t
blacklist_subject(struct associated_subjects *assocs, uint8_t subject_id)
{
	uint8_t result = 0;

	int subject_index = 0;
	for (; subject_index < assocs->nb_of_associated_subjects ; subject_index++) {
		printf("assocs->subject_association_set[subject_index]->id: %d\n", assocs->subject_association_set[subject_index]->id);
		if(assocs->subject_association_set[subject_index]->id == subject_id) {
			uint8_t policy_id = get_char_from(0, assocs->subject_association_set[subject_index]->policy);

			free(assocs->subject_association_set[subject_index]->policy);

			assocs->subject_association_set[subject_index]->policy = malloc(2 * sizeof(uint8_t));
			// Same policy id
			assocs->subject_association_set[subject_index]->policy[0] = policy_id;
			// Deny everything, no extra rules.
			assocs->subject_association_set[subject_index]->policy[1] = 0;
			assocs->subject_association_set[subject_index]->policy_size = 2;

			result = 1;
			// print policy, for debugging
			printf("After blacklist: \n");
			print_policy(assocs->subject_association_set[subject_index]->policy, 0);
		}
	}
	return result;
}

void
copy_policy(const uint8_t *data, int bit_index, uint8_t policy_size, uint8_t *destination)
{
	int index = 0;
	for (; index < policy_size; index++, bit_index += 8) {
		destination[index] = get_char_from(bit_index, data);
	}
}

uint8_t
policy_has_at_least_one_rule(uint8_t *policy) {
	//#bits(id) + #bits(effect) = 9
	return (get_bit(9, policy));
}

uint8_t
get_policy_effect(uint8_t *policy) {
	//#bits(id) = 8
	return (get_bit(8, policy));
}

uint8_t
rule_get_effect(uint8_t *policy, int bit_index) {
	//#bits(id) = 8
	return (get_bit(bit_index+8, policy));
}

uint8_t
rule_has_action(uint8_t *policy, int bit_index) {
	//#bits(id) +
	//#bits(effect) +
	//#bits(3 masks) +
	//= 12
	return (get_bit(bit_index+12, policy));
}

uint8_t
rule_has_at_least_one_obligation(uint8_t *policy, int bit_index) {
	//#bits(id) +
	//#bits(effect) +
	//#bits(4 masks) +
	//= 13
	return (get_bit(bit_index+13, policy));
}

//Precondition: this rule contains an action
uint8_t
rule_get_action(uint8_t *policy, int bit_index) {
	//#bits(id) +
	//#bits(effect)
	//= 9
	bit_index += 9;
	int copy = bit_index;

	//#bits(5 masks)
	bit_index += 5;

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy, policy)) {
		bit_index += 8;
	}
	return (get_3_bits_from(bit_index, policy));
}

uint8_t
obligation_has_fulfill_on(uint8_t *policy, int bit_index) {
	//Skip past task
	bit_index = task_increase_index(policy, bit_index);
	return (get_bit(bit_index, policy));
}

//Precondition: obligation has fulfill_on
uint8_t
obligation_get_fulfill_on(uint8_t *policy, int bit_index) {
	//Skip past task
	bit_index = task_increase_index(policy, bit_index);
	return (get_bit(bit_index+1, policy));
}

int
rule_get_first_exp_index(uint8_t *policy, int bit_index) {
	//#bits(id) +
	//#bits(effect)
	//= 9
	bit_index += 9;
	int copy = bit_index;

	//#bits(5 masks)
	bit_index += 5;

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy, policy)) {
		bit_index += 3;
	}
	//#bits(max_expression_index) = 3
	bit_index += 3;
	return (bit_index);
}

//Precondition: this policy contains at least one obligation
int
rule_get_first_obl_index(uint8_t *policy, int bit_index) {
	//#bits(id) +
	//#bits(effect)
	//= 9
	bit_index += 9;
	int copy = bit_index;

	//#bits(5 masks)
	bit_index += 5;

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy++, policy)) {
		bit_index += 8;
	}

	if (get_bit(copy, policy)) {
		bit_index += 3;
	}

	uint8_t nb_exp = get_3_bits_from(bit_index, policy) + 1;

	//#bits(max_expression_index) = 3
	bit_index += 3;

	//Go through all expressions
	while(nb_exp) {
		bit_index = expression_increase_index(policy, bit_index);
		nb_exp--;
	}

	//#bits(max_obl_index) = 3
	bit_index += 3;

	return (bit_index);
}

int
expression_increase_index(uint8_t *data, int bit_index)
{
	//Function id = 8
	bit_index += 8;


	if(get_bit(bit_index,data)) {
		bit_index += 1;

		uint8_t max_input_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_inputs = max_input_index + 1;

		while(nb_of_inputs) {
			bit_index = attribute_increase_index(data, bit_index);
			nb_of_inputs--;
		}
	} else {
		bit_index += 1;
	}

	return bit_index;

}

int
task_increase_index(const uint8_t *data, int bit_index)
{
	bit_index += 8;

	if(get_bit(bit_index,data)) {
		bit_index += 1;

		uint8_t max_input_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_inputs = max_input_index + 1;

		while(nb_of_inputs) {
			bit_index = attribute_increase_index(data, bit_index);
			nb_of_inputs--;
		}
	} else {
		bit_index += 1;
	}

	return bit_index;
}

int
attribute_increase_index(const uint8_t *data, int bit_index)
{
	uint8_t type = get_3_bits_from(bit_index, data);
	bit_index += 3;

	if (type == 0) {
		// type : BOOLEAN
		bit_index += 1;
	} else if (type == 1) {
		// type : BYTE
		bit_index += 8;
	} else if (type == 2) {
		// type : INTEGER
		bit_index += 16;
	} else if (type == 3) {
		// type : FLOAT
		bit_index += 32;
	} else if (type == 4) {
		// type : STRING
		//all characters in the string
		bit_index += 8*get_3_bits_from(bit_index, data);
		//nb_of_characters (3 bits)
		bit_index += 3;
	} else if (type == 5) {
		// type : REQUEST REFERENCE
		bit_index += 8;
	} else if (type == 6) {
		// type : SYSTEM REFERENCE
		bit_index += 8;
	} else if (type == 7) {
		// type : LOCAL REFERENCE
		bit_index += 3;
	} else {
		printf("Error while unpacking attribute\n");
	}

	return bit_index;
}

void
print_policy(uint8_t *data, int bit_index)
{
	printf("policy.id : %d\n", get_char_from(bit_index, data));
	bit_index += 8;
	printf("policy.effect : %d\n", get_bit(bit_index, data));
	bit_index += 1;

	if (get_bit(bit_index, data)) {
		bit_index += 1;

		uint8_t nb_of_rules = get_3_bits_from(bit_index, data)+1;
		bit_index += 3;
		printf("nb_of_rules : %d\n", nb_of_rules);

		while(nb_of_rules) {
			bit_index = print_rule(data, bit_index);
			nb_of_rules--;
		}
	} else {
		printf("There are no rules\n");
	}
}

/*---------------------------------------------------------------------------*/
int
print_rule(const uint8_t *data, int bit_index)
{
	printf("\n");
	printf("rule->id : %d\n", get_char_from(bit_index, data));
	bit_index += 8;

	printf("rule->effect : %d\n", get_bit(bit_index, data));
	bit_index += 1;

	uint8_t periodicity_mask = get_bit(bit_index, data);
	bit_index += 1;

	uint8_t iteration_mask = get_bit(bit_index, data);
	bit_index += 1;

	uint8_t resource_mask = get_bit(bit_index, data);
	bit_index += 1;

	uint8_t action_mask = get_bit(bit_index, data);
	bit_index += 1;

	uint8_t obligationset_mask = get_bit(bit_index, data);
	bit_index += 1;

	uint8_t periodicity = 0;
	if (periodicity_mask) {
		periodicity = get_char_from(bit_index, data);
		bit_index += 8;
	}

	uint8_t iteration = 0;
	if (iteration_mask) {
		iteration = get_char_from(bit_index, data);
		bit_index += 8;
	}

	uint8_t resource = 0;
	if (resource_mask) {
		resource = get_char_from(bit_index, data);
		bit_index += 8;
	}

	uint8_t action = 0;
	if (action_mask) {
		action = get_3_bits_from(bit_index, data);
		bit_index += 3;
	}

	printf("mask '%d' for rule->periodicity : %d\n", periodicity_mask, periodicity);
	printf("mask '%d' for rule->iteration :  %d\n", iteration_mask, iteration);
	printf("mask '%d' for rule->resource : %d\n", resource_mask, resource);
	printf("mask '%d' for rule->action : %d\n", action_mask, action);
	printf("mask '%d' for rule->obligationset\n", obligationset_mask);


	uint8_t max_condition_index = get_3_bits_from(bit_index, data);
	bit_index += 3;
	uint8_t nb_of_expressions = max_condition_index + 1;
	printf("nb_of_expressions : %d\n", nb_of_expressions);

	while(nb_of_expressions) {
		bit_index = print_expression(data, bit_index);
		nb_of_expressions--;
	}

	if (obligationset_mask) {
		uint8_t max_obligation_index = get_3_bits_from(bit_index, data);
		bit_index += 3;

		uint8_t nb_of_obligations = max_obligation_index + 1;
		printf("nb_of_obligations : %d\n", nb_of_obligations);

		while(nb_of_obligations) {
			bit_index = print_obligation(data, bit_index);
			nb_of_obligations--;
		}
	}

	return bit_index;
}
/*---------------------------------------------------------------------------*/
int
print_expression(const uint8_t *data, int bit_index)
{

	uint8_t function = get_char_from(bit_index, data);
	bit_index += 8;
	printf("\n");
	printf("exp->function : %d\n", function);

	if(get_bit(bit_index,data)) {
		bit_index += 1;

		uint8_t max_input_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_inputs = max_input_index + 1;
		printf("nb_of_inputs : %d\n", nb_of_inputs);

		while(nb_of_inputs) {
			bit_index = print_attribute(data, bit_index);
			nb_of_inputs--;
		}
	} else {
		bit_index += 1;
		printf("There are no inputs\n");
	}

	return bit_index;

}
/*---------------------------------------------------------------------------*/
int
print_obligation(const uint8_t *data, int bit_index)
{
	bit_index = print_task(data, bit_index);

	printf("obl->fulfill_on_existence_mask : %d\n", get_bit(bit_index, data));
	if (get_bit(bit_index, data)) {
		bit_index += 1;
		printf("obl->fulfill_on_existence_mask : %d\n", get_bit(bit_index, data));
		bit_index += 1;
	} else {
		bit_index += 1;
	}
	return bit_index;
}
/*---------------------------------------------------------------------------*/
int
print_task(const uint8_t *data, int bit_index)
{
	uint8_t function = get_char_from(bit_index, data);
	bit_index += 8;
	printf("\n");
	printf("task->function : %d\n", function);

	if(get_bit(bit_index,data)) {
		bit_index += 1;

		uint8_t max_input_index = get_3_bits_from(bit_index, data);
		bit_index += 3;
		uint8_t nb_of_inputs = max_input_index + 1;
		printf("nb_of_inputs : %d\n", nb_of_inputs);

		while(nb_of_inputs) {
			bit_index = print_attribute(data, bit_index);
			nb_of_inputs--;
		}
	} else {
		bit_index += 1;
		printf("There are no inputs\n");
	}

	return bit_index;
}
/*---------------------------------------------------------------------------*/
int
print_attribute(const uint8_t *data, int bit_index)
{
	uint8_t type = get_3_bits_from(bit_index, data);
	bit_index += 3;

	printf("\n");
	printf("attr->type : %d\n", type);

	if (type == 0) {
		// type : BOOLEAN
		uint8_t bool_value = get_bit(bit_index, data);
		bit_index += 1;
		printf("attr->bool_value : %d\n", bool_value);
	} else if (type == 1) {
		// type : BYTE
		uint8_t char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (BYTE) : %d\n", char_value);
	} else if (type == 2) {
		// type : INTEGER
		int int_value = get_int16_from(bit_index, data);
		bit_index += 16;
		// TODO hidra-r.c:450:3: warning: format ‘%d’ expects argument of type ‘int’, but argument 2 has type ‘int32_t’ [-Wformat]
		printf("attr->int_value : %d\n", int_value);
	} else if (type == 3) {
		// type : FLOAT
		printf("Warning: Float not yet supported by policy\n");
		float float_value = get_float_from(bit_index, data);
		bit_index += 32;
		// TODO hidra-r.c:456:3: warning: format ‘%f’ expects argument of type ‘double’, but argument 2 has type ‘float’ [-Wformat]
//		printf("attr->float_value : %f\n", attr->float_value);
	} else if (type == 4) {
		// type : STRING
		int nb_of_characters = get_3_bits_from(bit_index, data);
		bit_index += 3;
		printf("nb_of_characters : %d\n", nb_of_characters);

		int char_index;
		for (char_index = 0 ; char_index < nb_of_characters ; char_index++) {
			printf("%c", get_char_from(bit_index, data));
			bit_index += 8;
		}
		printf("\n");

	} else if (type == 5) {
		// type : REQUEST REFERENCE
		uint8_t char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (REQUEST) : %d\n", char_value);
	} else if (type == 6) {
		// type : SYSTEM REFERENCE
		uint8_t char_value = get_char_from(bit_index, data);
		bit_index += 8;
		printf("attr->char_value (SYSTEM) : %d\n", char_value);
	} else if (type == 7) {
		// type : LOCAL REFERENCE
		uint8_t local_reference_value = get_3_bits_from(bit_index,data);
		bit_index += 3;
		printf("attr->local_reference_value (LOCAL) : %d\n", local_reference_value);
	} else {
		printf("Error while unpacking attribute\n");
	}

	return bit_index;
}


/*---------------------------------------------------------------------------*/
uint8_t
get_mask_for(int nb_of_bits) {
	char mask = 0;
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
uint8_t
get_bits_between(int start_index, int end_index, const uint8_t *data) {

	int start_block = start_index / 8;
	int end_block = (end_index - 1) / 8;
	int nb_of_bits = end_index - start_index;
	char mask1;
	char mask2;

//	printf("\n");
//	printf("start_index: %d\n",start_index);
//	printf("end_index: %d\n",end_index);
//	printf("start_block: %d\n",start_block);
//	printf("end_block: %d\n",end_block);
//	printf("nb_of_bits: %d\n",nb_of_bits);

	if (start_block == end_block) {
		mask1 = get_mask_for(nb_of_bits);
//		printf("mask1: %d\n",mask1);
//		printf("data[start_block]: %d\n",data[start_block]);
//		printf("(data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1: %d\n",(data[start_block]>>(8-(start_index%8 + nb_of_bits))) & mask1);
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
/*---------------------------------------------------------------------------*/
uint8_t
get_bit(int index, const uint8_t *data) {
	return get_bits_between(index, index+1, data);
}
/*---------------------------------------------------------------------------*/
uint8_t
get_3_bits_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+3, data);
}
/*---------------------------------------------------------------------------*/
uint8_t
get_char_from(int index, const uint8_t *data) {
	return get_bits_between(index, index+8, data);
}
/*---------------------------------------------------------------------------*/
int16_t
get_int16_from(int index, const uint8_t *data) {
	int16_t result = ((((int16_t)get_char_from(index, data)) & 0xff) << 8 |
			(get_char_from(index+8, data) & 0xff));
	printf("%d\n", result);
	return result;
}
/*---------------------------------------------------------------------------*/
float
get_float_from(int index, const uint8_t *data) {
	int32_t result = (((int32_t)get_char_from(index, data)) & 0xff) << 24 |
				((int32_t)get_char_from(index+8, data)  & 0xff) << 16 |
				(get_char_from(index+16, data)  & 0xff) << 8 |
				(get_char_from(index+24, data) & 0xff);
	return *((float*)&result);
}
/*---------------------------------------------------------------------------*/
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
