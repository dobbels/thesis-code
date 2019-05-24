#include <stdio.h>
#include <stdlib.h>

#include "encoded-policy.h"

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

//#define SET_BIT_BUFFER(bb, index)   bb[((index) / 8)] |= (  1 << ( 7 - ((index) % 8) ))
//#define CLEAR_BIT_BUFFER(bb, index) bb[((index) / 8)] &= (~(1 << ( 7 - ((index) % 8) )))
//#define ASSIGN_BIT_BUFFER(bb, index, v) { if (v) { SET_BIT_BUFFER((bb), index); } else { CLEAR_BIT_BUFFER((bb), index); } }

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
		printf("attr->int_value : %d\n", int_value);
	} else if (type == 3) {
		// type : FLOAT
		printf("Warning: Float not supported by policy\n");
		bit_index += 32;
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
