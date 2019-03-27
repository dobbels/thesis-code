#ifndef POLICY_H_INCLUDED
#define POLICY_H_INCLUDED

struct attribute {
	uint8_t type : 3;
	uint8_t bool_value : 1;
	uint8_t local_reference_value : 3;
	char *string_value;
	int32_t int_value; //Comes from java => 4 bytes
	float float_value;
	uint8_t char_value;
};

struct expression {
	uint8_t function;
	struct attribute *inputset; // if == NULL, then no attributes where given
};

struct task {
	uint8_t function;
	struct attribute *inputset; // if == NULL, then no attributes where given
};

struct obligation {
	struct task task;
	uint8_t fulfill_on : 2; // a value of 0 : on deny, 1 : on permit, 2 : 'always execute', 3 : undefined
};

struct rule {
	uint8_t id;
	uint8_t effect : 1;
	uint8_t periodicity_mask : 1;
	uint8_t periodicity;
	uint8_t iteration_mask : 1;
	uint8_t iteration;
	uint8_t resource_mask : 1;
	uint8_t resource;
	uint8_t action_mask : 1;
	uint8_t action : 3;
	struct expression *conditionset;// TODO is aantal altijd af te leiden / te berekenen of best een variabele toevoegen?
	uint8_t obligationset_mask : 1;
	struct obligation *obligationset;
};

struct policy {
	uint8_t id;
	uint8_t effect : 1;
	struct rule *rules;
};

static void unpack_policy(const uint8_t *data, uint16_t datalen);

static int unpack_rule(const uint8_t *data, int bit_index, struct rule *rule);

static int unpack_expression(const uint8_t *data, int bit_index, struct expression *exp);

static int unpack_obligation(const uint8_t *data, int bit_index, struct obligation *obl);

static int unpack_task(const uint8_t *data, int bit_index, struct task *task);

static int unpack_attribute(const uint8_t *data, int bit_index, struct attribute *attr);

static uint8_t get_mask_for(int nb_of_bits);

static uint8_t get_bits_between(int start_index, int end_index, const uint8_t *data);

static uint8_t get_bit(int index, const uint8_t *data);

static uint8_t get_3_bits_from(int index, const uint8_t *data);

static uint8_t get_char_from(int index, const uint8_t *data);

static int32_t get_int_from(int index, const uint8_t *data);

static float get_float_from(int index, const uint8_t *data);

static void print_bits(uint8_t data);

#endif /* POLICY_H_INCLUDED */
