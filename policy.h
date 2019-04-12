#ifndef POLICY_H_INCLUDED
#define POLICY_H_INCLUDED

struct attribute {
	uint8_t type : 3;
	uint8_t bool_value : 1;
	uint8_t local_reference_value : 3;
	uint8_t string_length : 3; // max number of characters is 6
	char *string_value;
	int16_t int_value; //Comes from java => 4 bytes
	float float_value;
	uint8_t char_value;
};

struct expression {
	uint8_t function;
	uint8_t input_existence : 1; // if == 0, then no attributes where given
	uint8_t max_input_index : 3;
	struct attribute *inputset;
};

struct task {
	uint8_t function;
	uint8_t input_existence : 1;
	uint8_t max_input_index : 3;
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
	uint8_t max_condition_index : 3;
	struct expression *conditionset;
	uint8_t obligationset_mask : 1;
	uint8_t max_obligation_index : 3;
	struct obligation *obligationset;
};

struct policy {
	uint8_t id;
	uint8_t effect : 1;
	uint8_t rule_existence : 1;
	uint8_t max_rule_index : 3; // Necessary to be able to iterate over all rules
								// For current codification, 8 is the max number of rules in a policy, therefore 7 is the max max_rule_index
	struct rule *rules;
};

struct old_associated_subjects {
	uint8_t nb_of_associated_subjects;
	struct old_associated_subject *subject_association_set;
};

struct old_associated_subject {
	uint8_t id;
	uint8_t hid_cm_ind_success :1;
	uint8_t hid_s_r_req_succes :1;
	struct policy policy;
};

//To calculate size of a policy - both assumed to be initialized to zero
unsigned int policy_size_in_bytes;
unsigned char testing_local_policy_size;

void measure_policy_size(const uint8_t *data);

void unpack_policy(const uint8_t *data, int bit_index, struct policy *dest_policy);

int unpack_rule(const uint8_t *data, int bit_index, struct rule *rule);

int unpack_expression(const uint8_t *data, int bit_index, struct expression *exp);

int unpack_obligation(const uint8_t *data, int bit_index, struct obligation *obl);

int unpack_task(const uint8_t *data, int bit_index, struct task *task);

int unpack_attribute(const uint8_t *data, int bit_index, struct attribute *attr);

#endif /* POLICY_H_INCLUDED */
