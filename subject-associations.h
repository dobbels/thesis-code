#ifndef SUBJECT_ASSOC_H_INCLUDED
#define SUBJECT_ASSOC_H_INCLUDED


struct associated_subjects {//TODO hoort eigenlijk niet in dit bestand, want is overkoepelend?
	uint8_t nb_of_associated_subjects;
	struct associated_subject *subject_association_set;
};

struct associated_subject {
	uint8_t id;
	uint8_t hid_cm_ind_success :1;
	uint8_t hid_s_r_req_succes :1;
	struct policy policy;
};

struct associated_subjects_encoded {//TODO hoort eigenlijk niet in dit bestand, want is overkoepelend?
	uint8_t nb_of_associated_subjects;
	struct associated_subject_encoded *subject_association_set;
};

struct associated_subject_encoded {
	uint8_t id;
	uint8_t hid_cm_ind_success :1;
	uint8_t hid_s_r_req_succes :1;
	uint8_t policy_size; // in bytes
	struct uint8_t *policy;
};

#endif /* SUBJECT_ASSOC_H_INCLUDED */
