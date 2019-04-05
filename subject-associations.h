#ifndef SUBJECT_ASSOC_H_INCLUDED
#define SUBJECT_ASSOC_H_INCLUDED


struct associated_subjects {//TODO hoort eigenlijk niet in dit bestand, want is overkoepelend?
	uint8_t nb_of_associated_subjects;
	struct associated_subject *subject_association_set;
};

struct associated_subject {
	uint8_t id;
	struct policy policy;
};



#endif /* SUBJECT_ASSOC_H_INCLUDED */
