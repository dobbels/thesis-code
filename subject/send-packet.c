#include "contiki.h"
#include "lib/random.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"
#include "cfs/cfs.h"

#include <stdio.h>

#include "../tiny-AES-c/aes.h"

#include "../bit-operations.h"

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define ACS_UDP_PORT 4321
#define RESOURCE_UDP_PORT 1996

//#define ID 3
static uint8_t subject_id = 0;

static uint8_t authentication_requested = 0;
static uint8_t credentials_requested = 0;
static uint8_t resource_access_requested = 0;
static uint8_t security_association_established = 0;

static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_resource;

uip_ipaddr_t resource_addr;
uip_ipaddr_t acs_addr;

uint8_t subject_key[16] =
	{ (uint8_t) 0x7e, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

//TODO should be stored in file?
uint8_t credential_manager_key[16];
uint8_t credential_manager_nonce[8];

//File structure is a concatenation of:
//TicketCM (26 bytes)
int ticketcm_offset = 0;
//Kscm (16 bytes)
int kscm_offset = 26;
//Noncescm (8 bytes)
int noncescm_offset = 42;
//Nonce2 (8 bytes)
int nonce2_offset = 50;
//TicketR (26 bytes)
int ticketr_offset = 58;
//Ksr (16 bytes)
int k_sr_offset = 84;
//Noncesr (8 bytes)
int nonce_sr_offset = 100;
//Subkey (16 bytes)
int subkey_offset = 108;
//Nonce4
int nonce4_offset = 124;

static void full_print_hex(const uint8_t* str, uint8_t length);
static void print_hex(const uint8_t* str, uint8_t len);
static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length);
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed);

PROCESS(hidra_subject,"HidraSubject");
AUTOSTART_PROCESSES(&hidra_subject);

static void
receiver_resource(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	printf("\nData received from: ");
	PRINT6ADDR(sender_addr);
	printf("\nAt port %d from port %d with length %d\n",
		  receiver_port, sender_port, datalen);
	printf("Data Rx: %.*s\n", datalen, data);

	if (datalen > 1) {
		uint8_t s_r_rep[32];
		memcpy(s_r_rep, data, sizeof(s_r_rep));

		const char * filename = "properties";

		printf("Received HID_S_R_REP.\n");
		//Decrypt message
		uint8_t ksr[16];
		int fd_read = cfs_open(filename, CFS_READ);
		if(fd_read!=-1) {
			cfs_seek(fd_read, k_sr_offset, CFS_SEEK_SET);
			cfs_read(fd_read, ksr, sizeof(ksr));
			cfs_close(fd_read);
		} else {
			printf("Error: could not read ksr key from storage\n");
		}
		//TODO mag dit toch zomaar, const data aanpassen?!
		xcrypt_ctr(ksr, s_r_rep, sizeof(s_r_rep));

		//Check NonceSR
		uint8_t nonce[8];
		fd_read = cfs_open(filename, CFS_READ);
		if(fd_read!=-1) {
			cfs_seek(fd_read, nonce_sr_offset, CFS_SEEK_SET);
			cfs_read(fd_read, nonce, sizeof(nonce));
			cfs_close(fd_read);
		} else {
			printf("Error: could not read nonce_sr from storage\n");
		}
		if (memcmp(nonce, s_r_rep, 8) == 0){
			//Check Nonce4
			fd_read = cfs_open(filename, CFS_READ);
			if(fd_read!=-1) {
				cfs_seek(fd_read, nonce4_offset, CFS_SEEK_SET);
				cfs_read(fd_read, nonce, sizeof(nonce));
				cfs_close(fd_read);
			} else {
				printf("Error: could not read nonce4 from storage\n");
			}
			if (memcmp(nonce, s_r_rep + 24, 8) == 0){
				//Check session key
				uint8_t session_key[16];
				fd_read = cfs_open(filename, CFS_READ);
				if(fd_read!=-1) {
					cfs_seek(fd_read, subkey_offset, CFS_SEEK_SET);
					cfs_read(fd_read, session_key, sizeof(session_key));
					cfs_close(fd_read);
				} else {
					printf("Error: could not read session key from storage\n");
				}
				if (memcmp(session_key, s_r_rep + 8, 16) != 0){
					printf("Resource proposed different key\n");
					//Store key

				}
				security_association_established = 1;
				printf("End of Successful Hidra Exchange.\n");
			} else {
				printf("Wrong Nonce4 HID_S_R_REP.\n");
			}
		} else {
			printf("Wrong NonceSR HID_S_R_REP.\n");
		}
	} else {
		if(data[0]){
			printf("Received Acknowledge.\n");
		} else {
			printf("Received Non-Acknowledge.\n");
		}
	}
}

static void
process_ans_rep(const uint8_t *data,
        uint16_t datalen) {
	const char * filename = "properties";
	printf("HID_ANS_REP content:\n");
	static uint8_t ans_rep[62];
	memcpy(ans_rep, data, datalen);
	full_print_hex(ans_rep, sizeof(ans_rep));

	//Store the encrypted TGT for the credential manager
	int fd_write = cfs_open(filename, CFS_WRITE);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, ans_rep + 2, 26);
		cfs_close(fd_write);
		printf("Successfully written ticket (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write ticket to storage.\n");
	}

	printf("Encrypted HID_ANS_REP content (leaving out the first 28 bytes: IDs and TGT):\n");
	uint8_t encrypted_index = 2 + 16 + 2 + 8;
	full_print_hex(ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);

	//Decrypt rest of message
	xcrypt_ctr(subject_key, ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);
	printf("Decrypted HID_ANS_REP content (leaving out the first 28 bytes: IDs and TGT):\n");
	full_print_hex(ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);

	printf("Decrypted HID_ANS_REP, Kscm: \n");
	full_print_hex(ans_rep+encrypted_index, 16);

	//Store Kscm
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, ans_rep + encrypted_index, 16);
		cfs_close(fd_write);
		printf("Successfully written Kscm (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	   printf("Error: could not write Kscm to storage.\n");
	}

	printf("Decrypted HID_ANS_REP, Noncescm: \n");
	full_print_hex(ans_rep+encrypted_index+16, 8);

	//Store Noncescm
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, ans_rep + encrypted_index + 16, 8);
		cfs_close(fd_write);
		printf("Successfully written Noncescm (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	   printf("Error: could not write Noncescm to storage.\n");
	}

	//TODO store nonce1 and IDcm at start of protocol and check them here?
}

static void
construct_cm_req(uint8_t *cm_req) {
	const char * filename = "properties";
	//resource ID (2 bytes)
	cm_req[0] = 0;
	cm_req[1] = 2;
	//Lifetime TR (1 byte)
	cm_req[2] = 3;
	//Nonce2 (8 bytes)
	uint16_t part_of_nonce = random_rand();
	cm_req[3] = (part_of_nonce >> 8);
	cm_req[4] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_req[5] = (part_of_nonce >> 8);
	cm_req[6] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_req[7] = (part_of_nonce >> 8);
	cm_req[8] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	cm_req[9] = (part_of_nonce >> 8);
	cm_req[10] = part_of_nonce & 0xffff;
	printf("Nonce2 \n");
	full_print_hex(cm_req + 3, 8);
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write!=-1) {
	  int n = cfs_write(fd_write, cm_req + 3, 8);
	  cfs_close(fd_write);
	printf("Successfully written Nonce2 (%i bytes) to %s\n", n, filename);
	printf("\n");
	} else {
	  printf("Error: could not write Nonce2 to storage.\n");
	}
	//Ticket granting ticket (26 bytes)
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	  cfs_read(fd_read, cm_req + 11, 26);
	  cfs_close(fd_read);
	} else {
	  printf("Error: could not read ticket from storage.\n");
	}
	//Generate AuthNM and add to byte array
	//IDs
	cm_req[37] = 0;
	cm_req[38] = subject_id;
	//Noncescm + i, with i = 1
	uint8_t i = 1;
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	   cfs_seek(fd_read, noncescm_offset, CFS_SEEK_SET);
	   cfs_read(fd_read, cm_req + 39, 8);
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read noncescm from storage.\n");
	 }
	printf("Decrypted HID_ANS_REP, Noncescm + i: \n");
//	full_print_hex(cm_req + 39, 8);
	uint16_t temp = (cm_req[45]<< 8) | (cm_req[46]);
	temp += i;
	cm_req[45] = (temp >> 8) & 0xff;
	cm_req[46] = temp & 0xff;
	full_print_hex(cm_req + 39, 8);

	//Print unencrypted message for debugging purposes
	printf("Unencrypted CM_REQ message: \n");
	full_print_hex(cm_req, 47);

	uint8_t kscm[16];
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, kscm_offset, CFS_SEEK_SET);
		cfs_read(fd_read, kscm, 16);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read kscm from storage.\n");
	}

	//Encrypt last 10 bytes of message
	xcrypt_ctr(kscm, cm_req + 37, 10);
//	printf("Encrypted CM_REQ message: \n");
//	full_print_hex(cm_req, 47);
//	printf("with Kscm: \n");
//	full_print_hex(kscm, 16);
}

static uint8_t
process_cm_rep(const uint8_t *data,
        uint16_t datalen) {
	const char * filename = "properties";
	printf("HID_CM_REP content:\n");
	static uint8_t cm_rep[62];
	memcpy(cm_rep, data, datalen);
	full_print_hex(cm_rep, sizeof(cm_rep));

	// Check IDs else return 0
	if (cm_rep[1] != subject_id) {
		printf("Error: wrong subject id.\n");
		return 0;
	}

	// Store ticketR
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_rep + 2, 26);
		cfs_close(fd_write);
		printf("Successfully written ticketR (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write ticketR to storage.\n");
	}

	// Get Kscm key from storage
	uint8_t kscm[16];
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, kscm_offset, CFS_SEEK_SET);
		cfs_read(fd_read, kscm, 16);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read kscm from storage.\n");
	}

	// Decrypt last 34 bytes of message with Kscm
	xcrypt_ctr(kscm, cm_rep + 28, 34);

	// Get Nonce2 from storage
	uint8_t nonce2[8];
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, nonce2_offset, CFS_SEEK_SET);
		cfs_read(fd_read, nonce2, 8);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read Nonce2 from storage.\n");
	}

	// Check Nonce2 else return 0
	if (memcmp(cm_rep + 52, nonce2, 8) != 0) {
		printf("Error: not the Nonce2 that I sent in HID_CM_REQ.\n");
		printf("From message\n");
		full_print_hex(cm_rep + 52, 8);
		printf("From storage\n");
		full_print_hex(nonce2, 8);
		return 0;
	}

	// Store Ksr
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_rep + 28, 16);
		cfs_close(fd_write);
		printf("Successfully written Ksr (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write Ksr to storage.\n");
	}

	// Store Noncesr
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, cm_rep + 44, 8);
		cfs_close(fd_write);
		printf("Successfully written nonceSR (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write nonceSR to storage.\n");
	}
	return 1;
}

static void
construct_s_r_req(uint8_t *s_r_req) {
	printf("Constructing HID_S_R_REQ.\n");
	const char * filename = "properties";
	// Put ticketR in message from storage
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, ticketr_offset, CFS_SEEK_SET);
		cfs_read(fd_read, s_r_req, 26);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read ticketR from storage.\n");
	}

	// Put IDs
	s_r_req[26] = 0;
	s_r_req[27] = subject_id;

	// Get nonceSR from storage into message
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, nonce_sr_offset, CFS_SEEK_SET);
		cfs_read(fd_read, s_r_req + 28, 8);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read nonceSR from storage.\n");
	}

	// Generate session key to propose (16 bytes)
	uint8_t start_of_key = 36;
	uint16_t part_of_nonce = random_rand();
	s_r_req[start_of_key] = (part_of_nonce >> 8);
	s_r_req[1 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[2 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[3 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[4 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[5 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[6 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[7 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[8] = (part_of_nonce >> 8);
	s_r_req[9 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[10 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[11 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[12 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[13 + start_of_key] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[14 + start_of_key] = (part_of_nonce >> 8);
	s_r_req[15 + start_of_key] = part_of_nonce & 0xffff;

	// Store session key
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, s_r_req + start_of_key, 16);
		cfs_close(fd_write);
		printf("Successfully written Subkey (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write Subkey to storage.\n");
	}

	// Get encryption key from storage
	uint8_t k_sr[16];
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, k_sr_offset, CFS_SEEK_SET);
		cfs_read(fd_read, k_sr, 16);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read Ksr from storage.\n");
	}

	// Encrypt these 26 bytes (ID + Nonce + Key)
	xcrypt_ctr(k_sr, s_r_req + 26, 26);

	// Generate nonce4
	uint8_t start_of_nonce = 52;
	part_of_nonce = random_rand();
	s_r_req[start_of_nonce] = (part_of_nonce >> 8);
	s_r_req[1 + start_of_nonce] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[2 + start_of_nonce] = (part_of_nonce >> 8);
	s_r_req[3 + start_of_nonce] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[4 + start_of_nonce] = (part_of_nonce >> 8);
	s_r_req[5 + start_of_nonce] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	s_r_req[6 + start_of_nonce] = (part_of_nonce >> 8);
	s_r_req[7 + start_of_nonce] = part_of_nonce & 0xffff;

	// Store nonce4
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, s_r_req + start_of_nonce, 8);
		cfs_close(fd_write);
		printf("Successfully written Nonce4 (%i bytes) to %s\n", n, filename);
		printf("\n");
	} else {
	  printf("Error: could not write Nonce4 to storage.\n");
	}
}

static void
receiver_acs(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	printf("\nData received from: ");
	PRINT6ADDR(sender_addr);
	printf("\nAt port %d from port %d with length %d\n",
		  receiver_port, sender_port, datalen);
	if (authentication_requested) {
		if (!credentials_requested) {
			// Perform phase 2
			if(datalen != 62) {
				printf("Error: different length of HID_ANS_REP packet: %d\n", datalen);
			}
			//Check Subject ID
			if (get_char_from(8, data) == subject_id) {
				//Process message from authentication server
				process_ans_rep(data, datalen);
				//Construct message for credential manager
				static uint8_t response[47];
				construct_cm_req(response);
				//Send message to credential manager
				uint8_t result = simple_udp_sendto(&unicast_connection_acs, response, sizeof(response), &acs_addr);
				if (result == 0) {
					printf("Sent HID_CM_REQ\n");
				} else {
					printf("Error: sending HID_CM_REQ\n");
				}
				credentials_requested = 1;
			} else {
				printf("Error: wrong subject id %d\n", get_char_from(8, data));
			}
		} else {
			//Receive last step in phase 2
			if (process_cm_rep(data, datalen) != 0) {
				//Perform phase 3 exchange with resource
				static uint8_t response[60];
				construct_s_r_req(response);
				//Send message to credential manager
				uint8_t result = simple_udp_sendto(&unicast_connection_resource, response, sizeof(response), &resource_addr);
				if (result == 0) {
					printf("Sent HID_S_R_REQ\n");
				} else {
					printf("Error: sending HID_S_R_REQ\n");
				}
			} else {
				printf("Error while processing HID_CM_REP\n");
			}
		}
	} else {
		printf("Unexpected message from ACS\n");
	}
}

static void
start_hidra_protocol(void) {
	uint8_t ans_request[15];
	// IdS (2 bytes)
	ans_request[0] = 0;
	ans_request[1] = subject_id;
	// IdCM (2 bytes)
	ans_request[2] = 0;
	ans_request[3] = 0;
	// LifetimeTGT (3 bytes)
	ans_request[4] = 1;
	ans_request[5] = 1;
	ans_request[6] = 1;
	//Nonce1 (8 bytes)
	uint16_t part_of_nonce = random_rand();
	ans_request[7] = (part_of_nonce >> 8);
	ans_request[8] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	ans_request[9] = (part_of_nonce >> 8);
	ans_request[10] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	ans_request[11] = (part_of_nonce >> 8);
	ans_request[12] = part_of_nonce & 0xffff;
	part_of_nonce = random_rand();
	ans_request[13] = (part_of_nonce >> 8);
	ans_request[14] = part_of_nonce & 0xffff;
//	printf("Nonce1: \n");
//	full_print_hex(ans_request + 7,8);
	printf("ANS request message: \n");
	full_print_hex(ans_request,15);

	simple_udp_sendto(&unicast_connection_acs, ans_request, sizeof(ans_request), &acs_addr);
	authentication_requested = 1;
}

static void
send_access_request(void) { //TODO encrypted with Subkey and/or rather authenticated with MAC? -> encrypt(message + hash(message)) using subkey
	uint8_t response[8];
	const char *filename = "properties";
	//Content of access request, all full bytes for simplicity
	// = id (1 byte) + action (1 byte) + function:system_reference (1 byte) + input existence (1 bit) ( + inputs) + padding + hash (4 bytes)
	response[0] = subject_id;
	response[1] = 2;
	response[2] = 18;
	response[3] = 0; // Input non-existence bit padded with 7 extra zero-bits
	// input existence boolean: if input exists, first bit is set to 1 and input couples <type,value> follow

	// Calculate 4 byte hash of action + function + rest
	uint32_t hashed;
	hashed = murmur3_32(response + 1, 3, 17);
	response[4] = (hashed >> 24) & 0xff;
	response[5] = (hashed >> 16) & 0xff;
	response[6] = (hashed >> 8)  & 0xff;
	response[7] = hashed & 0xff;

	//Get session key from storage
	uint8_t session_key[16];
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	   cfs_seek(fd_read, subkey_offset, CFS_SEEK_SET);
	   cfs_read(fd_read, session_key, sizeof(session_key));
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read session key from storage\n");
	 }

	// Encrypt all bytes except the first (subject id)
	xcrypt_ctr(session_key, response+1, sizeof(response) - 1);

	//TODO nieuwe hmac/hash van alles, maar subject id niet encrypteren, anders heeft resource geen idee welke sleutel te gebruiken
	simple_udp_sendto(&unicast_connection_resource, response, sizeof(response), &resource_addr);
	resource_access_requested = 1;
}

static void
set_resource_address(void)
{
	uip_ip6addr(&resource_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 0x2);
}

static void
set_acs_address(void)
{
	uip_ip6addr(&acs_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0x1);
}

static uip_ipaddr_t *
set_global_address(void)
{
  static uip_ipaddr_t ipaddr;
  int i;
  uint8_t state;

  uip_ip6addr(&ipaddr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0);
  uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);
  uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

  printf("IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
      printf("\n");
    }
  }
  return &ipaddr;
}

static void
test_file_operations() {
	/* step 1 */
	char message[32];
	char buf[100];

	strcpy(message,"#1.hello world.");
	strcpy(buf,message);
	printf("step 1: %s\n", buf );

	/* End Step 1. We will add more code below this comment later */
	const char * filename = "test-file";
	int n;
	int fd_write = cfs_open(filename, CFS_WRITE);
	if(fd_write != -1) {
	  n = cfs_write(fd_write, message, sizeof(message));
	  cfs_close(fd_write);
	  printf("step 2: successfully written to cfs. wrote %i bytes\n", n);
	} else {
	  printf("Error: could not write to memory in step 2.\n");
	}
	/* step 3 */
	/* reading from cfs */
	strcpy(buf,"empty string");
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	  cfs_read(fd_read, buf, sizeof(message));
	  printf("step 3: %s\n", buf);
	  cfs_close(fd_read);
	} else {
	  printf("Error: could not read from memory in step 3.\n");
	}

	strcpy(message,"#1.hello test.");
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	 if(fd_write != -1) {
	   n = cfs_write(fd_write, message, sizeof(message));
	   cfs_close(fd_write);
	   printf("step 4: successfully appended data to cfs. wrote %i bytes\n",n);
	 } else {
	   printf("Error: could not write to memory in step 4.\n");
	 }
	strcpy(buf,"empty string");
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		//Lukt ook in combinatie met write, schrijven op een bepaalde plaats dus?
	   cfs_seek(fd_read, sizeof(message), CFS_SEEK_SET);
	   cfs_read(fd_read, buf, sizeof(message));
	   printf("step 5: #2 - %s\n", buf);
	   cfs_seek(fd_read, sizeof(message), CFS_SEEK_SET);
	   cfs_seek(fd_read, 8, CFS_SEEK_CUR);
	   cfs_read(fd_read, buf, sizeof(message));
	   printf("step 5: #2 - %s\n", buf);
	   //Dit is om een of andere reden niet mogelijk na cfs_read. Het lukt alleen met een SEEK_SET er net voor
	   cfs_seek(fd_read, 8, CFS_SEEK_CUR);
	   cfs_read(fd_read, buf, sizeof(message));
	   printf("step 5: #2 - %s\n", buf);
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read from memory in step 5.\n");
	 }
	/*        */
	/* step 6 */
	/*        */
	/* remove the file from cfs */
	cfs_remove(filename);
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read == -1) {
	printf("Successfully removed file\n");
	} else {
	printf("Error: could read from memory in step 6.\n");
	}
}

static void
send_ack(struct simple_udp_connection *c,
		const uip_ipaddr_t *sender_addr)
{
//	printf("Sending ACK to \n");

}

PROCESS_THREAD(hidra_subject, ev, data)
{
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);

	//use global address to deduce node-id
	subject_id = set_global_address()->u8[15];
	set_resource_address();
	set_acs_address();

	while(1) {
		PROCESS_WAIT_EVENT();

		if ((ev==sensors_event) && (data == &button_sensor)) {
			printf("Sending ack to resource\n");
			const char response = 1;
			simple_udp_sendto(&unicast_connection_resource, &response, 1, &resource_addr);
		}
	}
	PROCESS_END();
}
