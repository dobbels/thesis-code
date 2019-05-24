#include "contiki.h"
#include "lib/random.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"
#include "cfs/cfs.h"

#include "../../tinycrypt/lib/include/tinycrypt/hmac.h"
#include "../../tinycrypt/lib/include/tinycrypt/sha256.h"
#include "../../tinycrypt/lib/include/tinycrypt/constants.h"
#include "../../tinycrypt/lib/include/tinycrypt/utils.h"

#include <stdio.h>

#include "../../tiny-AES-c/aes.h"

#include "../../bit-operations.h"

#include "rtimer.h"
#include "sys/energest.h"

#define ENERGEST_SECOND RTIMER_ARCH_SECOND

#ifndef ENERGEST_GET_TOTAL_TIME
#ifdef ENERGEST_CONF_GET_TOTAL_TIME
#define ENERGEST_GET_TOTAL_TIME ENERGEST_CONF_GET_TOTAL_TIME
#else /* ENERGEST_CONF_GET_TOTAL_TIME */
#define ENERGEST_GET_TOTAL_TIME energest_get_total_time
#endif /* ENERGEST_CONF_GET_TOTAL_TIME */
#endif /* ENERGEST_GET_TOTAL_TIME */

uint64_t ENERGEST_GET_TOTAL_TIME(void);

uint64_t
energest_get_total_time(void)
{
  return energest_type_time(ENERGEST_TYPE_CPU) +
    energest_type_time(ENERGEST_TYPE_LPM);
}

static inline unsigned long
to_seconds(uint64_t time)
{
  return (unsigned long)(time / ENERGEST_SECOND);
}

void
print_energest_data(void) {
	/*
	 * Update all energest times. Should always be called before energest
	 * times are read.
	 */
	energest_flush();

	printf("\nEnergest subject:\n");
	printf(" CPU          %4lu ticks LPM      %4lu ticks Total ticks %lu \n",
			   energest_type_time(ENERGEST_TYPE_CPU),
			   energest_type_time(ENERGEST_TYPE_LPM),
			   ENERGEST_GET_TOTAL_TIME());
		printf(" Radio LISTEN %4lu ticks TRANSMIT %4lu ticks OFF      %4lu ticks\n",
			   energest_type_time(ENERGEST_TYPE_LISTEN),
			   energest_type_time(ENERGEST_TYPE_TRANSMIT),
			   ENERGEST_GET_TOTAL_TIME()
						  - energest_type_time(ENERGEST_TYPE_TRANSMIT)
						  - energest_type_time(ENERGEST_TYPE_LISTEN));
//	printf(" CPU          %4lus LPM      %4lus Total time %lus\n",
//		   to_seconds(energest_type_time(ENERGEST_TYPE_CPU)),
//		   to_seconds(energest_type_time(ENERGEST_TYPE_LPM)),
//		   to_seconds(ENERGEST_GET_TOTAL_TIME()));
//	printf(" Radio LISTEN %4lus TRANSMIT %4lus OFF      %4lus\n",
//		   to_seconds(energest_type_time(ENERGEST_TYPE_LISTEN)),
//		   to_seconds(energest_type_time(ENERGEST_TYPE_TRANSMIT)),
//		   to_seconds(ENERGEST_GET_TOTAL_TIME()
//					  - energest_type_time(ENERGEST_TYPE_TRANSMIT)
//					  - energest_type_time(ENERGEST_TYPE_LISTEN)));
}

unsigned long initial_timestamp;
unsigned long timestamp;
unsigned long r_timestamp;

// To print the IPv6 addresses in a friendlier way
#include "debug.h"
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define SERVER_UDP_PORT 4321
#define RESOURCE_UDP_PORT 1996

//#define ID 3
static uint8_t subject_id = 0;
static uint8_t pseudonym[2];

static uint8_t authentication_requested = 0;
static uint8_t credentials_requested = 0;
static uint8_t resource_access_requested = 0;
static uint8_t security_association_established = 0;

static struct simple_udp_connection unicast_connection_server;
static struct simple_udp_connection unicast_connection_resource;

uip_ipaddr_t resource_addr;
uip_ipaddr_t server_addr;

static uint8_t subject_key[16] =
	{ (uint8_t) 0x7e, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x16,
		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };

//TODO should be stored in file?
uint8_t credential_manager_key[16];
uint8_t credential_manager_nonce[8];

uint16_t access_counter = 0;

static void
store_access_counter(uint8_t * nonce) {
	access_counter = ((*nonce) << 8) | ((*(nonce+1)));
}

static uint8_t
nonce_equals(uint16_t ctr, uint8_t * nonce) {
	return ((ctr >> 8) == *nonce && (ctr & 0xff) == *(nonce+1));
}

static void
get_access_counter(uint8_t * nonce) {
	*nonce = access_counter >> 8;
	*(nonce+1) = (access_counter & 0xff);
}

static void
get_access_counter_increment(uint8_t * nonce) {
	access_counter++;
	*nonce = access_counter >> 8;
	*(nonce+1) = (access_counter & 0xff);
}

//File structure is a concatenation of:
//Nonce1 (8 bytes)
int nonce1_offset;
//TicketCM (26 bytes)
int ticketcm_offset;
//Kscm (16 bytes)
int kscm_offset;
//Noncescm (8 bytes)
int noncescm_offset;
//Nonce2 (8 bytes)
int nonce2_offset;
//TicketR (26 bytes)
int ticketr_offset;
//Ksr (16 bytes)
int k_sr_offset;
//Noncesr (8 bytes)
int nonce_sr_offset;
//Subkey (16 bytes)
int subkey_offset;
//Nonce4
int nonce4_offset;

static void full_print_hex(const uint8_t* str, uint8_t length);
static void print_hex(const uint8_t* str, uint8_t len);
static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length);
void compute_mac(uint8_t *key, const uint8_t *data, uint8_t datalen, uint8_t * final_digest);
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
	const char * filename = "properties";

	//Check session key
	static uint8_t session_key[16];
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, subkey_offset, CFS_SEEK_SET);
		cfs_read(fd_read, session_key, sizeof(session_key));
		cfs_close(fd_read);
	} else {
		printf("Error: could not read session key from storage\n");
	}

	if (datalen == 32) {
//		printf("s_r_req -> s_r_rep: %4lu ticks\n", clock_time() - timestamp);
//		timestamp = clock_time();
		static uint8_t s_r_rep[32];
		memcpy(s_r_rep, data, sizeof(s_r_rep));

		//printf("Received HID_S_R_REP.\n");
		//Decrypt message
		static uint8_t ksr[16];
		fd_read = cfs_open(filename, CFS_READ);
		if(fd_read!=-1) {
			cfs_seek(fd_read, k_sr_offset, CFS_SEEK_SET);
			cfs_read(fd_read, ksr, sizeof(ksr));
			cfs_close(fd_read);
		} else {
			printf("Error: could not read ksr key from storage\n");
		}

		xcrypt_ctr(ksr, s_r_rep, sizeof(s_r_rep));

		//Check NonceSR
		static uint8_t nonce[8];
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
				if (memcmp(session_key, s_r_rep + 8, 16) != 0){
					printf("Resource proposed different key\n");
					//Store key

				}
				security_association_established = 1;
//				printf("End of Successful Hidra Exchange.\n");
//				unsigned long last_duration = clock_time() - timestamp;
//				unsigned long duration = clock_time() - initial_timestamp;
//				printf("s_r_req reception: %4lu ticks\n", clock_time() - timestamp);
//				printf("It took %4lu ticks to complete the protocol\n", duration);
//				print_energest_data();
//				unsigned long r_duration = RTIMER_NOW() - r_timestamp;
//				printf("That means about %4lu milliseconds \n", duration*7813/1000);
//				printf("That means about %4lu milliseconds \n", (r_duration<<)/RTIMER_ARCH_SECOND);
//				printf("That means about %4lu milliseconds \n", r_duration*145982196/100000000);
			} else {
				printf("Wrong Nonce4 HID_S_R_REP.\n");
			}
		} else {
			printf("Wrong NonceSR HID_S_R_REP.\n");
		}
	} else if (datalen == 3) {
//		printf("access request response: %4lu ticks\n", clock_time() - timestamp);
//		timestamp = clock_time();
		uint8_t access_response[3];
		memcpy(access_response, data, sizeof(access_response));
		xcrypt_ctr(session_key, access_response, sizeof(access_response));
		if (nonce_equals(access_counter+1, access_response + 1)) {
			store_access_counter(access_response + 1);
			//printf("access_response[0]: %d\n", access_response[0]);
//			printf("processed_response: %4lu ticks\n", clock_time() - timestamp);
			if(access_response[0]){
				//printf("Received Acknowledge.\n");
			} else {
				printf("Received Non-Acknowledge.\n");
			}
		} else {
			printf("Not Nonce + i: Message out of sync.\n");
		}
	} else {
		if(data[0]){
			//printf("Received Acknowledge.\n");
		} else {
			printf("Received Non-Acknowledge.\n");
		}
	}
}

static void
process_ans_rep(const uint8_t *data,
        uint16_t datalen) {
	const char * filename = "properties";

	static uint8_t ans_rep[64];
	memcpy(ans_rep, data, datalen);

	//Store the encrypted TGT for the credential manager
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, ans_rep + 2, 26);
		cfs_close(fd_write);
		//printf("Successfully written ticket (%i bytes) to %s\n", n, filename);
		//printf("\n");
	} else {
	  printf("Error: could not write ticket to storage.\n");
	}

	//printf("Encrypted HID_ANS_REP content (leaving out the first 28 bytes: IDs and TGT):\n");
	uint8_t encrypted_index = 2 + 16 + 2 + 8;
	full_print_hex(ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);

	//Decrypt rest of message
	xcrypt_ctr(subject_key, ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);
	//printf("Decrypted HID_ANS_REP content (leaving out the first 28 bytes: IDs and TGT):\n");
	full_print_hex(ans_rep+encrypted_index, sizeof(ans_rep) - encrypted_index);

	static uint8_t nonce1[8];
	int fd_read = cfs_open(filename, CFS_READ);
	if (fd_read != -1) {
		cfs_read(fd_read, nonce1, 8);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read nonce1 from storage.\n");
	}
	if (memcmp(ans_rep + encrypted_index + 24, nonce1, 8) == 0) {

		//printf("Decrypted HID_ANS_REP, Kscm: \n");
		full_print_hex(ans_rep+encrypted_index, 16);

		//Store Kscm
		fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
		if(fd_write != -1) {
			int n = cfs_write(fd_write, ans_rep + encrypted_index, 16);
			cfs_close(fd_write);
			//printf("Successfully written Kscm (%i bytes) to %s\n", n, filename);
			//printf("\n");
		} else {
		   printf("Error: could not write Kscm to storage.\n");
		}

		//printf("Decrypted HID_ANS_REP, Noncescm: \n");
		full_print_hex(ans_rep+encrypted_index+16, 8);

		//Store Noncescm
		fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
		if(fd_write != -1) {
			int n = cfs_write(fd_write, ans_rep + encrypted_index + 16, 8);
			cfs_close(fd_write);
			//printf("Successfully written Noncescm (%i bytes) to %s\n", n, filename);
			//printf("\n");
		} else {
		   printf("Error: could not write Noncescm to storage.\n");
		}

		//Store pseudonym assigned to this subject
		memcpy(pseudonym, ans_rep + encrypted_index + 34, 2);
		//printf("Received pseudonym: \n");
		full_print_hex(pseudonym, 2);

	} else {
		printf("Error: unsecure response, nonce1 does not match.\n");
	}
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
	//printf("Nonce2 \n");
	full_print_hex(cm_req + 3, 8);
	int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	if(fd_write!=-1) {
	  int n = cfs_write(fd_write, cm_req + 3, 8);
	  cfs_close(fd_write);
	//printf("Successfully written Nonce2 (%i bytes) to %s\n", n, filename);
	//printf("\n");
	} else {
	  printf("Error: could not write Nonce2 to storage.\n");
	}
	//Ticket granting ticket (26 bytes)
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, ticketcm_offset, CFS_SEEK_SET);
		cfs_read(fd_read, cm_req + 11, 26);
	  cfs_close(fd_read);
	} else {
	  printf("Error: could not read ticket from storage.\n");
	}
	//Generate AuthNM and add to byte array
	//Pseudonym (2 bytes)
	memcpy(cm_req + 37, pseudonym, 2);
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
	uint16_t temp = (cm_req[45]<< 8) | (cm_req[46]);
	temp += i;
	cm_req[45] = (temp >> 8) & 0xff;
	cm_req[46] = temp & 0xff;
	full_print_hex(cm_req + 39, 8);

	//Print unencrypted message for debugging purposes
	//printf("Unencrypted CM_REQ message: \n");
	full_print_hex(cm_req, 47);

	static uint8_t kscm[16];
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
}

static uint8_t
process_cm_rep(const uint8_t *data,
        uint16_t datalen) {
	const char * filename = "properties";
	//printf("HID_CM_REP content:\n");
	static uint8_t cm_rep[62];
	memcpy(cm_rep, data, datalen);
	full_print_hex(cm_rep, sizeof(cm_rep));

	//If valid id (=pseudonym)
	if (memcmp(pseudonym, cm_rep, 2) == 0) {
		//printf("ticketR: \n");
		full_print_hex(cm_rep + 2, 26);

		//printf("ticketR, bit 8: \n");
		full_print_hex(cm_rep + 10, 1);

		// Store ticketR
		int fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
		if(fd_write != -1) {
			int n = cfs_write(fd_write, cm_rep + 2, 26);
			cfs_close(fd_write);
			//printf("Successfully written ticketR (%i bytes) to %s\n", n, filename);
			//printf("\n");
		} else {
		  printf("Error: could not write ticketR to storage.\n");
		}

		// Get Kscm key from storage
		static uint8_t kscm[16];
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
		static uint8_t nonce2[8];
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
		} else {
			//printf("Correct decryption of Nonce2 in HID_CM_REP.\n");
			//printf("\n");
		}

		//printf("Ksr: \n");
		full_print_hex(cm_rep + 28, 16);

		// Store Ksr
		fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
		if(fd_write != -1) {
			int n = cfs_write(fd_write, cm_rep + 28, 16);
			cfs_close(fd_write);
			//printf("Successfully written Ksr (%i bytes) to %s\n", n, filename);
			//printf("\n");
		} else {
		  printf("Error: could not write Ksr to storage.\n");
		}

		//printf("nonceSR: \n");
		full_print_hex(cm_rep + 44, 8);

		// Store Noncesr
		fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
		if(fd_write != -1) {
			int n = cfs_write(fd_write, cm_rep + 44, 8);
			cfs_close(fd_write);
			//printf("Successfully written nonceSR (%i bytes) to %s\n", n, filename);
			//printf("\n");
		} else {
		  printf("Error: could not write nonceSR to storage.\n");
		}
	}
	return 1;
}

static void
construct_s_r_req(uint8_t *s_r_req) {
	//printf("Constructing HID_S_R_REQ.\n");
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

	// Put Pseudonym
	memcpy(s_r_req + 26, pseudonym, 2);

	// Get nonceSR from storage into message
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
		cfs_seek(fd_read, nonce_sr_offset, CFS_SEEK_SET);
		cfs_read(fd_read, s_r_req + 28, 8);
		cfs_close(fd_read);
	} else {
		printf("Error: could not read nonceSR from storage.\n");
	}

	//printf("NonceSR: \n");
	full_print_hex(s_r_req + 28, 8);

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
	s_r_req[8 + start_of_key] = (part_of_nonce >> 8);
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
		//printf("Successfully written Subkey (%i bytes) to %s\n", n, filename);
		//printf("\n");
	} else {
	  printf("Error: could not write Subkey to storage.\n");
	}

	// Get encryption key from storage
	static uint8_t k_sr[16];
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
		//printf("Successfully written Nonce4 (%i bytes) to %s\n", n, filename);
		//printf("\n");
	} else {
	  printf("Error: could not write Nonce4 to storage.\n");
	}

	//So that in every new session, the counter is set to zero
	access_counter = 0;
}

static void
receiver_server(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
	if (authentication_requested) {
		if (!credentials_requested) {
//			printf("ans_ -> ans_rep: %4lu ticks\n", clock_time() - timestamp);
//			timestamp = clock_time();
			// Perform phase 2
			if(datalen != 64) {
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
				simple_udp_sendto(&unicast_connection_server, response, sizeof(response), &server_addr);
				//printf("Sent HID_CM_REQ\n");
				credentials_requested = 1;
//				printf("ans_rep -> cm_req: %4lu ticks\n", clock_time() - timestamp);
//				timestamp = clock_time();
			} else {
				printf("Error: wrong subject id %d\n", get_char_from(8, data));
			}
		} else {
//			printf("cm_req -> cm_rep: %4lu ticks\n", clock_time() - timestamp);
//			timestamp = clock_time();
			//Receive last step in phase 2
			if (process_cm_rep(data, datalen) != 0) {
				//Perform phase 3 exchange with resource
				static uint8_t response[60];
				construct_s_r_req(response);
				//Send message to credential manager
				simple_udp_sendto(&unicast_connection_resource, response, sizeof(response), &resource_addr);
				//printf("Sent HID_S_R_REQ\n");
//				printf("cm_rep -> s_r_req: %4lu ticks\n", clock_time() - timestamp);
//				timestamp = clock_time();
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

//	print_energest_data();

//	timestamp = clock_time();

//	initial_timestamp = clock_time();

	static uint8_t ans_request[15];
	const char *filename = "properties";

//	r_timestamp = RTIMER_NOW();

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

	//Store generated nonce
	int fd_write = cfs_open(filename, CFS_WRITE);
	if(fd_write != -1) {
		int n = cfs_write(fd_write, ans_request + 7, 8);
		cfs_close(fd_write);
		//printf("Successfully written nonce1 (%i bytes) to %s\n", n, filename);
		//printf("\n");
	} else {
	  printf("Error: could not write nonce1 to storage.\n");
	}

	//printf("Nonce1: \n");
//	full_print_hex(ans_request + 7,8);
	//printf("ANS request message: \n");
	full_print_hex(ans_request,15);

	simple_udp_sendto(&unicast_connection_server, ans_request, sizeof(ans_request), &server_addr);
	authentication_requested = 1;

//	printf("hid_req: %4lu ticks\n", clock_time() - timestamp);
//	timestamp = clock_time();
}

static void
send_access_request(void) {
//	timestamp = clock_time();

	uint8_t message_length = 7;
	uint8_t response[message_length + 4];
	const char *filename = "properties";
	//Content of access request, all full bytes for simplicity
	// = id (1 byte) + action (1 byte) + function:system_reference (1 byte) + input existence (1 bit) ( + inputs) + padding + hash (4 bytes)
	memcpy(response, pseudonym, 2);
	uint8_t action = 2;
	uint8_t function = 18;
	uint8_t input_existence = 0;
	response[2] = (action << 6) | (function >> 2);
	//printf("response[2] %d should be 132 \n", response[2]);
	response[3] = (function << 6) | (input_existence >> 2); // with 5 padding zero-bits
	//printf("response[3] %d should be 128 \n", response[3]);

	// input existence boolean: if input exists, the bit is set to 1 and input couples <type,value> follow

	//Put incremented access counter in message
	get_access_counter_increment(response + 4);

	//Get session key from storage
	static uint8_t session_key[16];
	int fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
	   cfs_seek(fd_read, subkey_offset, CFS_SEEK_SET);
	   cfs_read(fd_read, session_key, sizeof(session_key));
	   cfs_close(fd_read);
	 } else {
	   printf("Error: could not read session key from storage\n");
	 }

	// Calculate 4 byte mac of action + function + rest
	compute_mac(session_key, response, message_length, response + message_length);

	// Encrypt-and-MAC (E&M)
	// Encrypt all bytes except the first 2 (pseudonym) and the last 4 (MAC)
	xcrypt_ctr(session_key, response + 2, sizeof(response) - 6);


	//TODO nieuwe hmac/hash van alles, maar subject id niet encrypteren, anders heeft resource geen idee welke sleutel te gebruiken
	simple_udp_sendto(&unicast_connection_resource, response, sizeof(response), &resource_addr);
	resource_access_requested = 1;

//	printf("construct access_request: %4lu ticks\n", clock_time() - timestamp);
//	timestamp = clock_time();
}

static void
set_resource_address(void)
{
	uip_ip6addr(&resource_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0xc30c, 0, 0, 0x2);
}

static void
set_server_address(void)
{
	uip_ip6addr(&server_addr, UIP_DS6_DEFAULT_PREFIX, 0, 0, 0, 0, 0, 0, 0x1);
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

PROCESS_THREAD(hidra_subject, ev, data)
{
	static struct etimer periodic_timer;

	PROCESS_BEGIN();

//	print_energest_data();

	SENSORS_ACTIVATE(button_sensor);

	clock_init();

//	static int i = 4;
//	etimer_set(&periodic_timer, CLOCK_SECOND * 2);
//	while(i--) {
//		print_energest_data();
//		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
//		etimer_reset(&periodic_timer);
//	}
//	random_init();

	//use global address to deduce node-id
	subject_id = set_global_address()->u8[15];
	//use subject id to customize key
	subject_key[15] = subject_id;

	set_resource_address();
	set_server_address();

//	test_file_operations();

	simple_udp_register(&unicast_connection_server, SERVER_UDP_PORT,
						  NULL, SERVER_UDP_PORT,
						  receiver_server);

	simple_udp_register(&unicast_connection_resource, RESOURCE_UDP_PORT,
						  NULL, RESOURCE_UDP_PORT,
						  receiver_resource);

	//File structure is a concatenation of:
	//Nonce1 (8 bytes)
	nonce1_offset = 0;
	//TicketCM (26 bytes)
	ticketcm_offset = nonce1_offset + 8;
	//Kscm (16 bytes)
	kscm_offset = ticketcm_offset + 26;
	//Noncescm (8 bytes)
	noncescm_offset = kscm_offset + 16;
	//Nonce2 (8 bytes)
	nonce2_offset = noncescm_offset + 8;
	//TicketR (26 bytes)
	ticketr_offset = nonce2_offset + 8;
	//Ksr (16 bytes)
	k_sr_offset = ticketr_offset + 26;
	//Noncesr (8 bytes)
	nonce_sr_offset = k_sr_offset + 16;
	//Subkey (16 bytes)
	subkey_offset = nonce_sr_offset + 8;
	//Nonce4
	nonce4_offset = subkey_offset + 16;


	uint8_t testing = 0;
	while(1) {
		PROCESS_WAIT_EVENT();
//		if (etimer_expired(&periodic_timer)) {
//			clock_time_t clock_time(); // Get the system time.
//			unsigned long clock_seconds(); // Get the system time in seconds.
//			void clock_delay(unsigned int delay); // Delay the CPU.
//			void clock_wait(int delay); // Delay the CPU for a number of clock ticks.
//			void clock_init(void); // Initialize the clock module.
//			CLOCK_SECOND; // The number of ticks per second.
//			printf("clock_time(), i.e. ticks: %4lu\n", clock_time());//return unsigned long
//			printf("clock_seconds: %4lus\n", clock_seconds());

//			clock_set_seconds(unsigned long sec) //TODO test dit + print clock_seconds hierna

//			printf("RTIMER_ARCH_SECOND: %4lu ticks\n", RTIMER_ARCH_SECOND);
//			printf("CLOCK_SECOND: %4lu ticks\n", CLOCK_SECOND);
//			etimer_reset(&periodic_timer);
//		}

		if ((ev==sensors_event) && (data == &button_sensor)) {
			if (testing) {
//				printf("clock_time(), i.e. ticks: %4lu\n", clock_time());//return unsigned long
//				printf("clock_seconds: %4lus\n", clock_seconds());
//				printf("RTIMER_ARCH_SECOND: %4lu ticks\n", RTIMER_ARCH_SECOND);
//				printf("RTIMER_SECOND: %4lu ticks\n", RTIMER_SECOND);
//				printf("CLOCK_SECOND: %4lu ticks\n", CLOCK_SECOND);
			}

			else if (!security_association_established) {
				printf("Starting Hidra Protocol\n");
				start_hidra_protocol();
			} else {
				send_access_request();
			}
		}
	}
	PROCESS_END();
}

//Expects a digest of 4 bytes
void compute_mac(uint8_t *key, const uint8_t *data, uint8_t datalen, uint8_t * final_digest) {
	static struct tc_hmac_state_struct h;

	(void)memset(&h, 0x00, sizeof(h));
	(void)tc_hmac_set_key(&h, key, 16);

	static uint8_t digest[32];

	(void)tc_hmac_init(&h);
	(void)tc_hmac_update(&h, data, datalen);
	(void)tc_hmac_final(digest, TC_SHA256_DIGEST_SIZE, &h);

	uint32_t hashed = murmur3_32(digest, 32, 17);

	final_digest[0] = (hashed >> 24) & 0xff;
	final_digest[1] = (hashed >> 16) & 0xff;
	final_digest[2] = (hashed >> 8)  & 0xff;
	final_digest[3] = hashed & 0xff;
}

static void xcrypt_ctr(uint8_t *key, uint8_t *in, uint32_t length)
{
	uint8_t iv[16]  = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
	static struct AES_ctx ctx;

	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, in, length);
}

static void full_print_hex(const uint8_t* str, uint8_t length) {
//	int i = 0;
//	for (; i < (length/16) ; i++) {
//		print_hex(str + i * 16, 16);
//	}
//	print_hex(str + i * 16, length%16);
//	printf("\n");
}

// prints string as hex
static void print_hex(const uint8_t* str, uint8_t len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}


//////////////////////////////////////////
//CODE FROM tiny AES PROJECT
/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97
    f5d3d58503b9699de785895a96fdbaaf
    43b1cd7f598ece23881b00e3ed030688
    7b0c785e27e8ad3f8223207104725dd4


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/
/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.

// jcallan@github points out that declaring Multiply as a function
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];



// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM -
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),TODO
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 *
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed),
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  {
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = 1; round < Nr; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for (round = (Nr - 1); round > 0; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
  }

  // The last round is given below.
  // The MixColumns function is not here in the last round.
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}

static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
  uint8_t buffer[AES_BLOCKLEN];

  unsigned i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {

      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
	{
          ctx->Iv[bi] = 0;
          continue;
        }
        ctx->Iv[bi] += 1;
        break;
      }
      bi = 0;
    }

    buf[i] = (buf[i] ^ buffer[bi]);
  }
}
//END OF CODE FROM tiny AES PROJECT
/////////////////////////////////////////

//Hash to 32 bits from https://en.wikipedia.org/wiki/MurmurHash
uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
{
	//printf("Values to hash\n");
	full_print_hex(key, len);
	uint32_t h = seed;
	if (len > 3) {
		const uint32_t* key_x4 = (const uint32_t*) key;
		size_t i = len >> 2;
		do {
			uint32_t k = *key_x4++;
			k *= 0xcc9e2d51;
			k = (k << 15) | (k >> 17);
			k *= 0x1b873593;
			h ^= k;
			h = (h << 13) | (h >> 19);
			h = h * 5 + 0xe6546b64;
		} while (--i);
		key = (const uint8_t*) key_x4;
	}
	if (len & 3) {
		size_t i = len & 3;
		uint32_t k = 0;
		key = &key[i - 1];
		do {
			k <<= 8;
			k |= *key--;
		} while (--i);
		k *= 0xcc9e2d51;
		k = (k << 15) | (k >> 17);
		k *= 0x1b873593;
		h ^= k;
	}
	h ^= len;
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

/////////////////TINYCRYPT HMAC SHA256

/* utils.c - TinyCrypt platform-dependent run-time operations */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#define MASK_TWENTY_SEVEN 0x1b

uint32_t _copy(uint8_t *to, uint32_t to_len,
		   const uint8_t *from, uint32_t from_len)
{
	if (from_len <= to_len) {
		(void)memcpy(to, from, from_len);
		return from_len;
	} else {
		return TC_CRYPTO_FAIL;
	}
}

void _set(void *to, uint8_t val, uint32_t len)
{
	(void)memset(to, val, len);
}

/*
 * Doubles the value of a byte for values up to 127.
 */
uint8_t _double_byte(uint8_t a)
{
	return ((a<<1) ^ ((a>>7) * MASK_TWENTY_SEVEN));
}

int _compare(const uint8_t *a, const uint8_t *b, size_t size)
{
	const uint8_t *tempa = a;
	const uint8_t *tempb = b;
	uint8_t result = 0;

	uint32_t i;
	for (i = 0; i < size; i++) {
		result |= tempa[i] ^ tempb[i];
	}
	return result;
}


/* sha256.c - TinyCrypt SHA-256 crypto hash algorithm implementation */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

static void compress(uint32_t *iv, const uint8_t *data);

int tc_sha256_init(TCSha256State_t s)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	/*
	 * Setting the initial state values.
	 * These values correspond to the first 32 bits of the fractional parts
	 * of the square roots of the first 8 primes: 2, 3, 5, 7, 11, 13, 17
	 * and 19.
	 */
	_set((uint8_t *) s, 0x00, sizeof(*s));
	s->iv[0] = 0x6a09e667;
	s->iv[1] = 0xbb67ae85;
	s->iv[2] = 0x3c6ef372;
	s->iv[3] = 0xa54ff53a;
	s->iv[4] = 0x510e527f;
	s->iv[5] = 0x9b05688c;
	s->iv[6] = 0x1f83d9ab;
	s->iv[7] = 0x5be0cd19;

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_update(TCSha256State_t s, const uint8_t *data, size_t datalen)
{
	/* input sanity check: */
	if (s == (TCSha256State_t) 0 ||
	    data == (void *) 0) {
		return TC_CRYPTO_FAIL;
	} else if (datalen == 0) {
		return TC_CRYPTO_SUCCESS;
	}

	while (datalen-- > 0) {
		s->leftover[s->leftover_offset++] = *(data++);
		if (s->leftover_offset >= TC_SHA256_BLOCK_SIZE) {
			compress(s->iv, s->leftover);
			s->leftover_offset = 0;
			s->bits_hashed += (TC_SHA256_BLOCK_SIZE << 3);
		}
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_sha256_final(uint8_t *digest, TCSha256State_t s)
{
	uint32_t i;

	/* input sanity check: */
	if (digest == (uint8_t *) 0 ||
	    s == (TCSha256State_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	s->bits_hashed += (s->leftover_offset << 3);

	s->leftover[s->leftover_offset++] = 0x80; /* always room for one byte */
	if (s->leftover_offset > (sizeof(s->leftover) - 8)) {
		/* there is not room for all the padding in this block */
		_set(s->leftover + s->leftover_offset, 0x00,
		     sizeof(s->leftover) - s->leftover_offset);
		compress(s->iv, s->leftover);
		s->leftover_offset = 0;
	}

	/* add the padding and the length in big-Endian format */
	_set(s->leftover + s->leftover_offset, 0x00,
	     sizeof(s->leftover) - 8 - s->leftover_offset);
	s->leftover[sizeof(s->leftover) - 1] = (uint8_t)(s->bits_hashed);
	s->leftover[sizeof(s->leftover) - 2] = (uint8_t)(s->bits_hashed >> 8);
	s->leftover[sizeof(s->leftover) - 3] = (uint8_t)(s->bits_hashed >> 16);
	s->leftover[sizeof(s->leftover) - 4] = (uint8_t)(s->bits_hashed >> 24);
	s->leftover[sizeof(s->leftover) - 5] = (uint8_t)(s->bits_hashed >> 32);
	s->leftover[sizeof(s->leftover) - 6] = (uint8_t)(s->bits_hashed >> 40);
	s->leftover[sizeof(s->leftover) - 7] = (uint8_t)(s->bits_hashed >> 48);
	s->leftover[sizeof(s->leftover) - 8] = (uint8_t)(s->bits_hashed >> 56);

	/* hash the padding and length */
	compress(s->iv, s->leftover);

	/* copy the iv out to digest */
	for (i = 0; i < TC_SHA256_STATE_BLOCKS; ++i) {
		uint32_t t = *((uint32_t *) &s->iv[i]);
		*digest++ = (uint8_t)(t >> 24);
		*digest++ = (uint8_t)(t >> 16);
		*digest++ = (uint8_t)(t >> 8);
		*digest++ = (uint8_t)(t);
	}

	/* destroy the current state */
	_set(s, 0, sizeof(*s));

	return TC_CRYPTO_SUCCESS;
}

/*
 * Initializing SHA-256 Hash constant words K.
 * These values correspond to the first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes between 2 and 311.
 */
static const uint32_t k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t ROTR(uint32_t a, uint32_t n)
{
	return (((a) >> n) | ((a) << (32 - n)));
}

#define Sigma0(a)(ROTR((a), 2) ^ ROTR((a), 13) ^ ROTR((a), 22))
#define Sigma1(a)(ROTR((a), 6) ^ ROTR((a), 11) ^ ROTR((a), 25))
#define sigma0(a)(ROTR((a), 7) ^ ROTR((a), 18) ^ ((a) >> 3))
#define sigma1(a)(ROTR((a), 17) ^ ROTR((a), 19) ^ ((a) >> 10))

#define Ch(a, b, c)(((a) & (b)) ^ ((~(a)) & (c)))
#define Maj(a, b, c)(((a) & (b)) ^ ((a) & (c)) ^ ((b) & (c)))

static inline uint32_t BigEndian(const uint8_t **c)
{
	uint32_t n = 0;

	n = (((uint32_t)(*((*c)++))) << 24);
	n |= ((uint32_t)(*((*c)++)) << 16);
	n |= ((uint32_t)(*((*c)++)) << 8);
	n |= ((uint32_t)(*((*c)++)));
	return n;
}

static void compress(uint32_t *iv, const uint8_t *data)
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t s0, s1;
	uint32_t t1, t2;
	uint32_t work_space[16];
	uint32_t n;
	uint32_t i;

	a = iv[0]; b = iv[1]; c = iv[2]; d = iv[3];
	e = iv[4]; f = iv[5]; g = iv[6]; h = iv[7];

	for (i = 0; i < 16; ++i) {
		n = BigEndian(&data);
		t1 = work_space[i] = n;
		t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
		t2 = Sigma0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	for ( ; i < 64; ++i) {
		s0 = work_space[(i+1)&0x0f];
		s0 = sigma0(s0);
		s1 = work_space[(i+14)&0x0f];
		s1 = sigma1(s1);

		t1 = work_space[i&0xf] += s0 + s1 + work_space[(i+9)&0xf];
		t1 += h + Sigma1(e) + Ch(e, f, g) + k256[i];
		t2 = Sigma0(a) + Maj(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	iv[0] += a; iv[1] += b; iv[2] += c; iv[3] += d;
	iv[4] += e; iv[5] += f; iv[6] += g; iv[7] += h;
}

/* hmac.c - TinyCrypt implementation of the HMAC algorithm */

/*
 *  Copyright (C) 2017 by Intel Corporation, All Rights Reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *    - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *    - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *    - Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */


static void rekey(uint8_t *key, const uint8_t *new_key, uint32_t key_size)
{
	const uint8_t inner_pad = (uint8_t) 0x36;
	const uint8_t outer_pad = (uint8_t) 0x5c;
	uint32_t i;

	for (i = 0; i < key_size; ++i) {
		key[i] = inner_pad ^ new_key[i];
		key[i + TC_SHA256_BLOCK_SIZE] = outer_pad ^ new_key[i];
	}
	for (; i < TC_SHA256_BLOCK_SIZE; ++i) {
		key[i] = inner_pad; key[i + TC_SHA256_BLOCK_SIZE] = outer_pad;
	}
}

int tc_hmac_set_key(TCHmacState_t ctx, const uint8_t *key,
		    uint32_t key_size)
{
	/* Input sanity check */
	if (ctx == (TCHmacState_t) 0 ||
	    key == (const uint8_t *) 0 ||
	    key_size == 0) {
		return TC_CRYPTO_FAIL;
	}

	const uint8_t dummy_key[TC_SHA256_BLOCK_SIZE];
	struct tc_hmac_state_struct dummy_state;

	if (key_size <= TC_SHA256_BLOCK_SIZE) {
		/*
		 * The next three calls are dummy calls just to avoid
		 * certain timing attacks. Without these dummy calls,
		 * adversaries would be able to learn whether the key_size is
		 * greater than TC_SHA256_BLOCK_SIZE by measuring the time
		 * consumed in this process.
		 */
		(void)tc_sha256_init(&dummy_state.hash_state);
		(void)tc_sha256_update(&dummy_state.hash_state,
				       dummy_key,
				       key_size);
		(void)tc_sha256_final(&dummy_state.key[TC_SHA256_DIGEST_SIZE],
				      &dummy_state.hash_state);

		/* Actual code for when key_size <= TC_SHA256_BLOCK_SIZE: */
		rekey(ctx->key, key, key_size);
	} else {
		(void)tc_sha256_init(&ctx->hash_state);
		(void)tc_sha256_update(&ctx->hash_state, key, key_size);
		(void)tc_sha256_final(&ctx->key[TC_SHA256_DIGEST_SIZE],
				      &ctx->hash_state);
		rekey(ctx->key,
		      &ctx->key[TC_SHA256_DIGEST_SIZE],
		      TC_SHA256_DIGEST_SIZE);
	}

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_init(TCHmacState_t ctx)
{

	/* input sanity check: */
	if (ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

  (void) tc_sha256_init(&ctx->hash_state);
  (void) tc_sha256_update(&ctx->hash_state, ctx->key, TC_SHA256_BLOCK_SIZE);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_update(TCHmacState_t ctx,
		   const void *data,
		   uint32_t data_length)
{

	/* input sanity check: */
	if (ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	(void)tc_sha256_update(&ctx->hash_state, data, data_length);

	return TC_CRYPTO_SUCCESS;
}

int tc_hmac_final(uint8_t *tag, uint32_t taglen, TCHmacState_t ctx)
{

	/* input sanity check: */
	if (tag == (uint8_t *) 0 ||
	    taglen != TC_SHA256_DIGEST_SIZE ||
	    ctx == (TCHmacState_t) 0) {
		return TC_CRYPTO_FAIL;
	}

	(void) tc_sha256_final(tag, &ctx->hash_state);

	(void)tc_sha256_init(&ctx->hash_state);
	(void)tc_sha256_update(&ctx->hash_state,
			       &ctx->key[TC_SHA256_BLOCK_SIZE],
				TC_SHA256_BLOCK_SIZE);
	(void)tc_sha256_update(&ctx->hash_state, tag, TC_SHA256_DIGEST_SIZE);
	(void)tc_sha256_final(tag, &ctx->hash_state);

	/* destroy the current state */
	_set(ctx, 0, sizeof(*ctx));

	return TC_CRYPTO_SUCCESS;
}
