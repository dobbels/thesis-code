#include "contiki.h"

#include "net/ipv6/uip-ds6.h"

#include "simple-udp.h"

//#include "dev/button-sensor.h"
//
////#include "../sha.h"
//
//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>
//
//#include "debug.h"
//#define DEBUG DEBUG_PRINT
//#include "net/ip/uip-debug.h"

//const uint8_t resource_key[16] =
//	{ (uint8_t) 0x2b, (uint8_t) 0x7e, (uint8_t) 0x15, (uint8_t) 0x16,
//		(uint8_t) 0x28, (uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x2b,
//		(uint8_t) 0x2b, (uint8_t) 0x2b, (uint8_t) 0x15, (uint8_t) 0x2b,
//		(uint8_t) 0x09, (uint8_t) 0x2b, (uint8_t) 0x4f, (uint8_t) 0x3c };


//static void full_print_hex(uint8_t* str, uint8_t length);
//static void print_hex(uint8_t* str, uint8_t len);
//
//int i = 0;


static struct simple_udp_connection unicast_connection_acs;
static struct simple_udp_connection unicast_connection_subject;

#define ACS_UDP_PORT 1234
#define SUBJECT_UDP_PORT 1996

PROCESS(hidra_r,"HidraR");
AUTOSTART_PROCESSES(&hidra_r);

static void
receiver_subject(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
//  printf("\nData received from: ");
//  PRINT6ADDR(sender_addr);
//  printf("\nAt port %d from port %d with length %d\n",
//		  receiver_port, sender_port, datalen);
//  printf("Data Rx: %.*s\n", datalen, data);
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
//	printf("\nData received from: ");
//	PRINT6ADDR(sender_addr);
//	printf("\nAt port %d from port %d with length %d\n",
//		  receiver_port, sender_port, datalen);
//	printf("Data Rx: %.*s\n", datalen, data);


	const char *response = "hi";
	simple_udp_sendto(c, response, strlen(response), sender_addr);
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

//  printf("IPv6 addresses: ");
//  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
//    state = uip_ds6_if.addr_list[i].state;
//    if(uip_ds6_if.addr_list[i].isused &&
//       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
//      uip_debug_ipaddr_print(&uip_ds6_if.addr_list[i].ipaddr);
//      printf("\n");
//    }
//  }

  return &ipaddr;
}


//Hash to 32 bits from https://en.wikipedia.org/wiki/MurmurHash
//uint32_t murmur3_32(const uint8_t* key, size_t len, uint32_t seed)
//{
//	printf("Values to hash\n");
//	full_print_hex(key, len);
//	uint32_t h = seed;
//	if (len > 3) {
//		const uint32_t* key_x4 = (const uint32_t*) key;
//		size_t i = len >> 2;
//		do {
//			uint32_t k = *key_x4++;
//			k *= 0xcc9e2d51;
//			k = (k << 15) | (k >> 17);
//			k *= 0x1b873593;
//			h ^= k;
//			h = (h << 13) | (h >> 19);
//			h = h * 5 + 0xe6546b64;
//		} while (--i);
//		key = (const uint8_t*) key_x4;
//	}
//	if (len & 3) {
//		size_t i = len & 3;
//		uint32_t k = 0;
//		key = &key[i - 1];
//		do {
//			k <<= 8;
//			k |= *key--;
//		} while (--i);
//		k *= 0xcc9e2d51;
//		k = (k << 15) | (k >> 17);
//		k *= 0x1b873593;
//		h ^= k;
//	}
//	h ^= len;
//	h ^= h >> 16;
//	h *= 0x85ebca6b;
//	h ^= h >> 13;
//	h *= 0xc2b2ae35;
//	h ^= h >> 16;
//	return h;
//}

//void
//test_hmac() {
//	const uint8_t text[46] = { 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
//							0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x51,
//							0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
//	printf("Vector: \n");
//	full_print_hex(text, sizeof(text));
//
//	printf("Key: \n");
//	full_print_hex(resource_key, sizeof(resource_key));
//
////	//Size : USHAMaxHashSize
//	uint8_t digest[USHAMaxHashSize];
////	//TODO process result code, should be 0
//	hmac (SHA1, text, sizeof(text), resource_key, sizeof(resource_key), digest);
//
//	printf("HMAC_SHA_1: \n");
//	full_print_hex(digest, 20);
//
//	uint32_t hashed = murmur3_32(digest, 20, 17);
//	uint8_t hashed_array[4];
//	hashed_array[0] = (hashed >> 24) & 0xff;
//	hashed_array[1] = (hashed >> 16) & 0xff;
//	hashed_array[2] = (hashed >> 8)  & 0xff;
//	hashed_array[3] = hashed & 0xff;
//
//	printf("Hashed HMAC_SHA_1: \n");
//	full_print_hex(hashed_array, 4);
//}

PROCESS_THREAD(hidra_r, ev, data)
{
	PROCESS_BEGIN();
//	SENSORS_ACTIVATE(button_sensor);

	set_global_address();

	// Register a sockets, with the correct host and remote ports
	// NULL parameter as the destination address to allow packets from any address. (fixed IPv6 address can be given)
	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);
	simple_udp_register(&unicast_connection_subject, SUBJECT_UDP_PORT,
							  NULL, SUBJECT_UDP_PORT,
							  receiver_subject);

//	test_hmac();

	while(1) {
		PROCESS_WAIT_EVENT();
//		printf("Still working: %d\n", ++i);
	}

	PROCESS_END();
}


//static void full_print_hex(uint8_t* str, uint8_t length) {
//	printf("********************************\n");
//	int i = 0;
//	for (; i < (length/16) ; i++) {
//		print_hex(str + i * 16, 16);
//	}
//	print_hex(str + i * 16, length%16);
//	printf("********************************\n");
//}
//
//// prints string as hex
//static void print_hex(uint8_t* str, uint8_t len)
//{
//    unsigned char i;
//    for (i = 0; i < len; ++i)
//        printf("%.2x", str[i]);
//    printf("\n");
//}
