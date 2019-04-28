#include "contiki.h"
#include "lib/random.h"
#include "net/ipv6/uip-ds6.h"
#include "dev/button-sensor.h"
#include "simple-udp.h"
#include "cfs/cfs.h"

#include <stdio.h>

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

uint8_t *key = "gebruikersleutel";

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
	if (resource_access_requested) {
		if(data[0]){
			printf("End of Successful Hidra Exchange.\n");
			security_association_established = 1;
		} else {
			printf("Received Non-Acknowledge: Unsuccessful hidra exchange.\n");
		}
	} else {
		printf("Unexpected message from resource\n");
	}
}

static void
send_access_request(void) {
	//Content of access request, all full bytes for simplicity
	// = id (1 byte) + action (1 byte) + system_reference (1 byte)
	const char action =  2;//PUT
	const char function =  18;
	const char response[3] = {subject_id, action, function};
	simple_udp_sendto(&unicast_connection_resource, response, strlen(response), &resource_addr);
	resource_access_requested = 1;
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
	printf("Data Rx: %.*s\n", datalen, data);
	if (authentication_requested) {
		if (credentials_requested) {
				// Perform phase 3, the access request
				send_access_request();
		} else {
			// Perform phase 2
			const char response = subject_id;
			simple_udp_sendto(&unicast_connection_acs, &response, strlen(&response), &acs_addr);
			credentials_requested = 1;
		}
	} else {
		printf("Unexpected message from ACS\n");
	}
}

static void
start_hidra_protocol(void) {
	//TODO zou 15 bytes lang moeten zijn?! Als je niet vindt waarom, doe dan gewoon bvb 4, voor elk veld 1
	uint8_t temp[4];
	// IdS
	temp[0] = subject_id;
	// IdCM
	temp[1] = 0;
	// LifetimeTGT
	temp[2] = 255;
	//Nonce1 (2 bytes)
	uint16_t nonce = random_rand();
	temp[3] = nonce && 0xffff;
//	temp[3] = (nonce >> 8);
//	temp[4] = nonce && 0xffff;
	const uint8_t *response = temp;
	simple_udp_sendto(&unicast_connection_acs, response, 4, &acs_addr);
	authentication_requested = 1;
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
	  printf("ERROR: could not write to memory in step 2.\n");
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
	  printf("ERROR: could not read from memory in step 3.\n");
	}

	strcpy(message,"#1.hello test.");
	fd_write = cfs_open(filename, CFS_WRITE | CFS_APPEND);
	 if(fd_write != -1) {
	   n = cfs_write(fd_write, message, sizeof(message));
	   cfs_close(fd_write);
	   printf("step 4: successfully appended data to cfs. wrote %i bytes\n",n);
	 } else {
	   printf("ERROR: could not write to memory in step 4.\n");
	 }
	strcpy(buf,"empty string");
	fd_read = cfs_open(filename, CFS_READ);
	if(fd_read!=-1) {
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
	   printf("ERROR: could not read from memory in step 5.\n");
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
	printf("ERROR: could read from memory in step 6.\n");
	}
}

PROCESS_THREAD(hidra_subject, ev, data)
{
	PROCESS_BEGIN();

	SENSORS_ACTIVATE(button_sensor);
//	random_init();

	//use global address to deduce node-id
	subject_id = set_global_address()->u8[15];
	set_resource_address();
	set_acs_address();

//	test_file_operations();

	simple_udp_register(&unicast_connection_acs, ACS_UDP_PORT,
						  NULL, ACS_UDP_PORT,
						  receiver_acs);

	simple_udp_register(&unicast_connection_resource, RESOURCE_UDP_PORT,
						  NULL, RESOURCE_UDP_PORT,
						  receiver_resource);

	while(1) {
		PROCESS_WAIT_EVENT();

		if ((ev==sensors_event) && (data == &button_sensor)) {
			if (!security_association_established) {
				printf("Starting Hidra Protocol\n");
				start_hidra_protocol();
			}
		}
	}
	PROCESS_END();
}
