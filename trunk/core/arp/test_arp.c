/**@file test_arp.c
 *@brief this files contains all the functions to test an ARP module SINGLE INTERFACE
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */
#include <finstypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <finsdebug.h>
#include <metadata.h>

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <queueModule.h>
#include <pthread.h>
#include "test_arp.h" //this header file already contains #include "arp.h"
#define DEBUG

sem_t ARP_to_Switch_Qsem;
finsQueue ARP_to_Switch_Queue;

sem_t Switch_to_ARP_Qsem;
finsQueue Switch_to_ARP_Queue;

struct arp_node *ptr_neighbor_list;
int num_hosts; /*<the number of neighbors to be generated*/

uint64_t host_MAC_addrs;/**<MAC address of current interface; sent to the arp module*/
uint32_t host_IP_addrs;/**<IP address of current interface; sent to the arp module*/

unsigned char *IP_addrs; /**<This contains an IP address (from heap) which is used by the paramValue of a FINS control frame*/
struct arp_hdr *arp_net;

//struct node *ptr_neighbor_list; /**<pointer the first element of a list of 'neighbors'*/
FILE *ptr_file; /**<file pointer to the file which contains a list of neighbors*/

/**
 * @brief this function is used to read an IP address from a user
 */
uint32_t read_IP_addrs() {
	uint32_t IP_target_addrs;

	uint8_t b1, b2, b3, b4; /**<octets representing the IP address*/
	char IP_string[20];
	char *a1, *a2, *a3, *a4; /**<temporary variables to store parsed IP octet strings*/
	int test_int;

	PRINT_DEBUG("Enter IP address (e.g. 234.0.17.8) of target; (0.0.0.0) to end:\n");
	scanf("%s", IP_string);

	test_int = atoi(IP_string);

	a1 = strtok(IP_string, ".");
	b1 = atoi(a1);
	a2 = strtok(NULL, ".");
	b2 = atoi(a2);
	a3 = strtok(NULL, ".");
	b3 = atoi(a3);
	a4 = strtok(NULL, ".");
	b4 = atoi(a4);

	IP_target_addrs = gen_IP_addrs(b1, b2, b3, b4);

	if (IP_target_addrs == 0)
		IP_target_addrs = NULLADDRESS;

	return IP_target_addrs;
}

/** @brief generates a binary file with artificially generated hosts (with random IP and
 * MAC addresses within a network
 * @param fileName is the name of the file where these addresses are stored
 */
void gen_neighbor_list(char *fileName) {
	//	int num_hosts; /**<number of neighbors to be generated*/
	int i; /**< This is a variable for iterating through number of records <recordsNum>*/

	/**< The following variables are for storing octet values*/
	uint8_t IPa, IPb, IPc, IPd, MACa, MACb, MACc, MACd, MACe, MACf;

	struct arp_node record;

	ptr_file = fopen(fileName, "w");
	if (!ptr_file) {
		PRINT_DEBUG("Unable to open file!");
		exit(0);
	}

	PRINT_DEBUG("How many neighbors in a network to create?\n");
	fflush(stdout);
	scanf("%d", &num_hosts);

	srand((unsigned) time(0));

	for (i = 0; i < num_hosts; i++) {
		MACa = (rand()) % 255;
		MACb = (rand()) % 255;
		MACc = (rand()) % 255;
		MACd = (rand()) % 255;
		MACe = (rand()) % 255;
		MACf = (rand()) % 255;
		IPa = (rand()) % 255;
		IPb = (rand()) % 255;
		IPc = (rand()) % 255;
		IPd = (rand()) % 255;
		record.IP_addrs = gen_IP_addrs(IPa, IPb, IPc, IPd);
		record.MAC_addrs = gen_MAC_addrs(MACa, MACb, MACc, MACd, MACe, MACf);
		fwrite(&record, sizeof(struct arp_node), 1, ptr_file);
	}

	fclose(ptr_file); // closes the file
}

/**@brief this function reads a list of artificially created neighbor's list of a host
 * @param fileName is the file from which a list is generated
 */
struct arp_node* read_neighbor_list(char* fileName) {
	int i, j; /**<temporary variables for condition testing purposes*/

	struct arp_node *ptr_elementInList1, *ptr_elementInList2, *new_host, ptr_list; /**<These variables are used to store
	 the read struct data from the file*/

	if ((ptr_file = fopen(fileName, "r")) == NULL) {
		PRINT_DEBUG("Cannot open file.\n");
		exit(0);
	}

	j = 0;
	i = 0;

	while (!feof(ptr_file) && j < num_hosts) {
		fread(&ptr_list, sizeof(struct arp_node), 1, ptr_file);

		new_host = (struct arp_node *) malloc(sizeof(struct arp_node));

		new_host->IP_addrs = ptr_list.IP_addrs;
		new_host->MAC_addrs = ptr_list.MAC_addrs;
		new_host->next = NULL;

		if (j == 0) {
			ptr_elementInList1 = new_host;
			ptr_elementInList2 = new_host;
		} else {
			ptr_elementInList2->next = new_host;
			ptr_elementInList2 = new_host;
		}

		j = j + 1;
	}

	fclose(ptr_file); // closes the file
	return ptr_elementInList1;
}

/**
 * @brief this function reads from a binary file a list of nodes (neighbors) used in testing
 * @param fileName is the name of the binary file
 */
void init_recordsARP(char *fileName) {

	ptr_file = fopen(fileName, "r"); //open file

	if (!ptr_file) // exit if file cannot open
		exit(0);

	ptr_neighbor_list = read_neighbor_list(fileName); /**initialize the table from the file*/

}

/**@brief this function mimics ARP request from some neighbor within a network
 * @param IP_sender_addrs is the IP address of the neighbor which has sent a 'request'
 * @param MAC_sender_addrs is the MAC address of the neighbor
 * @param request_ARP_ptr is the pointer to the ARP message struct
 */
void mimic_net_request(uint32_t IP_sender_addrs, uint64_t MAC_sender_addrs, struct ARP_message *request_ARP_ptr) {
	request_ARP_ptr->hardware_type = (HWDTYPE);
	request_ARP_ptr->protocol_type = (PROTOCOLTYPE);
	request_ARP_ptr->hardware_addrs_length = HDWADDRSLEN;
	request_ARP_ptr->protocol_addrs_length = PROTOCOLADDRSLEN;
	request_ARP_ptr->operation = (ARP_OP_REQUEST);
	request_ARP_ptr->sender_MAC_addrs = MAC_sender_addrs;
	request_ARP_ptr->sender_IP_addrs = IP_sender_addrs;
	request_ARP_ptr->target_MAC_addrs = 0;
	request_ARP_ptr->target_IP_addrs = host_IP_addrs;

}

/**Based on which host matches the ARP request an appropriate reply through a FINS frame is
 * created
 * @brief this function mimics a network response for an ARP request pushed via a FINS frame.
 * The purpose is to test the functionality of the code for the ARP module
 * @param request_ARP_ptr is the pointer to the ARP message struct request received by the 'nodes'
 * @param reply_ARP_ptr is the pointer to the ARP message struct reply given the appropriate node
 */
void mimic_net_reply(struct ARP_message *request_ARP_ptr, struct ARP_message *reply_ARP_ptr) {
	struct arp_node *ptr_elementInList;
	struct ARP_message reply_ARP;

	ptr_elementInList = ptr_neighbor_list;

	while (ptr_elementInList != NULL) {
		if (ptr_elementInList->IP_addrs == request_ARP_ptr->target_IP_addrs) {
			reply_ARP.sender_IP_addrs = ptr_elementInList->IP_addrs;
			reply_ARP.sender_MAC_addrs = ptr_elementInList->MAC_addrs;
			reply_ARP.target_IP_addrs = request_ARP_ptr->sender_IP_addrs;
			reply_ARP.target_MAC_addrs = request_ARP_ptr->sender_MAC_addrs;
			reply_ARP.hardware_addrs_length = request_ARP_ptr->hardware_addrs_length;
			reply_ARP.hardware_type = (request_ARP_ptr->hardware_type);
			reply_ARP.operation = (ARP_OP_REPLY);
			reply_ARP.protocol_addrs_length = request_ARP_ptr->protocol_addrs_length;
			reply_ARP.protocol_type = (request_ARP_ptr->protocol_type);
			memcpy(reply_ARP_ptr, &reply_ARP, sizeof(struct ARP_message));
		}
		ptr_elementInList = ptr_elementInList->next;
	}
}

/**@brief this generates a Fins frame which is sent to the arp module so that the
 * (1) a host receives an ARP reply, OR (2) sends an ARP request to a network
 * @param fins_frame is the pointer to the received fins frame
 * @param task indicates whether the arp message is a request or a reply to or from network
 */
void fins_from_net(struct finsFrame *fins_frame, int task) {
	struct ARP_message msg1, msg2;
	uint32_t IP_addrs_read;
	uint64_t MAC_addrs;

	PRINT_DEBUG("\nFins data frame which carries a request or reply ARP from a network\n");

	IP_addrs_read = read_IP_addrs();
	MAC_addrs = search_MAC_addrs(IP_addrs_read, ptr_neighbor_list);

	if (task == 1) {
		mimic_net_request(IP_addrs_read, MAC_addrs, &msg1);
		arp_msg_to_hdr(&msg1, arp_net);
		host_to_net(arp_net);
		arp_to_fins(arp_net, fins_frame);
	} else if (task == 2) {
		gen_requestARP(IP_addrs_read, &msg1);
		mimic_net_reply(&msg1, &msg2);
		arp_msg_to_hdr(&msg2, arp_net);
		host_to_net(arp_net);
		arp_to_fins(arp_net, fins_frame);
	}
	fins_frame->destinationID.id = ARPID;

}

/**@brief this function generates a fins frame from the ethernet stub
 * @param fins_frame is the pointer to the fins frame to be sent into the arp
 */
void fins_from_stub(struct finsFrame *fins_frame) {

	uint32_t IP_addrs_read;

	PRINT_DEBUG("\nFins control frame from link layer stub\n");
	IP_addrs_read = read_IP_addrs();
	IP_addrs_conversion(IP_addrs_read, IP_addrs);
	fins_frame->dataOrCtrl = CONTROL;
	fins_frame->destinationID.id = ARPID;
	fins_frame->ctrlFrame.opcode = 333/*WRITEREQUEST*/;
	fins_frame->ctrlFrame.serialNum = 123;
	fins_frame->ctrlFrame.senderID = (unsigned char) ETHERSTUBID;
	fins_frame->ctrlFrame.paramterValue = IP_addrs;
}

void test_to_arp(struct finsFrame *fins_frame) {
	PRINT_DEBUG("Entered: ff=%p meta=%p", fins_frame, fins_frame->metaData);

	if (sem_wait(&Switch_to_ARP_Qsem)) {
		PRINT_ERROR("Switch_to_ARP_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(fins_frame, Switch_to_ARP_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&Switch_to_ARP_Qsem);
		return;
	}

	PRINT_DEBUG("");
	sem_post(&Switch_to_ARP_Qsem);
}

void *ARP() {

	arp_init(NULL);

	pthread_exit(NULL);
}

void arp_test_harness() {
	struct finsFrame *fins_frame = malloc(sizeof(struct finsFrame));
	int task;

	IP_addrs = (unsigned char *) malloc(sizeof(unsigned char) * PROTOCOLADDRSLEN);
	arp_net = (struct arp_hdr*) malloc(sizeof(struct arp_hdr));

	init_arp_intface(host_MAC_addrs, host_IP_addrs); //necessary to initialize the arp module

	pthread_t thread;
	//spin off thread to handle
	if (pthread_create(&thread, NULL, ARP, NULL)) {
		PRINT_ERROR("ERROR: unable to create thread thread.");
	} else {
		//pthread_detach(thread);
	}

	task = 1;
	while (task != 0) {

		PRINT_DEBUG("\nReceive from network a request arp `1' or reply arp `2' or\n generate request to network `3', `0' to exit\n");
		scanf("%d", &task);

		if ((task == 1) || (task == 2))
			fins_from_net(fins_frame, task);
		else if (task == 3)
			fins_from_stub(fins_frame);

		if (task == 1 || task == 2 || task == 3) {
			//arp_in(&fins_frame); //necessary to run the arp module
			test_to_arp(fins_frame);
		}

		//TODO wait on the outcoming FF and test to see if it's right
	}

	term_arp_intface(); //necessary to terminate the arp module
	free(IP_addrs);
	free(arp_net);

}

#define MAX_Queue_size 100000

int main(int argc, char *argv[]) {
	uint64_t MACADDRESS = 9890190479;/**<MAC address of host; sent to the arp module*/
	uint32_t IPADDRESS = 672121;/**<IP address of host; sent to the arp module*/

	host_MAC_addrs = MACADDRESS;
	host_IP_addrs = IPADDRESS;

	ARP_to_Switch_Queue = init_queue("arp2switch", MAX_Queue_size);
	Switch_to_ARP_Queue = init_queue("switch2arp", MAX_Queue_size);
	sem_init(&ARP_to_Switch_Qsem, 0, 1);
	sem_init(&Switch_to_ARP_Qsem, 0, 1);

	gen_neighbor_list(argv[1]);

	init_recordsARP(argv[1]);
	print_neighbors(ptr_neighbor_list);

	arp_test_harness(); //test functionality of ARP module

	return 0;
}
