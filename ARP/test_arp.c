/**@file test_arp.c
 *@brief this files contains all the functions to test an ARP module SINGLE INTERFACE
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */
#include "finstypes.h"
#include "arp.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "finsdebug.h"
#include "metadata.h"

#define DEBUG


int INTERFACECOUNT= 1;
uint64_t MACADDRESS = 890190479;/**<hard coded MAC address of host*/
uint32_t IPADDRESS = 672121;/**<hard coded IP address of host*/

struct node *ptr_neighbor_list;

uint32_t IP_interface_set[1];
uint64_t MAC_interface_set[1];
uint64_t interface_MAC_addrs;/**<MAC address of current interface*/
uint32_t interface_IP_addrs;/**<IP address of current interface*/

int num_hosts;
struct node *ptr_neighbor_list; /**<pointer the first element of a list of 'neighbors'*/
FILE *ptr_file; /**<file pointer to the file which contains a list of neighbors*/

/**
 * @brief this function is used to read an IP address from a user
 */
uint32_t read_IP_addrs()
{
	uint32_t IP_target_addrs;

	uint8_t b1, b2, b3, b4; /**<octets representing the IP address*/
	char IP_string[20];
	char *a1, *a2, *a3, *a4; /**<temporary variables to store parsed IP octet strings*/
	int test_int;

	PRINT_DEBUG("Enter IP address (e.g. 234.0.17.8) of target; (0.0.0.0) to end:\n");
	scanf("%s",IP_string);

	test_int = atoi(IP_string);

	a1 = strtok(IP_string, ".");
	b1 = atoi(a1);
	a2 = strtok( NULL, "." );
	b2 = atoi(a2);
	a3 = strtok( NULL, "." );
	b3 = atoi(a3);
	a4 = strtok( NULL, "." );
	b4 = atoi(a4);

	IP_target_addrs = gen_IP_addrs(b1,b2,b3,b4);

	if (IP_target_addrs == 0)
		IP_target_addrs = NULLADDRESS;

	return IP_target_addrs;
}

/** @brief generates a binary file with artificially generated hosts (with random IP and
 * MAC addresses within a network
 * @param fileName is the name of the file where these addresses are stored
 */
void gen_neighbor_list(char *fileName)
{
	//	int num_hosts; /**<number of neighbors to be generated*/
	int i; /**< This is a variable for iterating through number of records <recordsNum>*/

	/**< The following variables are for storing octet values*/
	uint8_t IPa, IPb, IPc, IPd, MACa, MACb, MACc, MACd, MACe, MACf;

	struct node record;

	ptr_file =fopen(fileName,"w");
	if (!ptr_file)
	{	PRINT_DEBUG("Unable to open file!");
	exit (0);
	}

	PRINT_DEBUG("How many neighbors in a network to create?\n");
	fflush(stdout);
	scanf("%d", &num_hosts);

	srand ( (unsigned)time (0) );

	for (i=0;i<num_hosts;i++)
	{
		MACa = (rand())%255;
		MACb = (rand())%255;
		MACc = (rand())%255;
		MACd = (rand())%255;
		MACe = (rand())%255;
		MACf = (rand())%255;
		IPa = (rand())%255;
		IPb = (rand())%255;
		IPc = (rand())%255;
		IPd = (rand())%255;
		record.IP_addrs = gen_IP_addrs(IPa,IPb,IPc,IPd);
		record.MAC_addrs = gen_MAC_addrs(MACa,MACb,MACc,MACd,MACe, MACf);
		fwrite(&record, sizeof(struct node), 1, ptr_file);
	}

	fclose(ptr_file);    // closes the file
}

/**@brief this function reads a list of artificially created neighbor's list of a host
 * @param fileName is the file from which a list is generated
 */
struct node* read_neighbor_list(char* fileName)
		{
	int i,j; /**<temporary variables for condition testing purposes*/

	struct node *ptr_elementInList1, *ptr_elementInList2, *new_host, ptr_list; /**<These variables are used to store
	the read struct data from the file*/

	if((ptr_file=fopen(fileName, "r")) == NULL) {
		PRINT_DEBUG("Cannot open file.\n");
		exit(0);
	}

	j = 0;
	i = 0;

	while (!feof(ptr_file) && j<num_hosts)
	{
		fread(&ptr_list,sizeof(struct node),1,ptr_file);

		new_host = (struct node *) malloc (sizeof(struct node));

		new_host->IP_addrs = ptr_list.IP_addrs;
		new_host->MAC_addrs=ptr_list.MAC_addrs;
		new_host->next = NULL;
		new_host->co_intface = NULL;

		if (j==0)
		{ ptr_elementInList1 = new_host;
		ptr_elementInList2 = new_host;
		}
		else
		{
			ptr_elementInList2->next = new_host;
			ptr_elementInList2 = new_host;
		}

		j=j+1;
	}

	fclose(ptr_file);    // closes the file
	return ptr_elementInList1;
		}

/**
 * @brief this function reads from a binary file a list of nodes (neighbors) used in testing
 * @param fileName is the name of the binary file
 */
void init_recordsARP(char *fileName){

	ptr_file =fopen(fileName,"r");  //open file

	if (!ptr_file)  // exit if file cannot open
		exit(0);

	ptr_neighbor_list = read_neighbor_list(fileName);  /**initialize the table from the file*/

}


/**@brief this function mimics ARP request from some neighbor within a network
 * @param IP_sender_addrs is the IP address of the neighbor which has sent a 'request'
 * @param MAC_sender_addrs is the MAC address of the neighbor
 * @param request_ARP_ptr is the pointer to the ARP message struct
 */
void mimic_net_request(uint32_t IP_sender_addrs, uint64_t MAC_sender_addrs,
		struct ARP_message *request_ARP_ptr)
{
	extern uint32_t interface_IP_addrs;

	request_ARP_ptr->hardware_type = HWDTYPE;
	request_ARP_ptr->protocol_type = PROTOCOLTYPE;
	request_ARP_ptr->hardware_addrs_length= HDWADDRSLEN ;
	request_ARP_ptr->protocol_addrs_length = PROTOCOLADDRSLEN;
	request_ARP_ptr->operation = ARPREQUESTOP;
	request_ARP_ptr->sender_MAC_addrs = MAC_sender_addrs;
	request_ARP_ptr->sender_IP_addrs = IP_sender_addrs;
	request_ARP_ptr->target_MAC_addrs = 0;
	request_ARP_ptr->target_IP_addrs = interface_IP_addrs;

}

/**Based on which host matches the ARP request an appropriate reply through a FINS frame is
 * created
 * @brief this function mimics a network response for an ARP request pushed via a FINS frame.
 * The purpose is to test the functionality of the code for the ARP module
 * @param request_ARP_ptr is the pointer to the ARP message struct request received by the 'nodes'
 * @param reply_ARP_ptr is the pointer to the ARP message struct reply given the appropriate node
 */
void mimic_net_reply(struct ARP_message *request_ARP_ptr, struct ARP_message *reply_ARP_ptr)
{
	struct node *ptr_elementInList;
	struct ARP_message reply_ARP;

	ptr_elementInList = ptr_neighbor_list;

	while (ptr_elementInList!=NULL )
	{
		if (ptr_elementInList->IP_addrs==request_ARP_ptr->target_IP_addrs)
		{
			reply_ARP.sender_IP_addrs = ptr_elementInList->IP_addrs;
			reply_ARP.sender_MAC_addrs = ptr_elementInList->MAC_addrs;
			reply_ARP.target_IP_addrs =request_ARP_ptr->sender_IP_addrs;
			reply_ARP.target_MAC_addrs = request_ARP_ptr->sender_MAC_addrs;
			reply_ARP.hardware_addrs_length = request_ARP_ptr->hardware_addrs_length;
			reply_ARP.hardware_type = request_ARP_ptr->hardware_type;
			reply_ARP.operation = ARPREPLYOP;
			reply_ARP.protocol_addrs_length=request_ARP_ptr->protocol_addrs_length;
			reply_ARP.protocol_type=request_ARP_ptr->protocol_type;

			memcpy(reply_ARP_ptr, &reply_ARP, sizeof(struct ARP_message));

		}
		ptr_elementInList = ptr_elementInList->next;
	}

}


/**@brief this function tests a set of functions which are used when
 * (1) a host receives an ARP request, and (2) keeps updating its cache based on
 * these ARP requests
 * @param fileName is the file from which the list of neighbors is drawn
 */
void send_receive_update(char *fileName)
{
	extern struct node *ptr_cacheHeader;
	struct finsFrame request_fins, reply_fins, *request_fins_ptr, *reply_fins_ptr;
	struct ARP_message request_ARP1, request_ARP2, reply_ARP1, reply_ARP2;
	struct ARP_message *request_ARP_ptr1, *request_ARP_ptr2, *reply_ARP_ptr1, *reply_ARP_ptr2;
	struct arp_hdr hdr_ARP, *hdr_ARP_ptr;
	uint64_t MAC_addrs;
	uint32_t IP_addrs_read;
	int task;

	/**Following code generates a list of IP/MAC addresses of 'neighbors' and initializes cache*/
	ptr_cacheHeader = init_intface();
	gen_neighbor_list(fileName);
	init_recordsARP(fileName);
	print_cache();
	print_neighbors(ptr_neighbor_list);
	hdr_ARP_ptr = &hdr_ARP;
	IP_addrs_read = 1;
	task = 1;

	/**Begin Initialize/Instantiate Pointers */
	request_fins_ptr = &request_fins;
	reply_fins_ptr = &reply_fins;
	request_ARP_ptr1 = &request_ARP1;
	request_ARP_ptr2 = &request_ARP2;
	reply_ARP_ptr1 = &reply_ARP1;
	reply_ARP_ptr2 = &reply_ARP2;

	/**A host can send update its cache based on its own request or a request from another network host*/
	while (IP_addrs_read!=0 && (task==0 || task == 1))
	{
		PRINT_DEBUG("\nTest send request and update `0' or test receive a request `1' \n");
		scanf("%d", &task);
		IP_addrs_read = read_IP_addrs();

		/**The following functions test the internal operations of the module*/
		if (task==0){

			gen_requestARP(IP_addrs_read, request_ARP_ptr1);
			print_msgARP(request_ARP_ptr1);
			arp_to_fins(request_ARP_ptr1, request_fins_ptr);
			fins_to_arp(request_fins_ptr, request_ARP_ptr2);
			mimic_net_reply(request_ARP_ptr2, reply_ARP_ptr1);

			if (check_valid_arp(reply_ARP_ptr1)==1){
			arp_to_fins(reply_ARP_ptr1, reply_fins_ptr);
			fins_to_arp(reply_fins_ptr, reply_ARP_ptr2);
			print_msgARP(reply_ARP_ptr2);
			update_cache(reply_ARP_ptr2);}

			print_cache();
		}
		else if (task==1){

			MAC_addrs = search_MAC_addrs(IP_addrs_read, ptr_neighbor_list);
			mimic_net_request(IP_addrs_read, MAC_addrs,request_ARP_ptr1);
			print_msgARP(request_ARP_ptr1);

			if (check_valid_arp(request_ARP_ptr1)==1){
			arp_to_fins(request_ARP_ptr1, request_fins_ptr);
			fins_to_arp(request_fins_ptr, request_ARP_ptr2);
			print_msgARP(request_ARP_ptr2);
			update_cache(request_ARP_ptr2);}

			print_cache();
		}

		/**The following functions test the external operation of the module*/

		if (check_valid_arp(request_ARP_ptr2)==1){
		hdr_ARP_ptr = &hdr_ARP;
		/**convert ARP message to htons format and generate MAC addresses as unsigned char ptr*/
		net_fmt_conversion(request_ARP_ptr2, hdr_ARP_ptr);
		print_arp_hdr(hdr_ARP_ptr);/**print some fields of the ARP message in external format*/
		host_fmt_conversion(hdr_ARP_ptr, request_ARP_ptr2);/**convert ARP message to ntohs format*/
		print_msgARP(request_ARP_ptr2);/**print ARP message internal format*/
		}

	}

	term_intface();
}


int main(int argc, char *argv[])
{
	IP_interface_set[0] = IPADDRESS;
	MAC_interface_set[0] = MACADDRESS;
	interface_MAC_addrs = MACADDRESS;
	interface_IP_addrs = IPADDRESS;

	send_receive_update(argv[1]); //ARP request/reply is received and cache is updated

	return 0;
}
