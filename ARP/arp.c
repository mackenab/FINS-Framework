/**@file arp.c
 *@brief this files contains all relevant functions to execute an ARP module,
 *@brief IP and MAC address of the host is provided by the main
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */

#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"
#include "arp.h"
#include "finsdebug.h"
#include "metadata.h"

#define DEBUG

struct node *ptr_cacheHeader; /**< points to the first element of the dynamic ARP cache*/

/**
 * An address like a.b.c.d (e.g. 5.45.0.07 where a= 5, b=45, c=0,d=7) is converted an integer
 * @brief this function takes a user defined address and produces a uint32 address
 * @param a an octet
 * @param b an octet
 * @param c an octet
 * @param d an octet
 */
uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{	return (16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d));
}

/**
 * An address like a:b:c:d:e:f is converted into an 64-byte unsigned integer
 * @brief this function takes a user provided MAC address as a set of octets and produces a uint64 address
 * @param a an octet
 * @param b an octet
 * @param c an octet
 * @param d an octet
 * @param e an octetvoid init_recordsARP(char *fileName);*/

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f)
{return (109951162800ull*(a)+ 4294967296ull*(b) + 16777216ull*(c) + 65536ull*(d) + (256ull*(e)) + (f));
}

/**
 * @brief this function prints IP address in a human readable format
 * @param IP_addrs is the uint32 address
 */
void print_IP_addrs(uint32_t IP_addrs)
{
	uint8_t a, b, c, d; /**<a,b,c,d are octets of an IP address (e.g. a.b.c.d)*/

	a = IP_addrs/(16777216);
	b = (IP_addrs - a*16777216)/65536;
	c = (IP_addrs - a*16777216 - b*65536)/(256);
	d = (IP_addrs - a*16777216 - b*(256*256) -c*256);
	PRINT_DEBUG("IP address = %u.%u.%u.%u ",a,b,c,d);

}

/**
 * @brief this function prints a MAC address in a readable format
 * @param IP_addrs is the uint64 address (although a 48-byte address is used in practice
 */
void print_MAC_addrs(uint64_t MAC_addrs)
{PRINT_DEBUG("MAC address = %llx", MAC_addrs);
}

/**
 * @brief this function produces an ARP request for a host whose IP address is known
 * @param IP_address_target is the uint32 address of the target host
 */
void gen_requestARP(uint32_t IP_address_target, struct ARP_message *request_ARP_ptr)
{
	//	struct ARP_message request_ARP;

	extern uint64_t interface_MAC_addrs;
	extern uint32_t interface_IP_addrs;

	request_ARP_ptr->sender_MAC_addrs = interface_MAC_addrs;
	request_ARP_ptr->sender_IP_addrs = interface_IP_addrs;
	request_ARP_ptr->target_MAC_addrs = NULLADDRESS;
	request_ARP_ptr->target_IP_addrs = IP_address_target;
	request_ARP_ptr->hardware_type = HWDTYPE;
	request_ARP_ptr->protocol_type = PROTOCOLTYPE;
	request_ARP_ptr->hardware_addrs_length= HDWADDRSLEN ;
	request_ARP_ptr->protocol_addrs_length = PROTOCOLADDRSLEN;
	request_ARP_ptr->operation = ARPREQUESTOP;

}

/**
 * @brief this function produces an ARP reply for the host which has already sent
 * a request for a MAC address
 * @param request_ARP is the ARP request from the host
 */
struct ARP_message gen_replyARP(struct ARP_message request_ARP)
{
	struct ARP_message reply_ARP;

	extern uint64_t interface_MAC_addrs;
	extern uint32_t interface_IP_addrs;

	reply_ARP.sender_MAC_addrs = interface_MAC_addrs;
	reply_ARP.sender_IP_addrs = interface_IP_addrs;
	reply_ARP.target_MAC_addrs = request_ARP.sender_MAC_addrs;
	reply_ARP.target_IP_addrs = request_ARP.sender_IP_addrs;
	reply_ARP.hardware_type = HWDTYPE;
	reply_ARP.protocol_type = PROTOCOLTYPE;
	reply_ARP.hardware_addrs_length= HDWADDRSLEN;
	reply_ARP.protocol_addrs_length = PROTOCOLADDRSLEN;
	reply_ARP.operation = ARPREPLYOP;

	return reply_ARP;
}

/**
 * @brief this function searches a list or cache for to check if it contains a
 * particular MAC address, returns 1 if found else returns 0
 * @param ptr_intface_cache is the pointer to the first element of the cache
 * @param MAC_addrs is the searched MAC address from the cache
 */
int search_list(struct node *ptr_firstElementOfList, uint64_t MAC_addrs)
{
	struct node *ptr_elementInList;
	int found = 0;

	ptr_elementInList = ptr_firstElementOfList;

	while (ptr_elementInList!=NULL)
	{

		if (ptr_elementInList->MAC_addrs == MAC_addrs )
			found = 1;

		ptr_elementInList = ptr_elementInList->next;
	}

	return found;
}

/** * ptr_cacheHeader is the pointer to the first element of the cache
 * @brief this function updates a cache based on an ARP reply
 * @param pckt_ARP is an ARP message (either reply or request) from some host within the neighborhood
 */
void update_cache(struct ARP_message *pckt)
{
	int found = 0;
	struct node *ptr_interfaceHeader, *ptr_elementInList;/**these variables are used to traverse the linked list structure of cache*/
	struct ARP_message *pckt_ARP;

	pckt_ARP = pckt;
	/**update cache is performed only is the received arp message pointer is not null*/
	if (check_valid_arp(pckt_ARP)==1)
	{

		/**cache header is a node which has information about the interface of
		 * the host itself. It links via 'next' pointer to the node containing addresses of
		 * a neighbor. Each subsequent neighbor is linked via this pointer
		 * */
		ptr_interfaceHeader = ptr_cacheHeader;

		while (ptr_interfaceHeader!=NULL)
		{
			/**point pointer to the list/cache header*/
			ptr_elementInList = ptr_interfaceHeader;
			/**returns 1 if found, else 0*/
			found = search_list(ptr_elementInList, pckt_ARP->sender_MAC_addrs);
			/**check for all of host's interfaces though not used in current version*/
			ptr_interfaceHeader = ptr_interfaceHeader->co_intface;
		}

		/**the received ARP message must be from a neighbor which is not currently known to host*/
		ptr_interfaceHeader = ptr_cacheHeader;

		while (ptr_interfaceHeader!=NULL && found==0)
		{
			if (pckt_ARP->target_IP_addrs!=NULLADDRESS && pckt_ARP->sender_MAC_addrs!=NULLADDRESS && pckt_ARP->sender_IP_addrs!=NULLADDRESS)
			{
				/**If the ARP module is a valid sender and contains information about a new neighbor add it to cache
				 * Store the new information as a new node and which will point to the current
				 * list of neighbors. The cache header point towards this new node
				 * Thus new node is added at the top of the list
				 * */
				struct node *new_host = malloc(sizeof(struct node));
				new_host->next = NULL;
				new_host->IP_addrs = pckt_ARP->sender_IP_addrs;
				new_host->MAC_addrs = pckt_ARP->sender_MAC_addrs;
				new_host->next = ptr_interfaceHeader->next;
				ptr_interfaceHeader->next = new_host;
			}
			ptr_interfaceHeader = ptr_interfaceHeader->co_intface;
		}

	}
}

/**
 * @brief for a given ARP message this function prints the IP and MAC addresses
 * of the sender and the target
 * @param pckt is the ARP request or reply which has been generated by a host
 */
void print_msgARP(struct ARP_message *pckt){

	if (pckt->operation == ARPREQUESTOP)
		PRINT_DEBUG("\nARP Message Request");
	if (pckt->operation == ARPREPLYOP)
		PRINT_DEBUG("\nARP Message Reply");

	PRINT_DEBUG("\nSender:");
	print_IP_addrs(pckt->sender_IP_addrs);
	print_MAC_addrs(pckt->sender_MAC_addrs);
	PRINT_DEBUG("\n Hardware Address Length : %u",pckt->hardware_addrs_length);
	PRINT_DEBUG("\n Hardware Type : %d",pckt->hardware_type);
	PRINT_DEBUG("\n Protocol Address Length : %u",pckt->protocol_addrs_length);
	PRINT_DEBUG("\n Protocol Type : %d",pckt->protocol_type);
	PRINT_DEBUG("\n Operation Type : %d",pckt->operation);
	PRINT_DEBUG("\nTarget:");
	print_IP_addrs(pckt->target_IP_addrs);
	print_MAC_addrs(pckt->target_MAC_addrs);

}

void print_arp_hdr(struct arp_hdr *pckt){

	int i;
	unsigned char sender[6], target[6];

	PRINT_DEBUG("Printing of an external format arp message the\n");

	addrs_conversion(pckt->arp.sender_MAC_addrs, &sender[0]);
	addrs_conversion(pckt->arp.target_MAC_addrs, &target[0]);

	PRINT_DEBUG("Sender hardware (MAC) address = ");
	for (i=HDWADDRSLEN-1;i>-1;i--)
		PRINT_DEBUG("%x", sender[i]);

	PRINT_DEBUG("\nTarget hardware (MAC) address= ");
	for (i=HDWADDRSLEN-1;i>-1;i--)
		PRINT_DEBUG("%x", target[i]);

	PRINT_DEBUG("\nHardware type: %d", pckt->arp.hardware_type);
	PRINT_DEBUG("\nProtocol type: %d\n", pckt->arp.protocol_type);
}

/**
 * @brief this function prints the contents of a cache for each of the interfaces
 * ptr_cacheHeader points to the first element/header of the cache
 */
void print_cache(){

	struct node *ptr_interfaceHeader, *ptr_elementInList;

	ptr_elementInList = ptr_cacheHeader;
	ptr_interfaceHeader = ptr_cacheHeader;

	while (ptr_interfaceHeader!=NULL){

		PRINT_DEBUG("\nHost Interface IP Address:");
		print_IP_addrs(ptr_interfaceHeader->IP_addrs);
		ptr_elementInList = ptr_elementInList->next; //move the pointer to the stored node
		print_neighbors(ptr_elementInList);
		ptr_interfaceHeader = ptr_interfaceHeader->co_intface;
		ptr_elementInList = ptr_interfaceHeader;
	}
	PRINT_DEBUG("\n\n");
}

/**
 * @brief this function prints the list of addresses of a host's neighbors
 * (useful in testing/mimicing network response)
 * @param ptr_neighbors points to the first element of the list of 'neighbors'
 */
void print_neighbors(struct node *ptr_list_neighbors){

	struct node *ptr_elementInList;

	ptr_elementInList = ptr_list_neighbors;
	PRINT_DEBUG("\n\nList of addresses of neighbors:\n");

	while (ptr_elementInList!=NULL){
		print_IP_addrs(ptr_elementInList->IP_addrs);
		print_MAC_addrs(ptr_elementInList->MAC_addrs);
		PRINT_DEBUG("\n");
		ptr_elementInList = ptr_elementInList->next;
	}
}

/**
 * @brief this function searches for a MAC address from a list of addresses of neighbors
 * where each neighbor has an IP and a MAC address
 * @param IP_addrs is the searched address
 * @param list points to the first element of the list of neighbors
 */
uint64_t search_MAC_addrs(uint32_t IP_addrs, struct node *ptr_list_neighbors)
{
	uint64_t MAC_addrs = NULLADDRESS;
	struct node *ptr_elementInList = ptr_list_neighbors;

	while (ptr_elementInList!=NULL)
	{
		if (IP_addrs == ptr_elementInList->IP_addrs)
			MAC_addrs = ptr_elementInList->MAC_addrs;

		ptr_elementInList = ptr_elementInList->next;

	}
	return MAC_addrs;
}

/**
 * @brief this function converts an ARP message into a FINS frame
 * @param reply_ARP is a pointer to an ARP message struct which is type cast as a PDU
 * of a data FINS frame
 */
void arp_to_fins(struct ARP_message *pckt_arp, struct finsFrame *pckt_fins)
{
	pckt_fins->dataOrCtrl = DATA;
	pckt_fins->dataFrame.pdu = (unsigned char *)(pckt_arp);

	if (pckt_arp->operation == ARPREQUESTOP) //request
	{
		pckt_fins->destinationID.id = (unsigned char) ETHERSTUBID; //to be sent to the ethernet
		pckt_fins->dataFrame.directionFlag= DOWN;
		pckt_fins->dataFrame.pduLength = sizeof(struct ARP_message);
	}

	else if (pckt_arp->operation == ARPREPLYOP) //reply
	{
		pckt_fins->destinationID.id = (unsigned char) ARPID; //to be sent to the ethernet
		pckt_fins->dataFrame.directionFlag= UP;
		pckt_fins->dataFrame.pduLength = sizeof(struct ARP_message);
	}
	else
	{
		PRINT_DEBUG("\nError: Invalid message or non-existent neighbor returning NULL\n");
	}
}

/**
 * @brief this function converts a FINS frame into an ARP message
 * @param pckt_fins is a FINS data frame whose pdu contains the address of an ARP message struct
 * @param reply_ARP is an 'empty' ARP message which will be be filled by the contents pointed to by the FINS frame's pdu
 */
void fins_to_arp(struct finsFrame *pckt_fins, struct ARP_message *pckt_arp){

	memcpy(pckt_arp,  pckt_fins->dataFrame.pdu, pckt_fins->dataFrame.pduLength );
}

/**
 * @brief this function initializes a cache for the host's interface.
 * @brief Note that an interface is the first element/header of
 * a linked list of neighbors' which are represented as nodes and the
 * 'co-intface' pointer is used to link multiple interfaces (not used in current version)
 * each neighbor is linked to the next neighbor via the 'next' pointer
 */
struct node* init_intface()
		{
	int i;
	struct node *ptr_elementInList1, *ptr_elementInList2; /**<temporary variables*/

	extern int INTERFACECOUNT;	/**<indicates the number of interfaces of the host (e.g. 1)*/
	extern uint32_t IP_interface_set[1];/**<stores the IP addresses of all interfaces*/
	extern uint64_t MAC_interface_set[1];/**<stores the MAC addresses of all interfaces*/

	PRINT_DEBUG("\nInitializing ARP cache\n");
	fflush(stdout);

	for (i=0;i<INTERFACECOUNT;i++){

		struct node *intface = malloc(sizeof(struct node));

		intface->IP_addrs = IP_interface_set[i];
		intface->MAC_addrs = MAC_interface_set[i];
		intface->co_intface=NULL;
		intface->next = NULL;


		if (i==0){
			ptr_elementInList1 = intface;
			ptr_elementInList2 = intface;
		}
		else{
			ptr_elementInList2->co_intface = intface;
			ptr_elementInList2 = intface;

		}
	}
	return ptr_elementInList1;
		}

/**
 * @brief this function liberates all memory allocated to store and represent the cache
 * for the ARP module */
void term_intface()
{
	struct node *ptr_elementInList1, *ptr_elementInList2, *ptr_elementInList3;

	ptr_elementInList1 = ptr_cacheHeader;
	ptr_elementInList2 = ptr_cacheHeader;
	ptr_elementInList2 = ptr_cacheHeader;

	PRINT_DEBUG("\nFreeing memory of ARP cache\n");

	while (ptr_elementInList1!=NULL){

		ptr_elementInList2 = ptr_elementInList1->next;
		ptr_elementInList3 = ptr_elementInList2;

		while (ptr_elementInList2!=NULL){

			ptr_elementInList3 = ptr_elementInList2;
			ptr_elementInList2 = ptr_elementInList2->next;

			free(ptr_elementInList3);
		}
		ptr_elementInList2 = ptr_elementInList1->co_intface;
		free(ptr_elementInList1);
		ptr_elementInList1 = ptr_elementInList2;
	}
}

/**
 * @brief converts 6-byte MAC address (stored as unsigned 64-bit int)
 * into a representable 6-byte char array
 * @param MAC_int_addrs is the address in unsigned int 64 bits
 * @param *MAC_char_addrs points to the character array which will store the converted address
 *  */

void addrs_conversion(uint64_t MAC_int_addrs, unsigned char *MAC_char_addrs){

	int i;

	/**register shifting is used to extract individual bytes in the code below*/

	for (i=0;i<6;i++)
	{
		if (i==0)
			MAC_char_addrs[i] = (unsigned char) ((MAC_int_addrs & (0x00000000000000FF)));
		else if (i==1)
			MAC_char_addrs[i] = (unsigned char) ((MAC_int_addrs & (0x000000000000FF00))>>8);
		else if (i==2)
			MAC_char_addrs[i] =  (unsigned char) ((MAC_int_addrs & (0x0000000000FF0000))>>16);
		else if (i==3)
			MAC_char_addrs[i] = (unsigned char) ((MAC_int_addrs & (0x00000000FF000000))>>24);
		else if (i==4)
			MAC_char_addrs[i] = (unsigned char) ((MAC_int_addrs & (0x00000000FF00000000))>>32);
		else if (i==5)
			MAC_char_addrs[i] = (unsigned char) ((MAC_int_addrs & (0x00FF0000000000))>>40);
	}

}


/**
 * @brief converts an internal ARP message into a representable ARP message which
 * the OS can use
 * @param pckt points to the internal ARP message
 * @param pckt_hdr points to the ARP message which can be sent outside the module
 */
void net_fmt_conversion(struct ARP_message *pckt, struct arp_hdr *pckt_hdr){

	memcpy(&(pckt_hdr->arp), pckt, sizeof(struct ARP_message));
	pckt_hdr->arp.protocol_type = htons(pckt_hdr->arp.protocol_type);/**little endien to big endien*/
	pckt_hdr->arp.hardware_type = htons(pckt_hdr->arp.hardware_type);
	addrs_conversion(pckt->target_MAC_addrs, pckt_hdr->tgt_hwd_addrs);
	addrs_conversion(pckt->sender_MAC_addrs, pckt_hdr->src_hwd_addrs);
}


/**
 * @brief converts an external ARP message into a representable ARP message which
 * the ARP module can use
 * @param pckt_hdr points to the ARP message which can be sent outside the module
 *  * @param pckt points to the internal ARP message
 * *  *  */
void host_fmt_conversion(struct arp_hdr *pckt_hdr, struct ARP_message *pckt){

	memcpy(pckt, &(pckt_hdr->arp), sizeof(struct ARP_message));
	pckt->protocol_type = ntohs(pckt_hdr->arp.protocol_type);/**big endien to little endien*/
	pckt->hardware_type = ntohs(pckt_hdr->arp.hardware_type);
}

/**
 * @brief simply checks whether a received ARP message is valid or not
 * @param pckt_arp points to the ARP message
 */
int check_valid_arp(struct ARP_message *pckt_arp){

	struct ARP_message *pckt;
	pckt = pckt_arp;

	if (pckt!=NULL)
		if (pckt->hardware_type==HWDTYPE)
			if(pckt->operation==ARPREQUESTOP || pckt->operation==ARPREPLYOP)
				if(pckt->hardware_addrs_length==HDWADDRSLEN)
					if(pckt->protocol_addrs_length==PROTOCOLADDRSLEN)
						if(pckt->protocol_type==PROTOCOLTYPE)
							return 1;
						else
							return 0;
					else
						return 0;
				else
					return 0;
			else
				return 0;
		else
			return 0;

	else
		return 0;
}
