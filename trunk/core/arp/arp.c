/**@file arp.c
 *@brief this files contains all relevant functions to execute an ARP module,
 *@brief IP and MAC address of the host is provided by the main
 *@author Syed Amaar Ahmad
 *@date  September 27, 2010
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "arp.h"

int arp_running;
extern sem_t ARP_to_Switch_Qsem;
extern finsQueue ARP_to_Switch_Queue;

extern sem_t Switch_to_ARP_Qsem;
extern finsQueue Switch_to_ARP_Queue;

//struct udp_statistics arpStat;

//#define DEBUG

/**
 * An address like a.b.c.d (e.g. 5.45.0.07 where a= 5, b=45, c=0,d=7) is converted an integer
 * @brief this function takes a user defined address and produces a uint32 address
 * @param a an octet (most significant)
 * @param b an octet
 * @param c an octet
 * @param d an octet (least significant)
 */
uint32_t gen_IP_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
	return (16777216ul * (a) + (65536ul * (b)) + (256ul * (c)) + (d));
}

/**
 * An address like a:b:c:d:e:f is converted into an 64-byte unsigned integer
 * @brief this function takes a user provided MAC address as a set of octets and produces a uint64 address
 * @param a an octet (most significant)
 * @param b an octet
 * @param c an octet
 * @param d an octet
 * @param e an octet
 * @parm f an octet (least significant)*/

uint64_t gen_MAC_addrs(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
	return 1099511627776ull * (a) + 4294967296ull * (b) + 16777216ull * (c) + 65536ull * (d) + (256ull * (e)) + (f);
}

/**
 * @brief this function prints IP address in a human readable format
 * @param IP_addrs is the uint32 address
 */
void print_IP_addrs(uint32_t IP_addrs) {
	uint8_t a, b, c, d; /**<a,b,c,d are octets of an IP address (e.g. a.b.c.d)*/

	a = IP_addrs / (16777216);
	b = (IP_addrs - a * 16777216) / 65536;
	c = (IP_addrs - a * 16777216 - b * 65536) / (256);
	d = (IP_addrs - a * 16777216 - b * (256 * 256) - c * 256);
	PRINT_DEBUG("IP address = %u.%u.%u.%u ", a, b, c, d);

}

/**
 * @brief this function prints a MAC address in a readable format
 * @param IP_addrs is the uint64 address (although a 48-byte address is used in practice
 */
void print_MAC_addrs(uint64_t MAC_intg_addrs) {
	PRINT_DEBUG("MAC address = %llx", MAC_intg_addrs);
}

/**
 * @brief this function produces an ARP request for a host whose IP address is known
 * @param IP_address_target is the uint32 address of the target host
 */
void gen_requestARP(uint32_t IP_address_target, struct arp_message *request_ARP_ptr) {
	request_ARP_ptr->sender_MAC_addrs = interface_MAC_addrs;
	request_ARP_ptr->sender_IP_addrs = interface_IP_addrs;
	request_ARP_ptr->target_MAC_addrs = NULLADDRESS;
	request_ARP_ptr->target_IP_addrs = IP_address_target;
	request_ARP_ptr->hardware_type = HWDTYPE;
	request_ARP_ptr->protocol_type = PROTOCOLTYPE;
	request_ARP_ptr->hardware_addrs_length = HDWADDRSLEN;
	request_ARP_ptr->protocol_addrs_length = PROTOCOLADDRSLEN;
	request_ARP_ptr->operation = ARP_OP_REQUEST;
}

void gen_requestARP_new(struct arp_message *request_ARP_ptr, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip) {
	request_ARP_ptr->sender_MAC_addrs = sender_mac;
	request_ARP_ptr->sender_IP_addrs = sender_ip;
	request_ARP_ptr->target_MAC_addrs = target_mac;
	request_ARP_ptr->target_IP_addrs = target_ip;

	request_ARP_ptr->hardware_type = HWDTYPE;
	request_ARP_ptr->protocol_type = PROTOCOLTYPE;
	request_ARP_ptr->hardware_addrs_length = HDWADDRSLEN;
	request_ARP_ptr->protocol_addrs_length = PROTOCOLADDRSLEN;
	request_ARP_ptr->operation = ARP_OP_REQUEST;
}

/**
 * @brief this function produces an ARP reply for the host which has already sent
 * a request for a MAC address
 * @param request_ARP is the ARP request
 * @param reply_ARP is the pointer to the
 */
void gen_replyARP(struct arp_message *request_ARP, struct arp_message *reply_ARP) {
	/**generate reply only if the request is intended for the host*/
	//if ((request_ARP->target_IP_addrs == interface_IP_addrs) && (request_ARP->target_MAC_addrs == NULLADDRESS)) {
	reply_ARP->sender_MAC_addrs = interface_MAC_addrs;
	reply_ARP->sender_IP_addrs = interface_IP_addrs;
	reply_ARP->target_MAC_addrs = request_ARP->sender_MAC_addrs;
	reply_ARP->target_IP_addrs = request_ARP->sender_IP_addrs;
	reply_ARP->hardware_type = HWDTYPE;
	reply_ARP->protocol_type = PROTOCOLTYPE;
	reply_ARP->hardware_addrs_length = HDWADDRSLEN;
	reply_ARP->protocol_addrs_length = PROTOCOLADDRSLEN;
	reply_ARP->operation = ARP_OP_REPLY;
	//}
}

void gen_replyARP_new(struct arp_message *reply_ARP, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip) {
	/**generate reply only if the request is intended for the host*/
	reply_ARP->sender_MAC_addrs = sender_mac;
	reply_ARP->sender_IP_addrs = sender_ip;
	reply_ARP->target_MAC_addrs = target_mac;
	reply_ARP->target_IP_addrs = target_ip;

	reply_ARP->hardware_type = HWDTYPE;
	reply_ARP->protocol_type = PROTOCOLTYPE;
	reply_ARP->hardware_addrs_length = HDWADDRSLEN;
	reply_ARP->protocol_addrs_length = PROTOCOLADDRSLEN;
	reply_ARP->operation = ARP_OP_REPLY;
}

/**
 * @brief this function searches a list or cache for to check if it contains a
 * particular MAC address, returns 1 if found else returns 0
 * @param ptr_intface_cache is the pointer to the first element of the cache
 * @param MAC_addrs is the searched MAC address from the cache
 */
int search_list(struct arp_node *ptr_firstElementOfList, uint32_t IP_addrs) {
	struct arp_node *ptr_elementInList;
	int found = 0;

	ptr_elementInList = ptr_firstElementOfList;

	while (ptr_elementInList != NULL) {

		if ((ptr_elementInList->IP_addrs == IP_addrs) && (ptr_elementInList->MAC_addrs != NULLADDRESS))
			found = 1;

		ptr_elementInList = ptr_elementInList->next;
	}

	return found;
}

struct arp_node *search_list_new(struct arp_node *head, uint32_t IP_addrs) {
	struct arp_node *temp;

	temp = head;
	while (temp != NULL) {
		if (temp->IP_addrs == IP_addrs) {
			break;
		}
		temp = temp->next;
	}

	return temp;
}

/** * ptr_cacheHeader is the pointer to the first element of the cache
 * @brief this function updates a cache based on an ARP message
 * @param pckt_ARP is an ARP message (either reply or request) from some host within the neighborhood
 */
void update_cache(struct arp_message *pckt) {
	int found = 0;
	struct arp_node *ptr_interfaceHeader;/**these variables are used to traverse the linked list structure of cache*/
	struct arp_message *pckt_ARP;

	pckt_ARP = pckt;
	/**update cache is performed only is the received arp message pointer is not null*/
	if (check_valid_arp(pckt_ARP) == 1) {
		/**cache header is a node which has information about the interface of
		 * the host itself. It links via 'next' pointer to the node containing addresses of
		 * a neighbor. Each subsequent neighbor is linked via this pointer
		 *
		 * */
		ptr_interfaceHeader = cache_list;

		/**returns 1 if found, else 0*/
		found = search_list(ptr_interfaceHeader, pckt_ARP->sender_IP_addrs);
		/**the received ARP message must be from a neighbor which is not currently known to host*/
		ptr_interfaceHeader = cache_list;

		if (found == 0) {
			/**If the ARP module is a valid sender and contains information about a new neighbor add it to cache
			 * Store the new information as a new node and which will point to the current
			 * list of neighbors. The cache header point towards this new node
			 * Thus new node is added at the top of the list
			 * */
			struct arp_node *new_host = (struct arp_node *) malloc(sizeof(struct arp_node));
			new_host->next = NULL;
			new_host->IP_addrs = pckt_ARP->sender_IP_addrs;
			new_host->MAC_addrs = pckt_ARP->sender_MAC_addrs;
			new_host->next = ptr_interfaceHeader->next;
			ptr_interfaceHeader->next = new_host;
		}
	}
}

void update_cache_new(struct arp_message *pckt) {
	int found = 0;
	struct arp_node *ptr_interfaceHeader;/**these variables are used to traverse the linked list structure of cache*/
	struct arp_message *pckt_ARP;

	pckt_ARP = pckt;
	/**update cache is performed only is the received arp message pointer is not null*/
	if (check_valid_arp(pckt_ARP) == 1) {
		/**cache header is a node which has information about the interface of
		 * the host itself. It links via 'next' pointer to the node containing addresses of
		 * a neighbor. Each subsequent neighbor is linked via this pointer
		 *
		 * */
		ptr_interfaceHeader = cache_list;

		/**returns 1 if found, else 0*/
		found = search_list(ptr_interfaceHeader, pckt_ARP->sender_IP_addrs);
		/**the received ARP message must be from a neighbor which is not currently known to host*/
		ptr_interfaceHeader = cache_list;

		if (found == 0) {
			/**If the ARP module is a valid sender and contains information about a new neighbor add it to cache
			 * Store the new information as a new node and which will point to the current
			 * list of neighbors. The cache header point towards this new node
			 * Thus new node is added at the top of the list
			 * */
			struct arp_node *new_host = (struct arp_node *) malloc(sizeof(struct arp_node));
			new_host->next = NULL;
			new_host->IP_addrs = pckt_ARP->sender_IP_addrs;
			new_host->MAC_addrs = pckt_ARP->sender_MAC_addrs;
			new_host->next = ptr_interfaceHeader->next;
			ptr_interfaceHeader->next = new_host;
		}
	}
}

/**
 * @brief for a given ARP message this function prints the IP and MAC addresses
 * of the sender and the target
 * @param pckt is the ARP request or reply which has been generated by a host
 */
void print_msgARP(struct arp_message *msg) {

	if (msg->operation == ARP_OP_REQUEST)
		PRINT_DEBUG("ARP Message Request");
	if (msg->operation == ARP_OP_REPLY)
		PRINT_DEBUG("ARP Message Reply");

	PRINT_DEBUG("Sender:");
	print_IP_addrs(msg->sender_IP_addrs);
	print_MAC_addrs(msg->sender_MAC_addrs);
	PRINT_DEBUG("Hardware Address Length : %u", msg->hardware_addrs_length);
	PRINT_DEBUG("Hardware Type : %d", msg->hardware_type);
	PRINT_DEBUG("Protocol Address Length : %u", msg->protocol_addrs_length);
	PRINT_DEBUG("Protocol Type : %d", msg->protocol_type);
	PRINT_DEBUG("Operation Type : %d", msg->operation);
	PRINT_DEBUG("Target:");
	print_IP_addrs(msg->target_IP_addrs);
	print_MAC_addrs(msg->target_MAC_addrs);

}

void print_arp_hdr(struct arp_hdr *pckt) {

	int i;

	PRINT_DEBUG("\n\nPrinting of an external format arp message");
	PRINT_DEBUG("\nSender hardware (MAC) address = ");
	for (i = 0; i < HDWADDRSLEN; i++)
		PRINT_DEBUG("%x:", pckt->sender_MAC_addrs[i]);
	PRINT_DEBUG("\nSender IP address = ");
	for (i = 0; i < PROTOCOLADDRSLEN; i++)
		PRINT_DEBUG("%d.", pckt->sender_IP_addrs[i]);
	PRINT_DEBUG("\nTarget hardware (MAC) address= ");
	for (i = 0; i < HDWADDRSLEN; i++)
		PRINT_DEBUG("%x:", pckt->target_MAC_addrs[i]);
	PRINT_DEBUG("\nTarget IP address = ");
	for (i = 0; i < PROTOCOLADDRSLEN; i++)
		PRINT_DEBUG("%d.", pckt->target_IP_addrs[i]);
	PRINT_DEBUG("\nHardware type: %d", pckt->hardware_type);
	PRINT_DEBUG("\nProtocol type: %d", pckt->protocol_type);
	PRINT_DEBUG("\nHardware length: %d", pckt->hardware_addrs_length);
	PRINT_DEBUG("\nHardware length: %d", pckt->protocol_addrs_length);
	PRINT_DEBUG("\nOperation: %d\n\n", pckt->operation);
}

/**
 * @brief this function prints the contents of a cache for each of the interfaces
 * ptr_cacheHeader points to the first element/header of the cache
 */
void print_cache() {

	struct arp_node *ptr_elementInList;

	PRINT_DEBUG("\nHost Interface:");
	ptr_elementInList = cache_list;
	print_IP_addrs(ptr_elementInList->IP_addrs);
	print_MAC_addrs(ptr_elementInList->MAC_addrs);
	ptr_elementInList = ptr_elementInList->next; //move the pointer to the stored node
	print_neighbors(ptr_elementInList);
	PRINT_DEBUG("\n\n");
}

/**
 * @brief this function prints the list of addresses of a host's neighbors
 * (useful in testing/mimicing network response)
 * @param ptr_neighbors points to the first element of the list of 'neighbors'
 */
void print_neighbors(struct arp_node *ptr_list_neighbors) {

	struct arp_node *ptr_elementInList;

	ptr_elementInList = ptr_list_neighbors;
	PRINT_DEBUG("\nList of addresses of neighbors:\n");

	while (ptr_elementInList != NULL) {
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
uint64_t search_MAC_addrs(uint32_t IP_addrs, struct arp_node *ptr_list_neighbors) {
	uint64_t MAC_addrs = NULLADDRESS;
	struct arp_node *ptr_elementInList = ptr_list_neighbors;

	while (ptr_elementInList != NULL) {
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
void arp_to_fins(struct arp_hdr *pckt_arp, struct finsFrame *pckt_fins) {
	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("failed to create matadata: ff=%p", pckt_fins);
		return;
	}
	metadata_create(params);

	//metadata_writeToElement(params, "src_ip", (uint32_t *) pckt_arp->sender_MAC_addrs, META_TYPE_INT);
	//metadata_writeToElement(params, "dst_ip", (uint32_t *) pckt_arp->target_IP_addrs, META_TYPE_INT);
	//metadata_writeToElement(params, "src_mac", pckt_arp->sender_MAC_addrs, META_TYPE_STRING) ;
	//metadata_writeToElement(params, "dst_mac", pckt_arp->target_MAC_addrs, META_TYPE_STRING) ;

	uint32_t type = (uint32_t) ARP_TYPE;
	metadata_writeToElement(params, "ether_type", &type, META_TYPE_INT);

	pckt_fins->destinationID.id = ETHERSTUBID;
	pckt_fins->dataOrCtrl = DATA;
	pckt_fins->dataFrame.pdu = (unsigned char *) pckt_arp;
	pckt_fins->dataFrame.directionFlag = DOWN;
	pckt_fins->dataFrame.pduLength = sizeof(struct arp_hdr);
	pckt_fins->metaData = params;
}

/**
 * @brief this function converts a FINS frame into an ARP message
 * @param pckt_fins is a FINS data frame whose pdu contains the address of an ARP message struct
 * @param reply_ARP is an 'empty' ARP message which will be be filled by the contents pointed to by the FINS frame's pdu
 */
void fins_to_arp(struct finsFrame *pckt_fins, struct arp_hdr *pckt_arp) {

	//memcpy(pckt_arp, pckt_fins->dataFrame.pdu, pckt_fins->dataFrame.pduLength);
	memcpy(pckt_arp, pckt_fins->dataFrame.pdu, sizeof(struct arp_hdr));

}

/**
 * @brief converts 6-byte MAC address (stored as unsigned 64-bit int)
 * into a representable 6-byte char array
 * @param int_addrs is the address in unsigned int 64
 * @param *char_addrs points to the character array which will store the converted address
 *  */
/**register shifting is used to extract individual bytes in the code below*/
void MAC_addrs_conversion(uint64_t int_addrs, unsigned char *char_addrs) {
	char_addrs[5] = (unsigned char) ((int_addrs & (0x00000000000000FF))); //least sig.
	char_addrs[4] = (unsigned char) ((int_addrs & (0x000000000000FF00)) >> 8);
	char_addrs[3] = (unsigned char) ((int_addrs & (0x0000000000FF0000)) >> 16);
	char_addrs[2] = (unsigned char) ((int_addrs & (0x00000000FF000000)) >> 24);
	char_addrs[1] = (unsigned char) ((int_addrs & (0x000000FF00000000)) >> 32);
	char_addrs[0] = (unsigned char) ((int_addrs & (0x0000FF0000000000)) >> 40); //most sig.
}

/**
 * @brief converts 4-byte IP address (stored as unsigned 32-bit int)
 * into a representable 4-byte char array
 * @param int_addrs is the address in unsigned int 32
 * @param *char_addrs points to the character array which will store the converted address
 *  */
void IP_addrs_conversion(uint32_t int_addrs, unsigned char *char_addrs) {
	/**register shifting is used to extract individual bytes in the code below*/
	char_addrs[3] = (unsigned char) ((int_addrs & (0x000000FF))); //least significant
	char_addrs[2] = (unsigned char) ((int_addrs & (0x0000FF00)) >> 8);
	char_addrs[1] = (unsigned char) ((int_addrs & (0x00FF0000)) >> 16);
	char_addrs[0] = (unsigned char) ((int_addrs & (0xFF000000)) >> 24); //most significant
}

/**
 * @brief converts an arp header into a representable format (endien/address format)
 * immediately receiving it after or before sending it outside the arp module
 * @param pckt_hdr points to the arp header
 */
void host_to_net(struct arp_hdr *pckt_hdr) {

	pckt_hdr->protocol_type = htons(pckt_hdr->protocol_type);
	pckt_hdr->hardware_type = htons(pckt_hdr->hardware_type);
	pckt_hdr->operation = htons(pckt_hdr->operation);
}

/**
 * @brief simply checks whether a received ARP message is valid or not
 * @param pckt_arp points to the ARP message
 */
int check_valid_arp(struct arp_message *msg) {

	return (msg->hardware_type == HWDTYPE) && (msg->operation == ARP_OP_REQUEST || msg->operation == ARP_OP_REPLY) && (msg->hardware_addrs_length
			== HDWADDRSLEN) && (msg->protocol_addrs_length == PROTOCOLADDRSLEN) && (msg->protocol_type == PROTOCOLTYPE) && (msg->sender_MAC_addrs
			!= NULLADDRESS) && (msg->sender_IP_addrs != NULLADDRESS) && (msg->target_IP_addrs != NULLADDRESS);
}

/**
 * @brief converts an internal ARP message into a proper ARP header to be sent outside the module
 * @param ptr_msg is the pointer to the internal ARP message
 * @param ptr_hdr is the pointer to the ARP header which will be communicated outside
 *   */
void arp_msg_to_hdr(struct arp_message *ptr_msg, struct arp_hdr *ptr_hdr) {

	ptr_hdr->hardware_type = ptr_msg->hardware_type;
	ptr_hdr->protocol_type = ptr_msg->protocol_type;

	ptr_hdr->hardware_addrs_length = ptr_msg->hardware_addrs_length;
	ptr_hdr->protocol_addrs_length = ptr_msg->protocol_addrs_length;
	ptr_hdr->operation = ptr_msg->operation;
	MAC_addrs_conversion(ptr_msg->sender_MAC_addrs, ptr_hdr->sender_MAC_addrs);
	IP_addrs_conversion(ptr_msg->sender_IP_addrs, ptr_hdr->sender_IP_addrs);
	MAC_addrs_conversion(ptr_msg->target_MAC_addrs, ptr_hdr->target_MAC_addrs);
	IP_addrs_conversion(ptr_msg->target_IP_addrs, ptr_hdr->target_IP_addrs);
}

/**
 * @brief converts an external ARP header into an internal ARP message
 * @param ptr_hdr is the pointer to the ARP header
 * @param ptr_msg is the pointer to the internal ARP message
 */
void arp_hdr_to_msg(struct arp_hdr *ptr_hdr, struct arp_message *ptr_msg) {

	unsigned char *sdr_ads, *tgt_ads, *ip_sdr, *ip_dst;

	sdr_ads = ptr_hdr->sender_MAC_addrs;
	tgt_ads = ptr_hdr->target_MAC_addrs;
	ip_sdr = ptr_hdr->sender_IP_addrs;
	ip_dst = ptr_hdr->target_IP_addrs;

	ptr_msg->hardware_type = ptr_hdr->hardware_type;
	ptr_msg->protocol_type = ptr_hdr->protocol_type;
	ptr_msg->hardware_addrs_length = ptr_hdr->hardware_addrs_length;
	ptr_msg->protocol_addrs_length = ptr_hdr->protocol_addrs_length;
	ptr_msg->operation = ptr_hdr->operation;
	ptr_msg->sender_MAC_addrs = gen_MAC_addrs(sdr_ads[0], sdr_ads[1], sdr_ads[2], sdr_ads[3], sdr_ads[4], sdr_ads[5]);
	ptr_msg->sender_IP_addrs = gen_IP_addrs((ip_sdr[0]), (ip_sdr[1]), (ip_sdr[2]), (ip_sdr[3]));
	ptr_msg->target_MAC_addrs = gen_MAC_addrs(tgt_ads[0], tgt_ads[1], tgt_ads[2], tgt_ads[3], tgt_ads[4], tgt_ads[5]);
	ptr_msg->target_IP_addrs = gen_IP_addrs(ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);
}

struct finsFrame *arp_to_fdf(struct arp_message *msg) {
	PRINT_DEBUG("Entered: msg=%p", msg);

	PRINT_DEBUG("target=%llx/%u, sender=%llx/%u, op=%d", msg->target_MAC_addrs, msg->target_IP_addrs, msg->sender_MAC_addrs, msg->sender_IP_addrs, msg->operation);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("failed to create matadata: msg=%p", msg);
		return NULL;
	}
	metadata_create(params);

	uint32_t ether_type = ARP_TYPE;
	metadata_writeToElement(params, "ether_type", &ether_type, META_TYPE_INT);
	metadata_writeToElement(params, "dst_mac", &msg->target_MAC_addrs, META_TYPE_INT64);
	metadata_writeToElement(params, "src_mac", &msg->sender_MAC_addrs, META_TYPE_INT64);

	struct finsFrame *ff = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("failed to create ff: msg=%p meta=%p", msg, params);
		metadata_destroy(params);
		return NULL;
	}

	ff->dataOrCtrl = DATA;
	ff->destinationID.id = ETHERSTUBID;
	ff->destinationID.next = NULL;
	ff->metaData = params;
	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = sizeof(struct arp_hdr);
	ff->dataFrame.pdu = (unsigned char *) malloc(ff->dataFrame.pduLength);

	if (ff->dataFrame.pdu == NULL) {
		PRINT_ERROR("failed to create pdu: msg=%p meta=%p", msg, params);
		freeFinsFrame(ff);
		return NULL;
	}

	struct arp_hdr *hdr = (struct arp_hdr *) ff->dataFrame.pdu;
	hdr->hardware_type = htons(msg->hardware_type);
	hdr->protocol_type = htons(msg->protocol_type);
	hdr->hardware_addrs_length = msg->hardware_addrs_length;
	hdr->protocol_addrs_length = msg->protocol_addrs_length;
	hdr->operation = htons(hdr->operation);

	MAC_addrs_conversion(msg->sender_MAC_addrs, hdr->sender_MAC_addrs);
	IP_addrs_conversion(msg->sender_IP_addrs, hdr->sender_IP_addrs);
	MAC_addrs_conversion(msg->target_MAC_addrs, hdr->target_MAC_addrs);
	IP_addrs_conversion(msg->target_IP_addrs, hdr->target_IP_addrs);

	PRINT_DEBUG("Exited: msg=%p ff=%p meta=%p", msg, ff, ff->metaData);
	return ff;
}

struct arp_message *fdf_to_arp(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

	if (ff->dataFrame.pduLength < sizeof(struct arp_hdr)) {
		PRINT_DEBUG("pdu len smaller than ARP header: hdr_len=%u, len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
		return NULL;
	} else if (ff->dataFrame.pduLength > sizeof(struct arp_hdr)) {
		PRINT_DEBUG("pdu len longer than ARP header: hdr_len=%u, len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
	}

	struct arp_message *msg = (struct arp_message *) malloc(sizeof(struct arp_message));
	if (msg == NULL) {
		PRINT_ERROR("msg malloc error");
		return NULL;
	}

	struct arp_hdr *hdr = (struct arp_hdr *) ff->dataFrame.pdu;
	//TODO change? such that sender_mac is uint64_t
	unsigned char *sender_mac = hdr->sender_MAC_addrs;
	unsigned char *sender_ip = hdr->sender_IP_addrs;
	unsigned char *target_mac = hdr->target_MAC_addrs;
	unsigned char *target_ip = hdr->target_IP_addrs;

	msg->hardware_type = ntohs(hdr->hardware_type);
	msg->protocol_type = ntohs(hdr->protocol_type);
	msg->hardware_addrs_length = hdr->hardware_addrs_length;
	msg->protocol_addrs_length = hdr->protocol_addrs_length;
	msg->operation = ntohs(hdr->operation);

	msg->sender_MAC_addrs = gen_MAC_addrs(sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
	msg->sender_IP_addrs = gen_IP_addrs(sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
	msg->target_MAC_addrs = gen_MAC_addrs(target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
	msg->target_IP_addrs = gen_IP_addrs(target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

	PRINT_DEBUG("target=%llx/%u, sender=%llx/%u, op=%d", msg->target_MAC_addrs, msg->target_IP_addrs, msg->sender_MAC_addrs, msg->sender_IP_addrs, msg->operation);

	return msg;
}

void arp_get_ff() {
	struct finsFrame *ff;

	do {
		sem_wait(&Switch_to_ARP_Qsem);
		ff = read_queue(Switch_to_ARP_Queue);
		sem_post(&Switch_to_ARP_Qsem);
	} while (arp_running && ff == NULL);

	if (!arp_running) {
		return;
	}

	//arp_in(ff);
	if (ff->dataOrCtrl == CONTROL) {
		arp_fcf(ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == UP) {
			arp_in_fdf(ff);
			PRINT_DEBUG("");
		} else { //directionFlag==DOWN
			//arp_out_fdf(ff); //TODO remove?
			PRINT_DEBUG("todo error");
		}
	} else {
		PRINT_DEBUG("todo error");
	}
}

void arp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT)
		;
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY)
		;
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM)
		;
		//arp_read_param(ff);
		//TODO read interface_mac?
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY)
		;
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM)
		;
		//arp_set_param(ff);
		//TODO set interface_mac?
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY)
		;
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC)
		;
		arp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY)
		;
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR)
		;
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode)
		;
		break;
	}
}

void arp_exec(struct finsFrame *ff) {
	int ret = 0;
	uint32_t exec_call;
	uint32_t dst_ip;
	uint32_t src_ip;

	PRINT_DEBUG("Entered: ff=%p", ff);

	metadata *params = ff->metaData;
	if (params) {
		ret = metadata_readFromElement(params, "exec_call", &exec_call) == CONFIG_FALSE;
		switch (exec_call) {
		case EXEC_ARP_GET_ADDR:
			PRINT_DEBUG("exec_call=EXEC_ARP_GET_ADDR (%d)", exec_call)
			;

			ret += metadata_readFromElement(params, "dst_ip", &dst_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "src_ip", &src_ip) == CONFIG_FALSE;

			if (ret) {
				PRINT_ERROR("ret=%d", ret);
				//TODO send nack
			} else {
				arp_exec_get_addr(ff, dst_ip, src_ip);
			}
			break;
		default:
			PRINT_ERROR("Error unknown exec_call=%d", exec_call)
			;
			//TODO implement?
			freeFinsFrame(ff);
			break;
		}
	} else {
		//TODO send nack
		PRINT_ERROR("Error fcf.metadata==NULL");
		freeFinsFrame(ff);
	}
}

/**@brief to be completed. A fins frame is written to the 'wire'*/
int arp_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p meta=%p", ff, ff->metaData);
	if (sem_wait(&ARP_to_Switch_Qsem)) {
		PRINT_ERROR("ARP_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, ARP_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&ARP_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&ARP_to_Switch_Qsem);

	return 0;
}

void arp_init(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("ARP Started");
	arp_running = 1;

	//uint64_t MACADDRESS = 9890190479;/**<MAC address of host; sent to the arp module*/
	uint64_t MACADDRESS = 0x080027445566; //eth0, bridged
	//uint64_t MACADDRESS = 0x080027112233; //eth1, nat
	//uint64_t MACADDRESS = 0x080027123456; //made up

	//uint32_t IPADDRESS = 672121;/**<IP address of host; sent to the arp module*/
	uint32_t IPADDRESS = IP4_ADR_P2H(192, 168, 1, 20);/**<IP address of host; sent to the arp module*/
	//uint32_t IPADDRESS = IP4_ADR_P2H(172,31,50,160);/**<IP address of host; sent to the arp module*/

	//init_arp_intface(MACADDRESS, IPADDRESS);

	interface_list = NULL;
	cache_list = NULL;

	arp_register_interface(MACADDRESS, IPADDRESS);

	while (arp_running) {
		arp_get_ff();
		PRINT_DEBUG("");
		//	free(pff);
	}

	PRINT_DEBUG("ARP Terminating");
}

void arp_shutdown() {
	arp_running = 0;

	//TODO fill this out
}

void arp_free() {
	//TODO free all module related mem
}
