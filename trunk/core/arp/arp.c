/**@file arp.c
 *@brief this files contains all relevant functions to execute an ARP module,
 *@brief IP and MAC address of the host is provided by the main
 *@author Jonathan Reed
 *@date  September 5, 2012
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include "arp.h"

#include <switch.h>
static struct fins_proto_module arp_proto = { .module_id = ARP_ID, .name = "arp", .running_flag = 1, };

pthread_t switch_to_arp_thread;

struct arp_interface *arp_interface_list;
uint32_t arp_interface_num;

struct arp_cache *arp_cache_list; //The list of current cache we have
uint32_t arp_cache_num;

uint8_t arp_interrupt_flag;
int arp_thread_count = 0;

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
 * @brief converts 6-byte MAC address (stored as unsigned 64-bit int)
 * into a representable 6-byte char array
 * @param int_addrs is the address in unsigned int 64
 * @param *char_addrs points to the character array which will store the converted address
 *  */
/**register shifting is used to extract individual bytes in the code below*/
void MAC_addrs_conversion(uint64_t int_addrs, unsigned char *char_addrs) {
	char_addrs[5] = (unsigned char) ((int_addrs & (0x00000000000000FFull))); //least sig.
	char_addrs[4] = (unsigned char) ((int_addrs & (0x000000000000FF00ull)) >> 8);
	char_addrs[3] = (unsigned char) ((int_addrs & (0x0000000000FF0000ull)) >> 16);
	char_addrs[2] = (unsigned char) ((int_addrs & (0x00000000FF000000ull)) >> 24);
	char_addrs[1] = (unsigned char) ((int_addrs & (0x000000FF00000000ull)) >> 32);
	char_addrs[0] = (unsigned char) ((int_addrs & (0x0000FF0000000000ull)) >> 40); //most sig.
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
 * @brief this function produces an ARP request for a host whose IP address is known
 * @param IP_address_target is the uint32 address of the target host
 */
void gen_requestARP(struct arp_message *request_ARP_ptr, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip) {
	request_ARP_ptr->sender_MAC_addrs = sender_mac;
	request_ARP_ptr->sender_IP_addrs = sender_ip;
	request_ARP_ptr->target_MAC_addrs = target_mac;
	request_ARP_ptr->target_IP_addrs = target_ip;

	request_ARP_ptr->hardware_type = ARP_HWD_TYPE;
	request_ARP_ptr->protocol_type = ARP_PROTOCOL_TYPE;
	request_ARP_ptr->hardware_addrs_length = ARP_HDW_ADDR_LEN;
	request_ARP_ptr->protocol_addrs_length = ARP_PROTOCOL_ADDR_LEN;
	request_ARP_ptr->operation = ARP_OP_REQUEST;
}

/**
 * @brief this function produces an ARP reply for the host which has already sent
 * a request for a MAC address
 * @param request_ARP is the ARP request
 * @param reply_ARP is the pointer to the
 */
void gen_replyARP(struct arp_message *reply_ARP, uint64_t sender_mac, uint32_t sender_ip, uint64_t target_mac, uint32_t target_ip) {
	/**generate reply only if the request is intended for the host*/
	reply_ARP->sender_MAC_addrs = sender_mac;
	reply_ARP->sender_IP_addrs = sender_ip;
	reply_ARP->target_MAC_addrs = target_mac;
	reply_ARP->target_IP_addrs = target_ip;

	reply_ARP->hardware_type = ARP_HWD_TYPE;
	reply_ARP->protocol_type = ARP_PROTOCOL_TYPE;
	reply_ARP->hardware_addrs_length = ARP_HDW_ADDR_LEN;
	reply_ARP->protocol_addrs_length = ARP_PROTOCOL_ADDR_LEN;
	reply_ARP->operation = ARP_OP_REPLY;
}

/**
 * @brief simply checks whether a received ARP message is valid or not
 * @param pckt_arp points to the ARP message
 */
int check_valid_arp(struct arp_message *msg) {

	return (msg->hardware_type == ARP_HWD_TYPE) && (msg->operation == ARP_OP_REQUEST || msg->operation == ARP_OP_REPLY) && (msg->hardware_addrs_length
			== ARP_HDW_ADDR_LEN) && (msg->protocol_addrs_length == ARP_PROTOCOL_ADDR_LEN) && (msg->protocol_type == ARP_PROTOCOL_TYPE)
			&& (msg->sender_MAC_addrs != ARP_MAC_NULL) && (msg->sender_IP_addrs != ARP_IP_NULL) && (msg->target_IP_addrs != ARP_IP_NULL);
}

struct arp_interface *arp_interface_create(uint64_t mac_addr, uint32_t ip_addr) {
	PRINT_DEBUG("Entered: mac=0x%llx, ip=%u", mac_addr, ip_addr);

	struct arp_interface *interface = (struct arp_interface *) fins_malloc(sizeof(struct arp_interface));
	interface->next = NULL;

	interface->mac_addr = mac_addr;
	interface->ip_addr = ip_addr;

	PRINT_DEBUG("Exited: mac=0x%llx, ip=%u, interface=%p", mac_addr, ip_addr, interface);
	return interface;
}

void arp_interface_free(struct arp_interface *interface) {
	PRINT_DEBUG("Entered: interface=%p", interface);

	free(interface);
}

int arp_interface_list_insert(struct arp_interface *interface) {
	PRINT_DEBUG("Entered: interface=%p", interface);

	interface->next = arp_interface_list;
	arp_interface_list = interface;

	arp_interface_num++;
	return 1;
}

struct arp_interface *arp_interface_list_find(uint32_t ip_addr) {
	PRINT_DEBUG("Entered: ip=%u", ip_addr);

	struct arp_interface *interface = arp_interface_list;

	while (interface != NULL && interface->ip_addr != ip_addr) {
		interface = interface->next;
	}

	PRINT_DEBUG("Exited: ip=%u, interface=%p", ip_addr, interface);
	return interface;
}

void arp_interface_list_remove(struct arp_interface *interface) {
	PRINT_DEBUG("Entered: interface=%p", interface);

	if (arp_interface_list == NULL) {
		return;
	}

	if (arp_interface_list == interface) {
		arp_interface_list = arp_interface_list->next;
		arp_interface_num--;
		return;
	}

	struct arp_interface *temp = arp_interface_list;
	while (temp->next != NULL) {
		if (temp->next == interface) {
			temp->next = interface->next;
			arp_interface_num--;
			return;
		}
		temp = temp->next;
	}
}

int arp_interface_list_is_empty(void) {
	return arp_interface_num == 0;
}

int arp_interface_list_has_space(void) {
	return arp_interface_num < ARP_INTERFACE_LIST_MAX;
}

struct arp_request *arp_request_create(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip) {
	PRINT_DEBUG("Entered: ff=%p, mac=0x%llx, ip=%u", ff, src_mac, src_ip);

	struct arp_request *request = (struct arp_request *) fins_malloc(sizeof(struct arp_request));
	request->next = NULL;

	request->ff = ff;
	request->src_mac = src_mac;
	request->src_ip = src_ip;

	PRINT_DEBUG("Exited: ff=%p, mac=0x%llx, ip=%u, request=%p", ff, src_mac, src_ip, request);
	return request;
}

void arp_request_free(struct arp_request *request) {
	PRINT_DEBUG("Entered: request=%p", request);

	if (request->ff) {
		freeFinsFrame(request->ff);
	}

	free(request);
}

struct arp_request_list *arp_request_list_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct arp_request_list *request_list = (struct arp_request_list *) fins_malloc(sizeof(struct arp_request_list));
	request_list->max = max;
	request_list->len = 0;

	request_list->front = NULL;
	request_list->end = NULL;

	PRINT_DEBUG("Exited: max=%u, request_list=%p", max, request_list);
	return request_list;
}

void arp_request_list_append(struct arp_request_list *request_list, struct arp_request *request) {
	PRINT_DEBUG("Entered: request_list=%p, request=%p", request_list, request);

	request->next = NULL;
	if (arp_request_list_is_empty(request_list)) {
		//queue empty
		request_list->front = request;
	} else {
		//node after end
		request_list->end->next = request;
	}
	request_list->end = request;
	request_list->len++;
}

struct arp_request *arp_request_list_find(struct arp_request_list *request_list, uint32_t src_ip) {
	PRINT_DEBUG("Entered: request_list=%p, ip=%u", request_list, src_ip);

	struct arp_request *request = request_list->front;
	while (request != NULL && request->src_ip != src_ip) {
		request = request->next;
	}

	PRINT_DEBUG("Exited: request_list=%p, ip=%u, request=%p", request_list, src_ip, request);
	return request;
}

struct arp_request *arp_request_list_remove_front(struct arp_request_list *request_list) {
	PRINT_DEBUG("Entered: request_list=%p", request_list);

	struct arp_request *request = request_list->front;

	request_list->front = request->next;
	request_list->len--;

	PRINT_DEBUG("Exited: request_list=%p, request=%p", request_list, request);
	return request;
}

int arp_request_list_is_empty(struct arp_request_list *request_list) {
	//return request_list->front == NULL;
	return request_list->len == 0;
}

int arp_request_list_has_space(struct arp_request_list *request_list) {
	return request_list->len < request_list->max;
}

void arp_request_list_free(struct arp_request_list *request_list) {
	PRINT_DEBUG("Entered: request_list=%p", request_list);

	struct arp_request *request = request_list->front;
	while (!arp_request_list_is_empty(request_list)) {
		request = arp_request_list_remove_front(request_list);
		arp_request_free(request);
	}

	free(request_list);
}

struct arp_cache *arp_cache_create(uint32_t ip_addr) {
	PRINT_DEBUG("Entered: ip=%u", ip_addr);

	struct arp_cache *cache = (struct arp_cache *) fins_malloc(sizeof(struct arp_cache));
	cache->next = NULL;
	cache->running_flag = 1;

	cache->mac_addr = ARP_MAC_NULL;
	cache->ip_addr = ip_addr;

	cache->request_list = arp_request_list_create(ARP_REQUEST_LIST_MAX);

	cache->seeking = 0;
	memset(&cache->updated_stamp, 0, sizeof(struct timeval));

	cache->to_flag = 0;
	cache->to_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (cache->to_fd == -1) {
		PRINT_ERROR("ERROR: unable to create to_fd.");
		exit(-1);
	}
	cache->retries = 0;

	//start timer thread
	struct intsem_to_thread_data *to_data = (struct intsem_to_thread_data *) fins_malloc(sizeof(struct intsem_to_thread_data));
	int id = arp_thread_count++;
	to_data->id = id;
	to_data->fd = cache->to_fd;
	to_data->running = &cache->running_flag;
	to_data->flag = &cache->to_flag;
	to_data->interrupt = &arp_interrupt_flag;
	to_data->sem = arp_proto.event_sem;
	if (pthread_create(&cache->to_thread, NULL, intsem_to_thread, (void *) to_data)) {
		PRINT_ERROR("ERROR: unable to create interrupt_to_thread thread.");
		exit(-1);
	}

	PRINT_DEBUG("Exited: ip=%u, cache=%p, id=%d, to_fd=%d", ip_addr, cache, id, cache->to_fd);
	return cache;
}

void arp_cache_shutdown(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	cache->running_flag = 0;

	//stop threads
	start_timer(cache->to_fd, ARP_TO_MIN);

	//sem_post(&conn->write_wait_sem);
	//sem_post(&conn->write_sem);
	//clear all threads using this conn_stub

	/*#*/PRINT_DEBUG("");
	//post to read/write/connect/etc threads
	pthread_join(cache->to_thread, NULL);
	/*#*/PRINT_DEBUG("");
}

void arp_cache_free(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (cache->request_list) {
		arp_request_list_free(cache->request_list);
	}

	free(cache);
}
int arp_cache_list_insert(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (arp_cache_list == NULL) {
		arp_cache_list = cache;
	} else {
		struct arp_cache *temp = arp_cache_list;

		while (temp->next != NULL) {
			temp = temp->next;
		}

		temp->next = cache;
		cache->next = NULL;
	}

	arp_cache_num++;
	return 1;
}

struct arp_cache *arp_cache_list_find(uint32_t ip_addr) {
	PRINT_DEBUG("Entered: ip=%u", ip_addr);

	struct arp_cache *cache = arp_cache_list;
	while (cache != NULL && cache->ip_addr != ip_addr) {
		cache = cache->next;
	}

	PRINT_DEBUG("Exited: ip=%u, cache=%p", ip_addr, cache);
	return cache;
}

void arp_cache_list_remove(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (arp_cache_list == NULL) {
		return;
	}

	if (arp_cache_list == cache) {
		arp_cache_list = arp_cache_list->next;
		arp_cache_num--;
		return;
	}

	struct arp_cache *temp = arp_cache_list;
	while (temp->next != NULL) {
		if (temp->next == cache) {
			temp->next = cache->next;
			arp_cache_num--;
			return;
		}
		temp = temp->next;
	}
}

struct arp_cache *arp_cache_list_remove_first_non_seeking(void) {
	PRINT_DEBUG("Entered");

	if (arp_cache_list == NULL) {
		return NULL;
	}

	struct arp_cache *cache = arp_cache_list;
	if (cache->seeking) {
		struct arp_cache *next;

		while (cache->next != NULL) {
			if (cache->next->seeking) {
				cache = cache->next;
			} else {
				next = cache->next;
				cache->next = next->next;

				arp_cache_num--;
				PRINT_DEBUG("Exited: cache=%p", next);
				return next;
			}
		}

		PRINT_DEBUG("Exited: cache=%p", NULL);
		return NULL; //TODO change to head?
	} else {
		arp_cache_list = cache->next;
	}

	arp_cache_num--;
	PRINT_DEBUG("Exited: cache=%p", cache);
	return cache;
}

int arp_cache_list_is_empty(void) {
	return arp_cache_num == 0;
}

int arp_cache_list_has_space(void) {
	return arp_cache_num < ARP_CACHE_LIST_MAX;
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
	PRINT_DEBUG("MAC address = 0x%llx", MAC_intg_addrs);
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
	PRINT_DEBUG("Hardware Address Length : %u", msg->hardware_addrs_length);PRINT_DEBUG("Hardware Type : %d", msg->hardware_type);PRINT_DEBUG("Protocol Address Length : %u", msg->protocol_addrs_length);PRINT_DEBUG("Protocol Type : %d", msg->protocol_type);PRINT_DEBUG("Operation Type : %d", msg->operation);PRINT_DEBUG("Target:");
	print_IP_addrs(msg->target_IP_addrs);
	print_MAC_addrs(msg->target_MAC_addrs);

}

void print_arp_hdr(struct arp_hdr *pckt) {

	int i;

	PRINT_DEBUG("Printing of an external format arp message");PRINT_DEBUG("Sender hardware (MAC) address = ");
	for (i = 0; i < ARP_HDW_ADDR_LEN; i++)
		PRINT_DEBUG("0x%x:", pckt->sender_MAC_addrs[i]);PRINT_DEBUG("Sender IP address = ");
	for (i = 0; i < ARP_PROTOCOL_ADDR_LEN; i++)
		PRINT_DEBUG("%d.", pckt->sender_IP_addrs[i]);PRINT_DEBUG("Target hardware (MAC) address= ");
	for (i = 0; i < ARP_HDW_ADDR_LEN; i++)
		PRINT_DEBUG("0x%x:", pckt->target_MAC_addrs[i]);PRINT_DEBUG("Target IP address = ");
	for (i = 0; i < ARP_PROTOCOL_ADDR_LEN; i++)
		PRINT_DEBUG("%d.", pckt->target_IP_addrs[i]);PRINT_DEBUG("Hardware type: %d", pckt->hardware_type);PRINT_DEBUG("Protocol type: %d", pckt->protocol_type);PRINT_DEBUG("Hardware length: %d", pckt->hardware_addrs_length);PRINT_DEBUG("Hardware length: %d", pckt->protocol_addrs_length);PRINT_DEBUG("Operation: %d", pckt->operation);
}

/**
 * @brief this function prints the contents of a cache for each of the interfaces
 * ptr_cacheHeader points to the first element/header of the cache
 */
void print_cache(void) { //TODO fix/update?
	//struct arp_cache *ptr_elementInList;

	//PRINT_DEBUG("Host Interface:");
	//ptr_elementInList = arp_cache_list;
	//print_IP_addrs(ptr_elementInList->ip_addr);
	//print_MAC_addrs(ptr_elementInList->mac_addr);
	//ptr_elementInList = ptr_elementInList->next; //move the pointer to the stored node
	print_neighbors(arp_cache_list);
	PRINT_DEBUG("");
}

/**
 * @brief this function prints the list of addresses of a host's neighbors
 * (useful in testing/mimicing network response)
 * @param ptr_neighbors points to the first element of the list of 'neighbors'
 */
void print_neighbors(struct arp_cache *ptr_list_neighbors) {

	struct arp_cache *ptr_elementInList;

	ptr_elementInList = ptr_list_neighbors;
	PRINT_DEBUG("List of addresses of neighbors:");

	while (ptr_elementInList != NULL) {
		print_IP_addrs(ptr_elementInList->ip_addr);
		print_MAC_addrs(ptr_elementInList->mac_addr);
		PRINT_DEBUG("");
		ptr_elementInList = ptr_elementInList->next;
	}
}

struct finsFrame *arp_to_fdf(struct arp_message *msg) {
	PRINT_DEBUG("Entered: msg=%p", msg);

	PRINT_DEBUG("target=0x%llx/%u, sender=0x%llx/%u, op=%d",
			msg->target_MAC_addrs, msg->target_IP_addrs, msg->sender_MAC_addrs, msg->sender_IP_addrs, msg->operation);

	metadata *params = (metadata *) fins_malloc(sizeof(metadata));
	metadata_create(params);

	uint32_t ether_type = ARP_TYPE;
	metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);
	metadata_writeToElement(params, "send_dst_mac", &msg->target_MAC_addrs, META_TYPE_INT64);
	metadata_writeToElement(params, "send_src_mac", &msg->sender_MAC_addrs, META_TYPE_INT64);

	struct finsFrame *ff = (struct finsFrame*) fins_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = INTERFACE_ID;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = sizeof(struct arp_hdr);
	ff->dataFrame.pdu = (uint8_t *) fins_malloc(ff->dataFrame.pduLength);

	struct arp_hdr *hdr = (struct arp_hdr *) ff->dataFrame.pdu;
	hdr->hardware_type = htons(msg->hardware_type);
	hdr->protocol_type = htons(msg->protocol_type);
	hdr->hardware_addrs_length = msg->hardware_addrs_length;
	hdr->protocol_addrs_length = msg->protocol_addrs_length;
	hdr->operation = htons(msg->operation);

	MAC_addrs_conversion(msg->sender_MAC_addrs, hdr->sender_MAC_addrs);
	IP_addrs_conversion(msg->sender_IP_addrs, hdr->sender_IP_addrs);
	MAC_addrs_conversion(msg->target_MAC_addrs, hdr->target_MAC_addrs);
	IP_addrs_conversion(msg->target_IP_addrs, hdr->target_IP_addrs);

	PRINT_DEBUG("Exited: msg=%p, ff=%p, meta=%p", msg, ff, ff->metaData);
	return ff;
}

struct arp_message *fdf_to_arp(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	if (ff->dataFrame.pduLength < sizeof(struct arp_hdr)) {
		PRINT_DEBUG("pdu len smaller than ARP header: hdr_len=%u, pdu_len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
		return NULL;
	} else if (ff->dataFrame.pduLength > sizeof(struct arp_hdr)) {
		PRINT_DEBUG("pdu len longer than ARP header: hdr_len=%u, pdu_len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
	}

	struct arp_message *msg = (struct arp_message *) fins_malloc(sizeof(struct arp_message));

	struct arp_hdr *hdr = (struct arp_hdr *) ff->dataFrame.pdu;
	//TODO change? such that sender_mac is uint64_t
	uint8_t *sender_mac = hdr->sender_MAC_addrs;
	uint8_t *sender_ip = hdr->sender_IP_addrs;
	uint8_t *target_mac = hdr->target_MAC_addrs;
	uint8_t *target_ip = hdr->target_IP_addrs;

	msg->hardware_type = ntohs(hdr->hardware_type);
	msg->protocol_type = ntohs(hdr->protocol_type);
	msg->hardware_addrs_length = hdr->hardware_addrs_length;
	msg->protocol_addrs_length = hdr->protocol_addrs_length;
	msg->operation = ntohs(hdr->operation);

	msg->sender_MAC_addrs = gen_MAC_addrs(sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
	msg->sender_IP_addrs = gen_IP_addrs(sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
	msg->target_MAC_addrs = gen_MAC_addrs(target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
	msg->target_IP_addrs = gen_IP_addrs(target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

	PRINT_DEBUG("target=0x%llx/%u, sender=0x%llx/%u, op=%d",
			msg->target_MAC_addrs, msg->target_IP_addrs, msg->sender_MAC_addrs, msg->sender_IP_addrs, msg->operation);

	PRINT_DEBUG("Exited: ff=%p, meta=%p, msg=%p", ff, ff->metaData, msg);
	return msg;
}

void arp_get_ff(void) {
	struct finsFrame *ff;

	do {
		if (sem_wait(arp_proto.event_sem)) {
			PRINT_ERROR("sem wait prob");
			exit(-1);
		}
		if (sem_wait(arp_proto.input_sem)) {
			PRINT_ERROR("sem wait prob");
			exit(-1);
		}
		ff = read_queue(arp_proto.input_queue);
		sem_post(arp_proto.input_sem);
	} while (arp_proto.running_flag && ff == NULL && !arp_interrupt_flag); //TODO change logic here, combine with switch_to_arp?

	if (!arp_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff) {
		if (ff->dataOrCtrl == CONTROL) {
			arp_fcf(ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (ff->dataFrame.directionFlag == UP) {
				arp_in_fdf(ff);
				PRINT_DEBUG("");
			} else { //directionFlag==DOWN
				//arp_out_fdf(ff); //TODO remove?
				PRINT_ERROR("todo error");
			}
		} else {
			PRINT_ERROR("todo error");
		}
	} else if (arp_interrupt_flag) {
		arp_interrupt_flag = 0;

		arp_interrupt();
	} else {
		PRINT_ERROR("todo error");
	}
}

void arp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo");
		//arp_read_param(ff);
		//TODO read interface_mac?
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		PRINT_ERROR("todo");
		//arp_set_param(ff);
		//TODO set interface_mac?
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		arp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void arp_exec(struct finsFrame *ff) {
	int ret = 0;
	uint32_t src_ip = 0;
	uint32_t dst_ip = 0;
	//uint32_t addr_ip = 0;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *params = ff->metaData;
	if (params) {
		switch (ff->ctrlFrame.param_id) {
		case EXEC_ARP_GET_ADDR:
			PRINT_DEBUG("param_id=EXEC_ARP_GET_ADDR (%d)", ff->ctrlFrame.param_id);

			ret += metadata_readFromElement(params, "src_ip", &src_ip) == META_FALSE;
			ret += metadata_readFromElement(params, "dst_ip", &dst_ip) == META_FALSE;
			//ret += metadata_readFromElement(params, "addr_ip", &addr_ip) == META_FALSE;

			if (ret) {
				PRINT_ERROR("ret=%d", ret);

				ff->destinationID.id = ff->ctrlFrame.senderID;
				ff->ctrlFrame.senderID = ARP_ID;
				ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
				ff->ctrlFrame.ret_val = 0;

				arp_to_switch(ff);
			} else {
				arp_exec_get_addr(ff, src_ip, dst_ip);
				//arp_exec_get_addr(ff, addr_ip);
			}
			break;
		default:
			PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id)
			;
			//TODO implement?
			freeFinsFrame(ff);
			break;
		}
	} else {
		PRINT_ERROR("Error fcf.metadata==NULL");

		ff->destinationID.id = ff->ctrlFrame.senderID;
		ff->ctrlFrame.senderID = ARP_ID;
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		ff->ctrlFrame.ret_val = 0;

		arp_to_switch(ff);
	}
}

void arp_interrupt(void) {
	struct arp_cache *cache = arp_cache_list;
	struct arp_cache *next;

	while (cache) {
		next = cache->next;
		if (cache->to_flag) {
			cache->to_flag = 0;

			arp_handle_to(cache);
		}
		cache = next;
	}
}

/**@brief to be completed. A fins frame is written to the 'wire'*/
int arp_to_switch(struct finsFrame *ff) {
	return module_to_switch(&arp_proto, ff);
}

void *switch_to_arp(void *local) {
	PRINT_CRITICAL("Entered");

	while (arp_proto.running_flag) {
		arp_get_ff();
		PRINT_DEBUG("");
		//	free(pff);
	}

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
}

void arp_init(void) {
	PRINT_CRITICAL("Entered");
	arp_proto.running_flag = 1;

	module_create_ops(&arp_proto);
	module_register(&arp_proto);

	arp_interface_list = NULL;
	arp_interface_num = 0;

	arp_cache_list = NULL;
	arp_cache_num = 0;
}

void arp_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	pthread_create(&switch_to_arp_thread, fins_pthread_attr, switch_to_arp, fins_pthread_attr);
}

int arp_register_interface(uint64_t MAC_address, uint32_t IP_address) {
	PRINT_DEBUG("Registering Interface: MAC=0x%llx, IP=%u", MAC_address, IP_address);

	if (arp_interface_list_has_space()) {
		struct arp_interface *interface = arp_interface_create(MAC_address, IP_address);
		arp_interface_list_insert(interface);

		return 1;
	} else {
		return 0;
	}
}

void arp_shutdown(void) {
	PRINT_CRITICAL("Entered");
	arp_proto.running_flag = 0;
	sem_post(arp_proto.event_sem);

	//TODO fill this out

	PRINT_CRITICAL("Joining switch_to_arp_thread");
	pthread_join(switch_to_arp_thread, NULL);
}

void arp_release(void) {
	PRINT_CRITICAL("Entered");

	module_unregister(arp_proto.module_id);

	//TODO free all module related mem

	PRINT_CRITICAL("arp_interface_list->len=%u", arp_interface_num);
	struct arp_interface *interface;
	while (!arp_interface_list_is_empty()) {
		interface = arp_interface_list;
		arp_interface_list_remove(interface);
		arp_interface_free(interface);
	}

	PRINT_CRITICAL("arp_cache_list->len=%u", arp_cache_num);
	struct arp_cache *cache;
	while (!arp_cache_list_is_empty()) {
		cache = arp_cache_list;
		arp_cache_list_remove(cache);

		arp_cache_shutdown(cache);
		arp_cache_free(cache);
	}

	module_destroy_ops(&arp_proto);
}
