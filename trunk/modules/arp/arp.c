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

#include "arp_internal.h"

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
void MAC_addrs_conversion(uint64_t int_addrs, uint8_t *char_addrs) {
	char_addrs[5] = (uint8_t) ((int_addrs & (0x00000000000000FFull))); //least sig.
	char_addrs[4] = (uint8_t) ((int_addrs & (0x000000000000FF00ull)) >> 8);
	char_addrs[3] = (uint8_t) ((int_addrs & (0x0000000000FF0000ull)) >> 16);
	char_addrs[2] = (uint8_t) ((int_addrs & (0x00000000FF000000ull)) >> 24);
	char_addrs[1] = (uint8_t) ((int_addrs & (0x000000FF00000000ull)) >> 32);
	char_addrs[0] = (uint8_t) ((int_addrs & (0x0000FF0000000000ull)) >> 40); //most sig.
}

/**
 * @brief converts 4-byte IP address (stored as unsigned 32-bit int)
 * into a representable 4-byte char array
 * @param int_addrs is the address in unsigned int 32
 * @param *char_addrs points to the character array which will store the converted address
 *  */
void IP_addrs_conversion(uint32_t int_addrs, uint8_t *char_addrs) {
	/**register shifting is used to extract individual bytes in the code below*/
	char_addrs[3] = (uint8_t) ((int_addrs & (0x000000FF))); //least significant
	char_addrs[2] = (uint8_t) ((int_addrs & (0x0000FF00)) >> 8);
	char_addrs[1] = (uint8_t) ((int_addrs & (0x00FF0000)) >> 16);
	char_addrs[0] = (uint8_t) ((int_addrs & (0xFF000000)) >> 24); //most significant
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

	return (msg->hardware_type == ARP_HWD_TYPE) && (msg->operation == ARP_OP_REQUEST || msg->operation == ARP_OP_REPLY)
			&& (msg->hardware_addrs_length == ARP_HDW_ADDR_LEN) && (msg->protocol_addrs_length == ARP_PROTOCOL_ADDR_LEN)
			&& (msg->protocol_type == ARP_PROTOCOL_TYPE) && (msg->sender_MAC_addrs != ARP_MAC_NULL) && (msg->sender_IP_addrs != ARP_IP_NULL)
			&& (msg->target_IP_addrs != ARP_IP_NULL);
}

struct arp_interface *arp_interface_create(uint64_t addr_mac, uint32_t addr_ip) {
	PRINT_DEBUG("Entered: mac=0x%llx, ip=%u", addr_mac, addr_ip);

	struct arp_interface *interface = (struct arp_interface *) secure_malloc(sizeof(struct arp_interface));
	interface->addr_mac = addr_mac;
	interface->addr_ip = addr_ip;

	PRINT_DEBUG("Exited: mac=0x%llx, ip=%u, interface=%p", addr_mac, addr_ip, interface);
	return interface;
}

int arp_interface_ip_test(struct arp_interface *interface, uint32_t *addr_ip) {
	return interface->addr_ip == *addr_ip;
}

void arp_interface_free(struct arp_interface *interface) {
	PRINT_DEBUG("Entered: interface=%p", interface);

	free(interface);
}

int arp_register_interface(struct fins_module *module, uint64_t MAC_address, uint32_t IP_address) {
	PRINT_DEBUG("Registering Interface: MAC=0x%llx, IP=%u", MAC_address, IP_address);

	struct arp_data *data = (struct arp_data *) module->data;

	if (list_has_space(data->interface_list)) {
		struct arp_interface *interface = arp_interface_create(MAC_address, IP_address);
		list_append(data->interface_list, interface);

		return 1;
	} else {
		return 0;
	}
}

struct arp_request *arp_request_create(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip) {
	PRINT_DEBUG("Entered: ff=%p, mac=0x%llx, ip=%u", ff, src_mac, src_ip);

	struct arp_request *request = (struct arp_request *) secure_malloc(sizeof(struct arp_request));
	request->ff = ff;
	request->src_mac = src_mac;
	request->src_ip = src_ip;

	PRINT_DEBUG("Exited: ff=%p, mac=0x%llx, ip=%u, request=%p", ff, src_mac, src_ip, request);
	return request;
}

int arp_request_ip_test(struct arp_request *request, uint32_t *src_ip) {
	return request->src_ip == *src_ip;
}

void arp_request_free(struct arp_request *request) {
	PRINT_DEBUG("Entered: request=%p", request);

	if (request->ff != NULL) {
		freeFinsFrame(request->ff);
	}

	free(request);
}

struct arp_cache *arp_cache_create(uint32_t addr_ip, uint8_t *interrupt_flag, sem_t *event_sem) {
	PRINT_DEBUG("Entered: ip=%u", addr_ip);

	struct arp_cache *cache = (struct arp_cache *) secure_malloc(sizeof(struct arp_cache));
	cache->addr_mac = ARP_MAC_NULL;
	cache->addr_ip = addr_ip;

	cache->request_list = list_create(ARP_REQUEST_LIST_MAX);

	cache->seeking = 0;
	memset(&cache->updated_stamp, 0, sizeof(struct timeval));

	cache->retries = 0;

	cache->to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
	cache->to_data->handler = intsem_to_handler;
	cache->to_data->flag = &cache->to_flag;
	cache->to_data->interrupt = interrupt_flag;
	cache->to_data->sem = event_sem;
	timer_create_to((struct to_timer_data *) cache->to_data);

	PRINT_DEBUG("Exited: ip=%u, cache=%p, tid=%ld", addr_ip, cache, (long) cache->to_data->tid);
	return cache;
}

void arp_cache_shutdown(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	//stop threads
	timer_stop(cache->to_data->tid);

	//sem_post(&conn->write_wait_sem);
	//sem_post(&conn->write_sem);
	//clear all threads using this conn_stub

	/*#*/PRINT_DEBUG("");
	//post to read/write/connect/etc threads
	/*#*/PRINT_DEBUG("");
}

void arp_cache_free(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (cache->request_list != NULL) {
		list_free(cache->request_list, arp_request_free);
	}

	timer_delete(cache->to_data->tid);
	free(cache->to_data);

	free(cache);
}

int arp_cache_ip_test(struct arp_cache *cache, uint32_t *addr_ip) {
	return cache->addr_ip == *addr_ip;
}

int arp_cache_non_seeking_test(struct arp_cache *cache) {
	return !cache->seeking;
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

	PRINT_DEBUG("Printing of an external format arp message");
	PRINT_DEBUG("Sender hardware (MAC) address = ");
	for (i = 0; i < ARP_HDW_ADDR_LEN; i++)
		PRINT_DEBUG("0x%x:", pckt->sender_MAC_addrs[i]);
	PRINT_DEBUG("Sender IP address = ");
	for (i = 0; i < ARP_PROTOCOL_ADDR_LEN; i++)
		PRINT_DEBUG("%d.", pckt->sender_IP_addrs[i]);
	PRINT_DEBUG("Target hardware (MAC) address= ");
	for (i = 0; i < ARP_HDW_ADDR_LEN; i++)
		PRINT_DEBUG("0x%x:", pckt->target_MAC_addrs[i]);
	PRINT_DEBUG("Target IP address = ");
	for (i = 0; i < ARP_PROTOCOL_ADDR_LEN; i++)
		PRINT_DEBUG("%d.", pckt->target_IP_addrs[i]);
	PRINT_DEBUG("Hardware type: %d", pckt->hardware_type);
	PRINT_DEBUG("Protocol type: %d", pckt->protocol_type);
	PRINT_DEBUG("Hardware length: %d", pckt->hardware_addrs_length);
	PRINT_DEBUG("Hardware length: %d", pckt->protocol_addrs_length);
	PRINT_DEBUG("Operation: %d", pckt->operation);
}

/**
 * @brief this function prints the contents of a cache for each of the interfaces
 * ptr_cacheHeader points to the first element/header of the cache
 */
void print_cache(struct fins_module *module) { //TODO fix/update?
	//struct arp_cache *ptr_elementInList;

	//struct arp_data *data = (struct arp_data *) module->data;
	//PRINT_DEBUG("Host Interface:");
	//ptr_elementInList = arp_cache_list;
	//print_IP_addrs(ptr_elementInList->addr_ip);
	//print_MAC_addrs(ptr_elementInList->addr_mac);
	//ptr_elementInList = ptr_elementInList->next; //move the pointer to the stored node
	//print_neighbors(data->cache_list);
	PRINT_DEBUG("");
}

/**
 * @brief this function prints the list of addresses of a host's neighbors
 * (useful in testing/mimicing network response)
 * @param ptr_neighbors points to the first element of the list of 'neighbors'
 */
/*
 void print_neighbors(struct linked_list *ptr_list_neighbors) {

 struct arp_cache *ptr_elementInList;

 ptr_elementInList = ptr_list_neighbors;
 PRINT_DEBUG("List of addresses of neighbors:");

 while (ptr_elementInList != NULL) {
 print_IP_addrs(ptr_elementInList->addr_ip);
 print_MAC_addrs(ptr_elementInList->addr_mac);
 }
 }
 */

struct finsFrame *arp_to_fdf(struct arp_message *msg) {
	PRINT_DEBUG("Entered: msg=%p", msg);

	PRINT_DEBUG("target=0x%llx/%u, sender=0x%llx/%u, op=%d",
			msg->target_MAC_addrs, msg->target_IP_addrs, msg->sender_MAC_addrs, msg->sender_IP_addrs, msg->operation);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t ether_type = ARP_TYPE;
	secure_metadata_writeToElement(meta, "send_ether_type", &ether_type, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "send_dst_mac", &msg->target_MAC_addrs, META_TYPE_INT64);
	secure_metadata_writeToElement(meta, "send_src_mac", &msg->sender_MAC_addrs, META_TYPE_INT64);

	struct finsFrame *ff = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = DATA;
	ff->destinationID = NONE_INDEX; //INTERFACE_ID;
	ff->metaData = meta;

	ff->dataFrame.directionFlag = DIR_DOWN;
	ff->dataFrame.pduLength = sizeof(struct arp_hdr);
	ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);

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

	struct arp_message *msg = (struct arp_message *) secure_malloc(sizeof(struct arp_message));

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

void arp_get_ff(struct fins_module *module) {
	struct arp_data *data = (struct arp_data *) module->data;
	struct finsFrame *ff;

	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL && !data->interrupt_flag); //TODO change logic here, combine with switch_to_arp?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff != NULL) {
		if (ff->metaData == NULL) {
			PRINT_ERROR("Error fcf.metadata==NULL");
			exit(-1);
		}

		if (ff->dataOrCtrl == CONTROL) {
			arp_fcf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataOrCtrl == DATA) {
			if (ff->dataFrame.directionFlag == DIR_UP) {
				arp_in_fdf(module, ff);
				PRINT_DEBUG("");
			} else { //directionFlag==DIR_DOWN
				//arp_out_fdf(ff); //TODO remove?
				PRINT_ERROR("todo error");
			}
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else if (data->interrupt_flag) {
		data->interrupt_flag = 0;

		arp_interrupt(module);
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}
}

void arp_fcf(struct fins_module *module, struct finsFrame *ff) {
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
		arp_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		arp_exec(module, ff);
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

void arp_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct arp_data *data = (struct arp_data *) module->data;
	int i;

	switch (ff->ctrlFrame.param_id) {
	case MOD_SET_PARAM_FLOWS:
		PRINT_DEBUG("PARAM_FLOWS");
		uint32_t flows_num = ff->ctrlFrame.data_len / sizeof(uint32_t);
		uint32_t *flows = (uint32_t *) ff->ctrlFrame.data;

		if (module->flows_max < flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = flows_num;

		for (i = 0; i < flows_num; i++) {
			data->flows[i] = flows[i];
		}

		//freeFF frees flows
		break;
	case MOD_SET_PARAM_LINKS:
		PRINT_DEBUG("PARAM_LINKS");
		if (ff->ctrlFrame.data_len != sizeof(struct linked_list)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		struct linked_list *link_list = (struct linked_list *) ff->ctrlFrame.data;
		data->link_list = link_list;

		ff->ctrlFrame.data = NULL;
		break;
	case MOD_SET_PARAM_DUAL:
		PRINT_DEBUG("PARAM_DUAL");

		if (ff->ctrlFrame.data_len != sizeof(struct fins_module_table)) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		struct fins_module_table *table = (struct fins_module_table *) ff->ctrlFrame.data;

		if (module->flows_max < table->flows_num) {
			PRINT_ERROR("todo error");
			freeFinsFrame(ff);
			return;
		}
		data->flows_num = table->flows_num;

		for (i = 0; i < table->flows_num; i++) {
			data->flows[i] = table->flows[i];
		}

		if (data->link_list != NULL) {
			list_free(data->link_list, free);
		}
		data->link_list = table->link_list;

		//freeFF frees table
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		break;
	}

	freeFinsFrame(ff);
}

void arp_exec(struct fins_module *module, struct finsFrame *ff) {
	uint32_t src_ip = 0;
	uint32_t dst_ip = 0;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *meta = ff->metaData;
	switch (ff->ctrlFrame.param_id) {
	case EXEC_ARP_GET_ADDR:
		PRINT_DEBUG("param_id=EXEC_ARP_GET_ADDR (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(meta, "src_ip", &src_ip);
		secure_metadata_readFromElement(meta, "dst_ip", &dst_ip);

		arp_exec_get_addr(module, ff, src_ip, dst_ip);
		//arp_exec_get_addr(ff, addr_ip);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void arp_to_func(struct arp_cache *cache, struct fins_module *module) {
	if (cache->to_flag) {
		cache->to_flag = 0;

		arp_handle_to(module, cache);
	}
}

void arp_interrupt(struct fins_module *module) {
	struct arp_data *data = (struct arp_data *) module->data;

	list_for_each1(data->cache_list, arp_to_func, module);
}

void *switch_to_arp(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		arp_get_ff(module);
		PRINT_DEBUG("");
		//	free(pff);
	}

	PRINT_IMPORTANT("Exited");
	return NULL;
}

void arp_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	metadata_element *sub = config_setting_add(root, "test", CONFIG_TYPE_GROUP);
	if (sub == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	metadata_element *elem = config_setting_add(sub, "key", CONFIG_TYPE_INT);
	if (elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	uint32_t value = 10;
	int status = config_setting_set_int(elem, *(int *) &value);
	if (status == CONFIG_FALSE) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
}

int arp_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	arp_init_params(module);

	module->data = secure_malloc(sizeof(struct arp_data));
	struct arp_data *data = (struct arp_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	data->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		data->flows[i] = flows[i];
	}

	data->interface_list = list_create(ARP_INTERFACE_LIST_MAX);
	data->cache_list = list_create(ARP_CACHE_LIST_MAX);

	//TODO extract this from meta?
	//set start-up vars from envi
	//arp_init();
	//arp_register_interface(my_host_mac_addr, my_host_ip_addr);
	arp_register_interface(module, 0x10683f4f7467ull, IP4_ADR_P2H(192, 168, 1, 20));

	return 1;
}

int arp_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct arp_data *data = (struct arp_data *) module->data;
	secure_pthread_create(&data->switch_to_arp_thread, attr, switch_to_arp, module);

	return 1;
}

int arp_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int arp_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int arp_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct arp_data *data = (struct arp_data *) module->data;

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_arp_thread");
	pthread_join(data->switch_to_arp_thread, NULL);

	return 1;
}

int arp_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct arp_data *data = (struct arp_data *) module->data;
	//TODO free all module related mem

	//delete threads
	PRINT_IMPORTANT("arp_interface_num=%u", data->interface_list->len);
	list_free(data->interface_list, arp_interface_free);

	PRINT_IMPORTANT("arp_cache_num=%u", data->cache_list->len);
	struct arp_cache *cache;
	while (!list_is_empty(data->cache_list)) {
		cache = (struct arp_cache *) list_remove_front(data->cache_list);

		arp_cache_shutdown(cache);
		arp_cache_free(cache);
	}
	free(data->cache_list);

	if (data->link_list != NULL) {
		list_free(data->link_list, free);
	}
	free(data);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void arp_dummy(void) {

}

static struct fins_module_ops arp_ops = { .init = arp_init, .run = arp_run, .pause = arp_pause, .unpause = arp_unpause, .shutdown = arp_shutdown, .release =
		arp_release, };

struct fins_module *arp_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, ARP_LIB);
	module->flows_max = ARP_MAX_FLOWS;
	module->ops = &arp_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
