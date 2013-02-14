/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <finsqueue.h>

void IP4_send_fdf_in(struct finsFrame *ff, struct ip4_header* pheader, struct ip4_packet* ppacket) {
	PRINT_DEBUG("Entered: ff=%p, pheader=%p, ppacket=%p", ff, pheader, ppacket);

	if (pheader->packet_length < pheader->header_length) {
		PRINT_ERROR("pduLen error, dropping");
		freeFinsFrame(ff);
		return;
	}

	//struct finsFrame *fins_frame = (struct finsFrame *) fins_malloc(sizeof(struct finsFrame));
	//ff->dataOrCtrl = DATA;
	uint32_t protocol = pheader->protocol; /* protocol number should  be 17 from metadata */
	switch (protocol) {
	case IP4_PT_ICMP:
		ff->destinationID.id = ICMP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_TCP:
		ff->destinationID.id = TCP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_UDP:
		ff->destinationID.id = UDP_ID;
		ff->destinationID.next = NULL;
		break;
	default:
		PRINT_ERROR("todo error");
		break;
	}

	//metadata *ipv4_meta = (metadata *) fins_malloc(sizeof(metadata));
	//metadata_create(ipv4_meta);

	IP4addr src_ip = pheader->source; //ppacket->ip_src;
	IP4addr dst_ip = pheader->destination; //ppacket->ip_dst;

	metadata *params = ff->metaData;
	secure_metadata_writeToElement(params, "recv_protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "recv_src_ip", &src_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "recv_dst_ip", &dst_ip, META_TYPE_INT32);

	uint32_t recv_ttl = pheader->ttl;
	secure_metadata_writeToElement(params, "recv_ttl", &recv_ttl, META_TYPE_INT32);

	//ff->metaData = ipv4_meta;
	PRINT_DEBUG("protocol=%u, src_ip=%lu, dst_ip=%lu, recv_ttl=%u", protocol, src_ip, dst_ip, recv_ttl);

	//ff->dataFrame.directionFlag = UP;
	//ff->dataFrame.pduLength = pheader->packet_length - 20;

	switch (protocol) {
	case IP4_PT_ICMP:
		//leave pdu/pdueLength same
		break;
	case IP4_PT_TCP:
	case IP4_PT_UDP:
		ff->dataFrame.pduLength = pheader->packet_length - pheader->header_length;
		uint8_t *pdu = ff->dataFrame.pdu;
		uint8_t *data = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
		ff->dataFrame.pdu = data;

		PRINT_DEBUG("Freeing pdu=%p", pdu);
		free(pdu);
		break;
	default:
		PRINT_ERROR("todo error");
		break;
	}

	ipv4_to_switch(ff);
}

void IP4_send_fdf_out(struct finsFrame *ff, struct ip4_packet* ppacket, struct ip4_next_hop_info next_hop, uint16_t length) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	PRINT_DEBUG("address=%u, interface=%u", (uint32_t)next_hop.address, next_hop.interface);

	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = INTERFACE_ID;
	ff->destinationID.next = NULL;
	//ff->metaData = ff->metaData;

	//ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = length + IP4_MIN_HLEN;

	uint8_t *pdu = ff->dataFrame.pdu;
	ff->dataFrame.pdu = (uint8_t *) secure_malloc(length + IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu, ppacket, IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu + IP4_MIN_HLEN, pdu, length);

	if (0) { //works, removes ARP
		uint64_t src_mac = 0x001d09b35512ull;
		uint64_t dst_mac = 0xf46d0449baddull; //jreed HAF-reed
		//uint64_t dst_mac = 0xa021b7710c87ull; //jreed home wifi
		uint32_t ether_type = IP4_ETH_TYPE;
		secure_metadata_writeToElement(ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
		secure_metadata_writeToElement(ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
		ipv4_to_switch(ff);

		free(pdu);
	}
	if (0) { //works, sends to arp every time
		if (store_list_has_space()) {
			metadata *params = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(params);

			//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
			//uint32_t dst_ip = ntohl(ppacket->ip_dst);
			uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
			uint32_t dst_ip = next_hop.address;

			secure_metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT32);

			struct finsFrame *ff_arp = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
			ff_arp->dataOrCtrl = CONTROL;
			ff_arp->destinationID.id = ARP_ID;
			ff_arp->destinationID.next = NULL;
			ff_arp->metaData = params;

			uint32_t serial_num = gen_control_serial_num();

			ff_arp->ctrlFrame.senderID = IPV4_ID;
			ff_arp->ctrlFrame.serial_num = serial_num;
			ff_arp->ctrlFrame.opcode = CTRL_EXEC;
			ff_arp->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

			ff_arp->ctrlFrame.data_len = 0;
			ff_arp->ctrlFrame.data = NULL;

			ipv4_to_switch(ff_arp);

			//TODO store IP fdf
			//struct ipv4_store *store = store_create(serial_num, ff, pdu);
			//store_list_insert(store);
		} else {
			PRINT_ERROR("todo error");
			//TODO expand store space? remove first stored packet, send error message, & store new packet?
			free(pdu);
		}
	}
	if (1) { //works, doesn't support errors when 2 src interfaces requesting same dst MAC (only request from 1st interface)
		uint64_t src_mac;
		uint64_t dst_mac;
		//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
		//uint32_t dst_ip = ntohl(ppacket->ip_dst);
		uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
		uint32_t dst_ip = next_hop.address;

		metadata *params = ff->metaData;

		struct ipv4_interface *interface = ipv4_interface_list_find(src_ip);
		if (interface) {
			src_mac = interface->addr_mac;
			PRINT_DEBUG("src: interface=%p, mac=0x%llx, ip=%u", interface, src_mac, src_ip);

			secure_metadata_writeToElement(params, "send_src_mac", &src_mac, META_TYPE_INT64);

			interface = ipv4_interface_list_find(dst_ip);
			if (interface) {
				dst_mac = interface->addr_mac;
				PRINT_DEBUG("dst: interface=%p, mac=0x%llx, ip=%u", interface, dst_mac, dst_ip);

				secure_metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);

				uint32_t ether_type = IP4_ETH_TYPE;
				secure_metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

				ipv4_to_switch(ff); //TODO decide of go to wire or route back to IPv4
				free(pdu);
			} else {
				struct ipv4_cache *cache = ipv4_cache_list_find(dst_ip);
				if (cache) {
					if (cache->seeking) {
						PRINT_DEBUG("cache seeking: cache=%p", cache);

						if (ipv4_request_list_has_space(cache->request_list)) {

							//TODO if src is first of unique in request_list, send FCF!

							struct ipv4_request *request = ipv4_request_create(ff, src_mac, src_ip, pdu);
							ipv4_request_list_append(cache->request_list, request);

							gettimeofday(&cache->updated_stamp, 0);
						} else {
							PRINT_ERROR("Error: request_list full, request_list->len=%u, ff=%p", cache->request_list->len, ff);
							freeFinsFrame(ff);
							free(pdu);
						}
					} else {
						dst_mac = cache->addr_mac;
						PRINT_DEBUG("dst: cache=%p, mac=0x%llx, ip=%u", cache, dst_mac, dst_ip);

						struct timeval current;
						gettimeofday(&current, 0);

						if (time_diff(&cache->updated_stamp, &current) <= IPV4_CACHE_TO_DEFAULT) {
							PRINT_DEBUG("up to date cache: cache=%p", cache);

							secure_metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);

							uint32_t ether_type = IP4_ETH_TYPE;
							secure_metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

							ipv4_to_switch(ff);
							free(pdu);
						} else {
							PRINT_DEBUG("cache expired: cache=%p", cache);

							if (ipv4_request_list_has_space(cache->request_list) && store_list_has_space()) {
								metadata *params_req = (metadata *) secure_malloc(sizeof(metadata));
								metadata_create(params_req);

								secure_metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);
								secure_metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);

								struct finsFrame *ff_req = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
								ff_req->dataOrCtrl = CONTROL;
								ff_req->destinationID.id = ARP_ID;
								ff_req->destinationID.next = NULL;
								ff_req->metaData = params_req;

								uint32_t serial_num = gen_control_serial_num();

								ff_req->ctrlFrame.senderID = IPV4_ID;
								ff_req->ctrlFrame.serial_num = serial_num;
								ff_req->ctrlFrame.opcode = CTRL_EXEC;
								ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

								ff_req->ctrlFrame.data_len = 0;
								ff_req->ctrlFrame.data = NULL;

								ipv4_to_switch(ff_req);

								struct ipv4_request *request = ipv4_request_create(ff, src_mac, src_ip, pdu);
								ipv4_request_list_append(cache->request_list, request);

								struct ipv4_store *store = ipv4_store_create(serial_num, cache, request);
								ipv4_store_list_insert(store);

								cache->seeking = 1;
								gettimeofday(&cache->updated_stamp, 0);
							} else {
								if (ipv4_request_list_has_space(cache->request_list)) {
									PRINT_ERROR("Error: no space, request_list->len=%u, ff=%p", cache->request_list->len, ff);
								} else {
									PRINT_ERROR("Error: no space, store_list full, ff=%p", ff);
								}
								freeFinsFrame(ff);
								free(pdu);
							}
						}
					}
				} else {
					PRINT_DEBUG("create cache: start seeking");

					if (store_list_has_space()) {
						metadata *params_req = (metadata *) secure_malloc(sizeof(metadata));
						metadata_create(params_req);

						secure_metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);
						secure_metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);

						struct finsFrame *ff_req = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
						ff_req->dataOrCtrl = CONTROL;
						ff_req->destinationID.id = ARP_ID;
						ff_req->destinationID.next = NULL;
						ff_req->metaData = params_req;

						uint32_t serial_num = gen_control_serial_num();

						ff_req->ctrlFrame.senderID = IPV4_ID;
						ff_req->ctrlFrame.serial_num = serial_num;
						ff_req->ctrlFrame.opcode = CTRL_EXEC;
						ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

						ff_req->ctrlFrame.data_len = 0;
						ff_req->ctrlFrame.data = NULL;

						ipv4_to_switch(ff_req);

						//TODO change this remove 1 cache by order of: nonseeking then seeking, most retries, oldest timestamp
						if (!ipv4_cache_list_has_space()) {
							PRINT_DEBUG("Making space in cache_list");

							struct ipv4_cache *temp_cache = ipv4_cache_list_remove_first_non_seeking();
							if (temp_cache) {
								struct ipv4_request *temp_request;
								struct finsFrame *temp_ff;

								while (!ipv4_request_list_is_empty(temp_cache->request_list)) {
									temp_request = ipv4_request_list_remove_front(temp_cache->request_list);
									temp_ff = temp_request->ff;

									temp_ff->destinationID.id = IPV4_ID; //ff->ctrlFrame.senderID
									temp_ff->ctrlFrame.senderID = ARP_ID;
									temp_ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
									temp_ff->ctrlFrame.ret_val = 0;

									ipv4_to_switch(temp_ff);

									temp_request->ff = NULL;
									ipv4_request_free(temp_request);
								}

								ipv4_cache_free(temp_cache);
							} else {
								PRINT_ERROR("todo error");
								freeFinsFrame(ff);
								free(pdu);
								return;
							}
						}

						cache = ipv4_cache_create(dst_ip);
						ipv4_cache_list_insert(cache);

						struct ipv4_request *request = ipv4_request_create(ff, src_mac, src_ip, pdu);
						ipv4_request_list_append(cache->request_list, request);

						struct ipv4_store *store = ipv4_store_create(serial_num, cache, request);
						ipv4_store_list_insert(store);

						cache->seeking = 1;
						gettimeofday(&cache->updated_stamp, 0);
					} else {
						PRINT_ERROR("Error: no space, store_list full, ff=%p", ff);
						freeFinsFrame(ff);
						free(pdu);
					}
				}
			}
		} else {
			PRINT_ERROR("No corresponding interface: ff=%p, src_ip=%u", ff, src_ip);
			//TODO with better interface control/list this shouldn't be possible
			freeFinsFrame(ff);
			free(pdu);
		}
	}
}
