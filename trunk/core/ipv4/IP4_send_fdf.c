/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

extern finsQueue IPv4_to_Switch_Queue;
extern sem_t IPv4_to_Switch_Qsem;

extern IP4addr my_ip_addr;

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
		PRINT_ERROR("todo error")
		;
		break;
	}

	//metadata *ipv4_meta = (metadata *) fins_malloc(sizeof(metadata));
	//metadata_create(ipv4_meta);
	metadata *params = ff->metaData;

	IP4addr src_ip = pheader->source; //ppacket->ip_src;
	IP4addr dst_ip = pheader->destination; //ppacket->ip_dst;

	metadata_writeToElement(params, "recv_protocol", &protocol, META_TYPE_INT32);
	metadata_writeToElement(params, "recv_src_ip", &src_ip, META_TYPE_INT32);
	metadata_writeToElement(params, "recv_dst_ip", &dst_ip, META_TYPE_INT32);

	uint32_t recv_ttl = pheader->ttl;
	metadata_writeToElement(params, "recv_ttl", &recv_ttl, META_TYPE_INT32);

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
		uint8_t *data = (uint8_t *) fins_malloc(ff->dataFrame.pduLength);
		memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
		ff->dataFrame.pdu = data;

		PRINT_DEBUG("Freeing pdu=%p", pdu);
		free(pdu);
		break;
	default:
		PRINT_ERROR("todo error")
		;
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
	ff->dataFrame.pdu = (uint8_t *) fins_malloc(length + IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu, ppacket, IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu + IP4_MIN_HLEN, pdu, length);

	if (1) {
		uint64_t src_mac = 0x001d09b35512ull;
		uint64_t dst_mac = 0xf46d0449baddull; //jreed HAF-reed
		//uint64_t dst_mac = 0xa021b7710c87ull; //jreed home wifi
		uint32_t ether_type = IP4_ETH_TYPE;
		metadata_writeToElement(ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
		metadata_writeToElement(ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);
		metadata_writeToElement(ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
		ipv4_to_switch(ff);

		free(pdu);
	}
	if (0) {
		if (store_list_has_space()) {
			metadata *params = (metadata *) fins_malloc(sizeof(metadata));
			metadata_create(params);

			//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
			//uint32_t dst_ip = ntohl(ppacket->ip_dst);
			uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
			uint32_t dst_ip = next_hop.address;

			metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT32);
			metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT32);

			struct finsFrame *ff_arp = (struct finsFrame *) fins_malloc(sizeof(struct finsFrame));
			ff_arp->dataOrCtrl = CONTROL;
			ff_arp->destinationID.id = ARP_ID;
			ff_arp->destinationID.next = NULL;
			ff_arp->metaData = params;

			uint32_t serial_num = gen_control_serial_num();

			ff_arp->ctrlFrame.senderID = IP_ID;
			ff_arp->ctrlFrame.serial_num = serial_num;
			ff_arp->ctrlFrame.opcode = CTRL_EXEC;
			ff_arp->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

			ff_arp->ctrlFrame.data_len = 0;
			ff_arp->ctrlFrame.data = NULL;

			ipv4_to_switch(ff_arp);

			//TODO store IP fdf
			struct ip4_store *store = store_create(serial_num, ff, pdu);
			store_list_insert(store);
		} else {
			PRINT_ERROR("todo error");
			//TODO expand store space? remove first stored packet, send error message, & store new packet?
			//free(pdu);
		}
	}
	/*
	if (1) {
		struct arp_interface *interface;
		struct arp_cache *cache;
		struct arp_cache *temp_cache;
		uint64_t dst_mac;
		uint64_t src_mac;

		//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
		//uint32_t dst_ip = ntohl(ppacket->ip_dst);
		uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
		uint32_t dst_ip = next_hop.address;

		metadata *params = ff->metaData;

		interface = interface_list_find(src_ip);
		if (interface) {
			src_mac = interface->mac_addr;
			PRINT_DEBUG("src: interface=%p, ip=%u, mac=%llx", interface, src_ip, src_mac);

			metadata_writeToElement(params, "send_src_mac", &src_mac, META_TYPE_INT64);

			interface = interface_list_find(dst_ip);
			if (interface) {
				dst_mac = interface->mac_addr;
				PRINT_DEBUG("dst: interface=%p, ip=%u, mac=%llx", interface, dst_ip, dst_mac);

				metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);

				uint32_t ether_type = IP4_ETH_TYPE;
				metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

				ipv4_to_switch(ff);
			} else {
				cache = cache_list_find(dst_ip);
				if (cache) {
					if (cache->seeking) {
						PRINT_DEBUG("cache seeking: cache=%p", cache);
						struct arp_request *request = request_create(ff, src_mac, src_ip);
						if (request_list_has_space(cache->request_list)) {
							request_list_append(cache->request_list, request);
						} else {
							PRINT_ERROR("Error: request_list full, request_list->len=%d, ff=%p", cache->request_list->len, ff);
							request_free(request);
							freeFinsFrame(ff);
						}
					} else {
						dst_mac = cache->mac_addr;
						PRINT_DEBUG("dst: cache=%p, ip=%u, mac=%llx", cache, dst_ip, dst_mac);

						struct timeval current;
						gettimeofday(&current, 0);

						if (time_diff(&cache->updated_stamp, &current) <= ARP_CACHE_TO_DEFAULT) {
							PRINT_DEBUG("up to date cache: cache=%p", cache); PRINT_DEBUG("dst: cache=%p, ip=%u, mac=%llx", cache, dst_ip, dst_mac);

							metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);

							uint32_t ether_type = IP4_ETH_TYPE;
							metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

							ipv4_to_switch(ff);
						} else {
							PRINT_DEBUG("cache expired: cache=%p", cache);

							metadata *params_req = (metadata *) fins_malloc(sizeof(metadata));
							if (params_req == NULL) {
								PRINT_ERROR("alloc error");
								exit(-1);
							}
							metadata_create(params_req);

							metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);
							metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);

							struct finsFrame *ff_req = (struct finsFrame *) fins_malloc(sizeof(struct finsFrame));
							if (ff_req == NULL) {
								PRINT_ERROR("alloc error");
								exit(-1);
							}

							ff_req->dataOrCtrl = CONTROL;
							ff_req->destinationID.id = ARP_ID;
							ff_req->destinationID.next = NULL;
							ff_req->metaData = params;

							uint32_t serial_num = gen_control_serial_num();

							ff_req->ctrlFrame.senderID = IP_ID;
							ff_req->ctrlFrame.serial_num = serial_num;
							ff_req->ctrlFrame.opcode = CTRL_EXEC;
							ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

							ff_req->ctrlFrame.data_len = 0;
							ff_req->ctrlFrame.data = NULL;

							ipv4_to_switch(ff_req);

							//#############################TODO checked up to here

							struct arp_message msg;
							gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

							struct finsFrame *ff_req = arp_to_fdf(&msg);
							if (arp_to_switch(ff_req)) {
								cache->seeking = 1;
								cache->retries = 0;

								gettimeofday(&cache->updated_stamp, 0); //TODO use this value as start of seeking
								start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);

								struct arp_request *request = request_create(ff, src_mac, src_ip);
								if (request_list_has_space(cache->request_list)) {
									request_list_append(cache->request_list, request);
								} else {
									PRINT_ERROR("Error: request_list full, request_list->len=%d", cache->request_list->len);
									request_free(request);

									ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
									ff->ctrlFrame.senderID = ARP_ID;
									ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
									ff->ctrlFrame.ret_val = 0;

									arp_to_switch(ff);
								}
							} else {
								PRINT_ERROR("switch send failed");
								freeFinsFrame(ff_req);

								ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
								ff->ctrlFrame.senderID = ARP_ID;
								ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
								ff->ctrlFrame.ret_val = 0;

								arp_to_switch(ff);
							}
						}
					}
				} else {
					PRINT_DEBUG("dst: start seeking");

					cache = cache_create(dst_ip);
					if (!cache_list_has_space()) {
						PRINT_DEBUG("Making space in cache_list");

						temp_cache = cache_list_remove_first_non_seeking();
						if (temp_cache) {
							struct arp_request *temp_request;
							struct finsFrame *temp_ff;

							while (!request_list_is_empty(temp_cache->request_list)) {
								temp_request = request_list_remove_front(temp_cache->request_list);
								temp_ff = temp_request->ff;

								temp_ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
								temp_ff->ctrlFrame.senderID = ARP_ID;
								temp_ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
								temp_ff->ctrlFrame.ret_val = 0;

								arp_to_switch(temp_ff);

								request_free(temp_request);
							}

							cache_shutdown(temp_cache);
							cache_free(temp_cache);
						} else {
							PRINT_ERROR("Cache full");

							ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
							ff->ctrlFrame.senderID = ARP_ID;
							ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
							ff->ctrlFrame.ret_val = 0;

							arp_to_switch(ff);

							cache_shutdown(cache);
							cache_free(cache);
							return;
						}
					}
					cache_list_insert(cache);
					cache->seeking = 1;
					cache->retries = 0;

					gettimeofday(&cache->updated_stamp, 0);
					start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);

					struct arp_request *request = request_create(ff, src_mac, src_ip);
					request_list_append(cache->request_list, request);

					if (store_list_has_space()) {
						metadata *params_req = (metadata *) fins_malloc(sizeof(metadata));
						if (params_req == NULL) {
							PRINT_ERROR("alloc error");
							exit(-1);
						}
						metadata_create(params_req);

						//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
						//uint32_t dst_ip = ntohl(ppacket->ip_dst);
						//uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
						//uint32_t dst_ip = next_hop.address;

						metadata_writeToElement(params_req, "src_ip", &src_ip, META_TYPE_INT32);
						metadata_writeToElement(params_req, "dst_ip", &dst_ip, META_TYPE_INT32);

						struct finsFrame *ff_req = (struct finsFrame *) fins_malloc(sizeof(struct finsFrame));
						if (ff_req == NULL) {
							PRINT_ERROR("alloc error");
							exit(-1);
						}

						ff_req->dataOrCtrl = CONTROL;
						ff_req->destinationID.id = ARP_ID;
						ff_req->destinationID.next = NULL;
						ff_req->metaData = params;

						uint32_t serial_num = gen_control_serial_num();

						ff_req->ctrlFrame.senderID = IPv4_ID;
						ff_req->ctrlFrame.serial_num = serial_num;
						ff_req->ctrlFrame.opcode = CTRL_EXEC;
						ff_req->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

						ff_req->ctrlFrame.data_len = 0;
						ff_req->ctrlFrame.data = NULL;

						ipv4_to_switch(ff_req);

						//TODO store IP fdf
						struct ip4_store *store = store_create(serial_num, ff, pdu);
						store_list_insert(store);
					} else {
						PRINT_ERROR("todo error");
						//TODO expand store space? remove first stored packet, send error message, & store new packet?
						//free(pdu);
					}

					//########
					PRINT_DEBUG("store, send FCF to ARP, create cache");
					metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);

					uint32_t ether_type = IP4_ETH_TYPE;
					metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

					ipv4_to_switch(ff);
					//########

					dst_mac = ARP_MAC_BROADCAST;

					struct arp_message msg;
					gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

					struct finsFrame *ff_req = arp_to_fdf(&msg);
					if (arp_to_switch(ff_req)) {
					} else {
						PRINT_DEBUG("switch send failed");
						freeFinsFrame(ff_req);

						ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
						ff->ctrlFrame.senderID = ARP_ID;
						ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
						ff->ctrlFrame.ret_val = 0;

						arp_to_switch(ff);
					}
				}
			}
		} else {
			PRINT_ERROR("No corresponding interface: ff=%p, src_ip=%u", ff, src_ip);
			//TODO with better interface control/list this shouldn't be possible
			freeFinsFrame(ff);
		}
	}
}
