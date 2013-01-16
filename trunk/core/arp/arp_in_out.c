/*
 * arp_in_out.c
 *
 *  Created on: September 5, 2012
 *      Author: Jonathan Reed
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <finstypes.h>
#include <finsdebug.h>
#include <metadata.h>
#include "arp.h"

void arp_exec_get_addr(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip) {
	struct arp_interface *interface;
	struct arp_cache *cache;
	struct arp_cache *temp_cache;
	uint64_t dst_mac;
	uint64_t src_mac;

	PRINT_DEBUG("Entered: ff=%p, dst_ip=%u, src_ip=%u", ff, dst_ip, src_ip);

	metadata *params = ff->metaData;

	interface = interface_list_find(src_ip);
	if (interface) {
		src_mac = interface->mac_addr;
		PRINT_DEBUG("src: interface=%p, ip=%u, mac=%llx", interface, src_ip, src_mac);

		metadata_writeToElement(params, "src_mac", &src_mac, META_TYPE_INT64);

		interface = interface_list_find(dst_ip);
		if (interface) {
			dst_mac = interface->mac_addr;
			PRINT_DEBUG("dst: interface=%p, ip=%u, mac=%llx", interface, dst_ip, dst_mac);

			metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

			ff->destinationID.id = ff->ctrlFrame.senderID;
			ff->ctrlFrame.senderID = ARP_ID;
			ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
			ff->ctrlFrame.ret_val = 1;

			arp_to_switch(ff);
		} else {
			cache = cache_list_find(dst_ip);
			if (cache) {
				if (cache->seeking) {
					PRINT_DEBUG("cache seeking: cache=%p", cache);
					struct arp_request *request = request_create(ff, src_mac, src_ip);
					if (request_list_has_space(cache->request_list)) {
						request_list_append(cache->request_list, request);
					} else {
						PRINT_ERROR("Error: request_list full, request_list->len=%d", cache->request_list->len);
						request_free(request);

						ff->destinationID.id = ff->ctrlFrame.senderID;
						ff->ctrlFrame.senderID = ARP_ID;
						ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
						ff->ctrlFrame.ret_val = 0;

						arp_to_switch(ff);
					}
				} else {
					dst_mac = cache->mac_addr;
					PRINT_DEBUG("dst: cache=%p, ip=%u, mac=%llx", cache, dst_ip, dst_mac);

					struct timeval current;
					gettimeofday(&current, 0);

					if (time_diff(&cache->updated_stamp, &current) <= ARP_CACHE_TO_DEFAULT) {
						PRINT_DEBUG("up to date cache: cache=%p", cache);

						metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

						ff->destinationID.id = ff->ctrlFrame.senderID;
						ff->ctrlFrame.senderID = ARP_ID;
						ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
						ff->ctrlFrame.ret_val = 1;

						arp_to_switch(ff);
					} else {
						PRINT_DEBUG("cache expired: cache=%p", cache);

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

								ff->destinationID.id = ff->ctrlFrame.senderID;
								ff->ctrlFrame.senderID = ARP_ID;
								ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
								ff->ctrlFrame.ret_val = 0;

								arp_to_switch(ff);
							}
						} else {
							PRINT_ERROR("switch send failed");
							freeFinsFrame(ff_req);

							ff->destinationID.id = ff->ctrlFrame.senderID;
							ff->ctrlFrame.senderID = ARP_ID;
							ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
							ff->ctrlFrame.ret_val = 0;

							arp_to_switch(ff);
						}
					}
				}
			} else {
				PRINT_DEBUG("dst: start seeking");

				dst_mac = ARP_MAC_BROADCAST;

				struct arp_message msg;
				gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

				struct finsFrame *ff_req = arp_to_fdf(&msg);
				if (arp_to_switch(ff_req)) {
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

								temp_ff->destinationID.id = temp_ff->ctrlFrame.senderID;
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

							ff->destinationID.id = ff->ctrlFrame.senderID;
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
				} else {
					PRINT_DEBUG("switch send failed");
					freeFinsFrame(ff_req);

					ff->destinationID.id = ff->ctrlFrame.senderID;
					ff->ctrlFrame.senderID = ARP_ID;
					ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
					ff->ctrlFrame.ret_val = 0;

					arp_to_switch(ff);
				}
			}
		}
	} else {
		PRINT_ERROR("No corresponding interface: ff=%p, src_ip=%u", ff, src_ip);

		ff->destinationID.id = ff->ctrlFrame.senderID;
		ff->ctrlFrame.senderID = ARP_ID;
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		ff->ctrlFrame.ret_val = 0;

		arp_to_switch(ff);
	}
}

void arp_in_fdf(struct finsFrame *ff) {
	struct arp_message *msg;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	msg = fdf_to_arp(ff);
	if (msg) {
		print_msgARP(msg);

		if (check_valid_arp(msg)) {
			uint32_t dst_ip = msg->target_IP_addrs;

			//TODO add sems?
			struct arp_interface *interface = interface_list_find(dst_ip);
			if (interface) {
				uint64_t dst_mac = interface->mac_addr;

				uint32_t src_ip = msg->sender_IP_addrs;
				uint64_t src_mac = msg->sender_MAC_addrs;

				if (msg->operation == ARP_OP_REQUEST) {
					PRINT_DEBUG("Request");

					struct arp_message arp_msg_reply;
					gen_replyARP(&arp_msg_reply, dst_mac, dst_ip, src_mac, src_ip);

					struct finsFrame *ff_reply = arp_to_fdf(&arp_msg_reply);
					if (!arp_to_switch(ff_reply)) {
						PRINT_ERROR("todo error");
						freeFinsFrame(ff_reply);
					}
				} else {
					PRINT_DEBUG("Reply");

					struct arp_cache *cache = cache_list_find(src_ip);
					if (cache) {
						if (cache->seeking) {
							PRINT_DEBUG("Updating host: node=%p, mac=0x%llx, ip=%u", cache, src_mac, src_ip);
							stop_timer(cache->to_fd);
							cache->to_flag = 0;
							gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

							cache->seeking = 0;
							cache->mac_addr = src_mac;

							struct arp_request *request;
							struct finsFrame *ff_resp;

							while (!request_list_is_empty(cache->request_list)) {
								request = request_list_remove_front(cache->request_list);
								ff_resp = request->ff;

								metadata_writeToElement(ff_resp->metaData, "dst_mac", &src_mac, META_TYPE_INT64);

								ff_resp->destinationID.id = ff_resp->ctrlFrame.senderID;
								ff_resp->ctrlFrame.senderID = ARP_ID;
								ff_resp->ctrlFrame.opcode = CTRL_EXEC_REPLY;
								ff_resp->ctrlFrame.ret_val = 1;

								if (!arp_to_switch(ff_resp)) {
									freeFinsFrame(ff_resp);
								}

								request_free(request);
							}
						} else {
							PRINT_ERROR("Not seeking addr. Dropping: ff=%p, dst=0x%llx/%u, src=0x%llx/%u, cache=%p",
									ff, dst_mac, dst_ip, src_mac, src_ip, cache);
						}
					} else {
						PRINT_ERROR("No corresponding request. Dropping: ff=%p, dst=0x%llx/%u, src=0x%llx/%u", ff, dst_mac, dst_ip, src_mac, src_ip);
					}
				}
			} else {
				PRINT_ERROR("No corresponding interface. Dropping: ff=%p, dst_ip=%u", ff, dst_ip); //TODO change to PRINT_ERROR
			}
		} else {
			PRINT_ERROR("Invalid Message. Dropping: ff=%p", ff);
		}

		free(msg);
	} else {
		PRINT_ERROR("Bad ARP message. Dropping: ff=%p", ff);
	}

	freeFinsFrame(ff);
}

void arp_out_fdf(struct finsFrame *ff) {

}

void arp_handle_to(struct arp_cache *cache) {
	PRINT_DEBUG("Entered: cache=%p", cache);

	if (cache->seeking) {
		if (cache->retries < ARP_RETRIES) {
			uint64_t dst_mac = ARP_MAC_BROADCAST;
			uint32_t dst_ip = cache->ip_addr;

			if (request_list_is_empty(cache->request_list)) {
				PRINT_ERROR("todo error");
				//TODO retrans from default interface?
				//TODO send error FCF ?
			} else {
				struct arp_request *request = cache->request_list->front;

				uint64_t src_mac = request->src_mac;
				uint32_t src_ip = request->src_ip;

				struct arp_message msg;
				gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

				struct finsFrame *ff_req = arp_to_fdf(&msg);
				if (arp_to_switch(ff_req)) {
					cache->retries++;

					//gettimeofday(&cache->updated_stamp, 0);
					start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);
				} else {
					PRINT_ERROR("todo error");
					freeFinsFrame(ff_req);

					//TODO send error FCF
				}
			}
		} else {
			PRINT_DEBUG("Unreachable address, sending error FCF");

			struct arp_request *request;
			struct finsFrame *ff;

			while (!request_list_is_empty(cache->request_list)) {
				request = request_list_remove_front(cache->request_list);
				ff = request->ff;

				ff->destinationID.id = ff->ctrlFrame.senderID;
				ff->ctrlFrame.senderID = ARP_ID;
				ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
				ff->ctrlFrame.ret_val = 0;

				arp_to_switch(ff);

				request_free(request);
			}

			cache_list_remove(cache);
			cache_shutdown(cache);
			cache_free(cache);
		}
	} else {
		PRINT_DEBUG("Dropping TO: cache=%p", cache);
	}
}
