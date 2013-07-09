/*
 * arp_in_out.c
 *
 *  Created on: September 5, 2012
 *      Author: Jonathan Reed
 */
#include "arp_internal.h"

void arp_exec_get_addr(struct fins_module *module, struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, src_ip=%u, dst_ip=%u", module, ff, src_ip, dst_ip);
	struct arp_data *md = (struct arp_data *) module->data;

	struct if_record *ifr;
	struct arp_cache *cache;
	struct arp_cache *temp_cache;
	uint64_t dst_mac;
	uint64_t src_mac;

	ifr = (struct if_record *) list_find1(md->if_list, ifr_ipv4_test, &src_ip);
	if (ifr != NULL) {
		src_mac = ifr->mac;
		PRINT_DEBUG("src: if_index=%d, mac=0x%012llx, ip=%u", ifr->index, src_mac, src_ip);

		secure_metadata_writeToElement(ff->metaData, "src_mac", &src_mac, META_TYPE_INT64);

		cache = (struct arp_cache *) list_find1(md->cache_list, arp_cache_ip_test, &dst_ip);
		if (cache != NULL) {
			if (cache->seeking != 0) {
				PRINT_DEBUG("cache seeking: cache=%p", cache);
				if (list_has_space(cache->request_list)) {
					struct arp_request *request = arp_request_create(ff, src_mac, src_ip);
					list_append(cache->request_list, request);
				} else {
					PRINT_ERROR("Error: request_list full, request_list->len=%d", cache->request_list->len);
					module_reply_fcf(module, ff, FCF_FALSE, 0);
				}
			} else {
				dst_mac = cache->mac;
				PRINT_DEBUG("dst: cache=%p, mac=0x%012llx, ip=%u", cache, dst_mac, dst_ip);

				struct timeval current;
				gettimeofday(&current, 0);

				if (time_diff(&cache->updated_stamp, &current) <= ARP_CACHE_TO_DEFAULT) {
					PRINT_DEBUG("up to date cache: cache=%p", cache);

					secure_metadata_writeToElement(ff->metaData, "dst_mac", &dst_mac, META_TYPE_INT64);

					ff->destinationID = ff->ctrlFrame.sender_id;
					ff->ctrlFrame.sender_id = module->index;
					ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
					ff->ctrlFrame.ret_val = FCF_TRUE;

					module_to_switch(module, ff);
				} else {
					PRINT_DEBUG("cache expired: cache=%p", cache);

					struct arp_message msg;
					gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

					struct finsFrame *ff_req = arp_to_fdf(&msg);
					int sent = module_send_flow(module, ff_req, ARP_FLOW_INTERFACE);
					if (sent > 0) {
						cache->seeking = 1;
						cache->retries = 0;

						gettimeofday(&cache->updated_stamp, 0); //TODO use this value as start of seeking
						timer_once_start(cache->to_data->tid, ARP_RETRANS_TO_DEFAULT);

						if (list_has_space(cache->request_list)) {
							struct arp_request *request = arp_request_create(ff, src_mac, src_ip);
							list_append(cache->request_list, request);
						} else {
							PRINT_ERROR("Error: request_list full, request_list->len=%d", cache->request_list->len);
							module_reply_fcf(module, ff, FCF_FALSE, 0);
						}
					} else {
						PRINT_ERROR("switch send failed");
						freeFinsFrame(ff_req);
						module_reply_fcf(module, ff, FCF_FALSE, 0);
					}
				}
			}
		} else {
			PRINT_DEBUG("create cache: start seeking");

			dst_mac = ARP_MAC_BROADCAST;

			struct arp_message msg;
			gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

			struct finsFrame *ff_req = arp_to_fdf(&msg);
			PRINT_DEBUG("module->data=%p", module->data);

			int sent = module_send_flow(module, ff_req, ARP_FLOW_INTERFACE);
			if (sent > 0) {
				//TODO change this remove 1 cache by order of: nonseeking then seeking, most retries, oldest timestamp
				if (!list_has_space(md->cache_list)) {
					PRINT_DEBUG("Making space in cache_list");

					//temp_cache = arp_cache_list_remove_first_non_seeking();
					temp_cache = (struct arp_cache *) list_find(md->cache_list,arp_cache_non_seeking_test);
					if (temp_cache != NULL) {
						list_remove(md->cache_list, temp_cache);

						struct arp_request *temp_request;
						struct finsFrame *temp_ff;

						while (!list_is_empty(temp_cache->request_list)) {
							temp_request = (struct arp_request *) list_remove_front(temp_cache->request_list);
							temp_ff = temp_request->ff;

							module_reply_fcf(module, temp_ff, FCF_FALSE, 0);

							temp_request->ff = NULL;
							arp_request_free(temp_request);
						}

						arp_cache_shutdown(temp_cache);
						arp_cache_free(temp_cache);
					} else {
						PRINT_ERROR("Cache full");
						module_reply_fcf(module, ff, FCF_FALSE, 0);
						return;
					}
				}

				cache = arp_cache_create(dst_ip, &md->interrupt_flag, module->event_sem);
				list_append(md->cache_list, cache);
				cache->seeking = 1;
				cache->retries = 0;

				gettimeofday(&cache->updated_stamp, 0);
				timer_once_start(cache->to_data->tid, ARP_RETRANS_TO_DEFAULT);

				struct arp_request *request = arp_request_create(ff, src_mac, src_ip);
				list_append(cache->request_list, request);
			} else {
				PRINT_DEBUG("switch send failed");
				freeFinsFrame(ff_req);

				module_reply_fcf(module, ff, FCF_FALSE, 0);
			}
		}
	} else {
		struct in_addr temp_src = { .s_addr = htonl(src_ip) };
		PRINT_WARN("FCF Used src_ip that has no corresponding interface: ff=%p, src_ip='%s' (%u)", ff, inet_ntoa(temp_src), src_ip);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
	}
}

void arp_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct arp_data *md = (struct arp_data *) module->data;

	struct arp_message *msg = fdf_to_arp(ff);
	if (msg != NULL) {
		print_msgARP(msg);

		if (check_valid_arp(msg)) {
			uint32_t dst_ip = msg->target_IP_addrs;

			struct if_record *ifr = (struct if_record *) list_find1(md->if_list, ifr_ipv4_test, &dst_ip);
			if (ifr != NULL) {
				uint64_t dst_mac = ifr->mac;

				uint32_t src_ip = msg->sender_IP_addrs;
				uint64_t src_mac = msg->sender_MAC_addrs;

				if (msg->operation == ARP_OP_REQUEST) {
					PRINT_DEBUG("Request");

					struct arp_message arp_msg_reply;
					gen_replyARP(&arp_msg_reply, dst_mac, dst_ip, src_mac, src_ip);

					struct finsFrame *ff_reply = arp_to_fdf(&arp_msg_reply);

					if (!module_send_flow(module, ff_reply, ARP_FLOW_INTERFACE)) {
						PRINT_WARN("todo error");
						freeFinsFrame(ff_reply);
					}
				} else {
					PRINT_DEBUG("Reply");

					struct arp_cache *cache = (struct arp_cache *) list_find1(md->cache_list, arp_cache_ip_test, &src_ip);
					if (cache != NULL) {
						if (cache->seeking != 0) {
							PRINT_DEBUG("Updating host: cache=%p, mac=0x%012llx, ip=%u", cache, src_mac, src_ip);
							timer_stop(cache->to_data->tid);
							cache->to_flag = 0;
							gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

							cache->seeking = 0;
							cache->mac = src_mac;

							struct arp_request *request;
							struct finsFrame *ff_resp;

							while (!list_is_empty(cache->request_list)) {
								request = (struct arp_request *) list_remove_front(cache->request_list);
								ff_resp = request->ff;

								secure_metadata_writeToElement(ff_resp->metaData, "dst_mac", &src_mac, META_TYPE_INT64);

								ff_resp->destinationID = ff_resp->ctrlFrame.sender_id;
								ff_resp->ctrlFrame.sender_id = module->index;
								ff_resp->ctrlFrame.opcode = CTRL_EXEC_REPLY;
								ff_resp->ctrlFrame.ret_val = FCF_TRUE;

								module_to_switch(module, ff_resp);

								request->ff = NULL;
								arp_request_free(request);
							}
						} else {
							struct in_addr temp_src = { .s_addr = htonl(src_ip) };
							PRINT_WARN("Not seeking addr. Dropping ARP reply: ff=%p, src=0x%llx/'%s' (%u)", ff, src_mac, inet_ntoa(temp_src), src_ip);
							struct in_addr temp_dst = { .s_addr = htonl(dst_ip) };
							PRINT_WARN("ff=%p, dst=0x%llx/'%s' (%u), cache=%p", ff, dst_mac, inet_ntoa(temp_dst), dst_ip, cache);
						}
					} else {
						struct in_addr temp_src = { .s_addr = htonl(src_ip) };
						struct in_addr temp_dst = { .s_addr = htonl(dst_ip) };
						PRINT_ERROR("No corresponding request. Dropping: ff=%p, src=0x%llx/'%s', dst=0x%llx/'%s'",
								ff, src_mac, inet_ntoa(temp_src), dst_mac, inet_ntoa(temp_dst));
					}
				}
			} else {
				struct in_addr temp = { .s_addr = htonl(dst_ip) };
				if (msg->operation == ARP_OP_REQUEST) {
					PRINT_WARN("No corresponding interface. Dropping ARP request: ff=%p, dst_ip='%s' (%u)", ff, inet_ntoa(temp), dst_ip);
				} else { //Reply
					PRINT_WARN("No corresponding interface. Dropping ARP reply: ff=%p, dst_ip='%s' (%u)", ff, inet_ntoa(temp), dst_ip);
				}
			}
		} else {
			PRINT_ERROR("Invalid Message. Dropping: ff=%p", ff);
		}

		PRINT_DEBUG("Freeing: msg=%p", msg);
		free(msg);
	} else {
		PRINT_ERROR("Bad ARP message. Dropping: ff=%p", ff);
	}

	freeFinsFrame(ff);
}

void arp_out_fdf(struct fins_module *module, struct finsFrame *ff) {

}

void arp_handle_to(struct fins_module *module, struct arp_cache *cache) {
	PRINT_DEBUG("Entered: module=%p, cache=%p", module, cache);
	struct arp_data *md = (struct arp_data *) module->data;

	if (cache->seeking != 0) {
		if (cache->retries < ARP_RETRIES) {
			uint64_t dst_mac = ARP_MAC_BROADCAST;
			uint32_t dst_ip = cache->ip;

			if (list_is_empty(cache->request_list)) {
				PRINT_WARN("todo error");
				//TODO retrans from default interface?
				//TODO send error FCF ?
			} else {
				struct arp_request *request = (struct arp_request *) list_look(cache->request_list, 0);

				uint64_t src_mac = request->src_mac;
				uint32_t src_ip = request->src_ip;

				struct arp_message msg;
				gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

				struct finsFrame *ff_req = arp_to_fdf(&msg);
				int sent = module_send_flow(module, ff_req, ARP_FLOW_INTERFACE);
				if (sent > 0) {
					cache->retries++;

					//gettimeofday(&cache->updated_stamp, 0);
					timer_once_start(cache->to_data->tid, ARP_RETRANS_TO_DEFAULT);
				} else {
					PRINT_WARN("todo error");
					freeFinsFrame(ff_req);

					//TODO send error FCF
				}
			}
		} else {
			PRINT_DEBUG("Unreachable address, sending error FCF");

			struct arp_request *request;
			struct finsFrame *ff;

			//TODO figure out if it rejects all requests or re-seeks per request
			while (!list_is_empty(cache->request_list)) {
				request = (struct arp_request *) list_remove_front(cache->request_list);
				ff = request->ff;
				module_reply_fcf(module, ff, FCF_FALSE, 0);

				request->ff = NULL;
				arp_request_free(request);
			}

			list_remove(md->cache_list, cache);
			arp_cache_shutdown(cache);
			arp_cache_free(cache);
		}
	} else {
		PRINT_DEBUG("Dropping TO: cache=%p", cache);
	}
}
