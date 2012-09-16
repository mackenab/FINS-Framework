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

double time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	double decimal = 0, diff = 0;

	PRINT_DEBUG("Entered: time1=%p, time2=%p", time1, time2);

	//PRINT_DEBUG("getting seqEndRTT=%d current=(%d, %d)\n", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

	if (time1->tv_usec > time2->tv_usec) {
		decimal = (1000000.0 + time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec - 1.0;
	} else {
		decimal = (time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec;
	}
	diff += decimal;

	diff *= 1000.0;

	PRINT_DEBUG("diff=%f", diff);
	return diff;
}

void arp_exec_get_addr(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip) {
	struct arp_interface *interface;
	struct arp_cache *cache;
	struct arp_cache *old;
	uint64_t dst_mac;
	uint64_t src_mac;

	PRINT_DEBUG("Entered: ff=%p dst_ip=%u src_ip=%u", ff, dst_ip, src_ip);

	interface = interface_list_find(src_ip);
	if (interface) {
		src_mac = interface->mac_addr;

		metadata *params = ff->metaData;
		metadata_writeToElement(params, "src_mac", &src_mac, META_TYPE_INT64);

		interface = interface_list_find(dst_ip);
		if (interface) {
			dst_mac = interface->mac_addr;
			metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

			ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
			ff->ctrlFrame.senderID = ARP_ID;
			ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;

			arp_to_switch(ff);
		} else {
			cache = cache_list_find(dst_ip);
			if (cache) {
				if (cache->seeking) {
					struct arp_request *request = request_create(ff, src_mac, src_ip);
					if (request_list_has_space(cache->request_list)) {
						request_list_append(cache->request_list, request);
					} else {
						PRINT_DEBUG("todo error");

						//TODO send error FCF
					}
				} else {
					dst_mac = cache->mac_addr;

					struct timeval current;
					gettimeofday(&current, 0);

					if (time_diff(&cache->updated_stamp, &current) <= ARP_CACHE_TO_DEFAULT) {
						metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

						ff->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
						ff->ctrlFrame.senderID = ARP_ID;
						ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;

						arp_to_switch(ff);
					} else {
						struct arp_message msg;
						gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

						struct finsFrame *ff_req = arp_to_fdf(&msg);
						if (arp_to_switch(ff_req)) {
							cache->seeking = 1;
							cache->retries = 0;

							gettimeofday(&cache->updated_stamp, 0); //TODO use this value as start of seeking
							arp_start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);

							struct arp_request *request = request_create(ff, src_mac, src_ip);
							if (request_list_has_space(cache->request_list)) {
								request_list_append(cache->request_list, request);
							} else {
								PRINT_DEBUG("todo error");

								//TODO send error FCF
							}
						} else {
							PRINT_DEBUG("todo error");
							free(ff_req->dataFrame.pdu);
							freeFinsFrame(ff_req);

							//TODO send error FCF
						}
					}
				}
			} else {
				dst_mac = ARP_MAC_BROADCAST;

				struct arp_message msg;
				gen_requestARP(&msg, src_mac, src_ip, dst_mac, dst_ip);

				struct finsFrame *ff_req = arp_to_fdf(&msg);
				if (arp_to_switch(ff_req)) {
					cache = cache_create(dst_ip);
					if (!cache_list_has_space()) {
						old = cache_list_remove_front(); //TODO change to finding first non seeking cache in list

						//TODO send error FCF for each dropped request

						cache_shutdown(old);
						cache_free(old);
					}
					cache_list_insert(cache);
					cache->seeking = 1;
					cache->retries = 0;

					gettimeofday(&cache->updated_stamp, 0);
					arp_start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);

					struct arp_request *request = request_create(ff, src_mac, src_ip);
					request_list_append(cache->request_list, request);
				} else {
					PRINT_DEBUG("todo error");
					free(ff_req->dataFrame.pdu);
					freeFinsFrame(ff_req);

					//TODO send error FCF
				}
			}
		}
	} else {
		PRINT_DEBUG("todo error");
	}
}

void arp_in_fdf(struct finsFrame *ff) {
	struct arp_message *msg;

	PRINT_DEBUG("Entered: ff=%p", ff);

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
						PRINT_DEBUG("todo error");
						free(ff_reply->dataFrame.pdu);
						freeFinsFrame(ff_reply);
					}
				} else {
					PRINT_DEBUG("Reply");

					struct arp_cache *cache = cache_list_find(src_ip);
					if (cache) {
						if (cache->seeking) {
							PRINT_DEBUG("Updating host: node=%p, mac=0x%llx, ip=%u", cache, src_mac, src_ip);
							arp_stop_timer(cache->to_fd);
							gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

							cache->seeking = 0;
							cache->mac_addr = src_mac;

							struct arp_request *request;
							struct finsFrame *ff_resp;

							while (!request_list_is_empty(cache->request_list)) {
								request = request_list_remove_front(cache->request_list);
								ff_resp = request->ff;

								metadata_writeToElement(ff_resp->metaData, "dst_mac", &src_mac, META_TYPE_INT64);

								ff_resp->destinationID.id = IP_ID; //ff->ctrlFrame.senderID
								ff_resp->ctrlFrame.senderID = ARP_ID;
								ff_resp->ctrlFrame.opcode = CTRL_EXEC_REPLY;

								if (!arp_to_switch(ff_resp)) {
									freeFinsFrame(ff_resp);
								}

								request_free(request);
							}
						} else {
							//TODO Drop?
							PRINT_DEBUG("Not seeking addr. Dropping...");
						}
					} else {
						PRINT_DEBUG("No corresponding request. Dropping...");
					}
				}
			} else {
				PRINT_DEBUG("No corresponding interface. Dropping...");
			}
		} else {
			PRINT_DEBUG("Invalid Message. Dropping...")
		}

		free(msg);
	} else {
		PRINT_DEBUG("Bad ARP message. Dropping...");
	}

	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

void arp_out_fdf(struct finsFrame *ff) {

}

void arp_handle_to(struct arp_cache *cache) {
	if (cache->retries < ARP_RETRIES) {
		uint64_t dst_mac = ARP_MAC_BROADCAST;
		uint32_t dst_ip = cache->ip_addr;

		if (request_list_is_empty(cache->request_list)) {
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
				arp_start_timer(cache->to_fd, ARP_RETRANS_TO_DEFAULT);
			} else {
				PRINT_DEBUG("todo error");
				free(ff_req->dataFrame.pdu);
				freeFinsFrame(ff_req);

				//TODO send error FCF
			}
		}
	} else {
		//TODO send error FCF
	}
}
