/*
 * arp_in_out.c
 *
 *  Created on: Oct 18, 2010
 *      Author: Syed Amaar Ahmad
 */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <finstypes.h>
#include <finsdebug.h>
#include <metadata.h>
#include "arp.h"

//struct finsFrame *fins_arp_in; /**<This is the pointer to the fins frame received by the ARP module*/

void arp_out_fdf(struct finsFrame *ff) {

}

void arp_in_fdf(struct finsFrame *ff) {
	struct arp_message *msg;

	PRINT_DEBUG("Entered: ff=%p", ff);

	msg = fdf_to_arp(ff);
	if (msg) {
		print_msgARP(msg);

		if (check_valid_arp(msg)) {
			uint32_t dst_ip = msg->target_IP_addrs;

			//TODO add sems
			struct arp_entry *dst_entry = search_list_new(interface_list, dst_ip);
			if (dst_entry) {
				uint64_t dst_mac = dst_entry->MAC_addrs;

				uint32_t src_ip = msg->sender_IP_addrs;
				uint64_t src_mac = msg->sender_MAC_addrs;

				if (msg->operation == ARP_OP_REQUEST) {
					PRINT_DEBUG("Request");

					struct arp_message arp_msg_reply;
					gen_replyARP_new(&arp_msg_reply, dst_mac, dst_ip, src_mac, src_ip);

					struct finsFrame *ff_reply = arp_to_fdf(&arp_msg_reply);
					if (ff_reply) {
						if (!arp_to_switch(ff_reply)) {
							PRINT_DEBUG("todo error");
							free(ff_reply->dataFrame.pdu);
							freeFinsFrame(ff_reply);
						}
					} else {
						PRINT_DEBUG("todo error");
					}
				} else {
					PRINT_DEBUG("Reply");

					struct arp_entry *src_entry = search_list_new(cache_list, src_ip);
					if (src_entry) {
						PRINT_DEBUG("Updating host: node=%p, ip=%u, mac=0x%llx", src_entry, src_ip, src_mac);

						//TODO update IP/MAC
						//TODO update time
					} else {
						src_entry = (struct arp_entry *) malloc(sizeof(struct arp_entry));
						if (src_entry == NULL) {
							PRINT_ERROR("node malloc error");
							return;
						}

						src_entry->IP_addrs = src_ip;
						src_entry->MAC_addrs = src_mac;
						//TODO add time created etc

						src_entry->next = cache_list;
						cache_list = src_entry;

						PRINT_DEBUG("Adding host: node=%p, ip=%u, mac=0x%llx", src_entry, src_ip, src_mac);
					}

					//TODO add search for FCF, drop if can't find FCF
					//find FCF from queue, update meta, & send to switch

					//arp_out(REPLYCONTROL); //generate fins control carrying neighbor's MAC address
					//arp_out_ctrl(src_ip, ff);

					//arp_to_switch(ff);
				}
			} else {
				PRINT_DEBUG("No corresponding interface. Dropping...");
				//TODO drop packet? since is trying to reach different or outdated IP
			}
		} else {
			PRINT_DEBUG("Invalid Message. Dropping...")
		}
	} else {
		PRINT_DEBUG("Bad ARP message. Dropping...");
	}

	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

void arp_exec_get_addr(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip) {
	struct arp_entry *dst_entry;
	struct arp_entry *src_entry;
	uint64_t dst_mac;
	uint64_t src_mac;

	PRINT_DEBUG("Entered: ff=%p dst_ip=%u src_ip=%u", ff, dst_ip, src_ip);

	src_entry = search_list_new(interface_list, src_ip);
	if (src_entry) {
		src_mac = src_entry->MAC_addrs;

		metadata *params = ff->metaData;
		metadata_writeToElement(params, "src_mac", &src_mac, META_TYPE_INT64);

		dst_entry = search_list_new(interface_list, dst_ip);
		if (dst_entry) {
			dst_mac = dst_entry->MAC_addrs;
			metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

			ff->destinationID.id = IPID; //ff->ctrlFrame.senderID
			ff->ctrlFrame.senderID = ARPID;
			ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;

			arp_to_switch(ff);
		} else {
			dst_entry = search_list_new(cache_list, dst_ip);
			if (dst_entry) {
				if (1 /* timecheck */) { //TODO add time check here
					dst_mac = dst_entry->MAC_addrs;
					metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);

					ff->destinationID.id = IPID; //ff->ctrlFrame.senderID
					ff->ctrlFrame.senderID = ARPID;
					ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;

					arp_to_switch(ff);
				} else {
					//TODO if TO, send ARP to old address, if timeout again, broadcast
					//TODO save fcf in queue
				}
			} else {
				dst_mac = ARP_MAC_BROADCAST;

				struct arp_message msg;
				//gen_requestARP_new(msg, src_mac, src_ip, ARP_MAC_NULL, dst_ip); //TODO remove/optimize?
				gen_requestARP_new(&msg, src_mac, src_ip, dst_mac, dst_ip); //TODO remove/optimize?

				struct finsFrame *ff_req = arp_to_fdf(&msg);
				if (ff_req) {
					if (!arp_to_switch(ff_req)) {
						PRINT_DEBUG("todo error");
						free(ff_req->dataFrame.pdu);
						freeFinsFrame(ff_req);
					}
				} else {
					PRINT_DEBUG("todo error");
				}

				struct arp_store *store = (struct arp_store *) malloc(sizeof(struct arp_store));
				if (store == NULL) {
					PRINT_ERROR("failed to create store: ff=%p", ff);
					return;
				}

				store->ff = ff;
				store->dst_ip = dst_ip;
				store->src_ip = src_ip;

				store->next = store_list;
				store_list = store;
			}
		}
	} else {
		PRINT_DEBUG("todo error");
	}
}

/**@brief this function receives an arp message from outside and processes it
 * @param fins_received is the pointer to the fins frame which has been received by the ARP module
 */
void arp_in(struct finsFrame *ff) {

	struct arp_message *arp_msg_ptr;

	/**request or reply received from the network and as transmitted by the ethernet stub*/
	if (ff->dataOrCtrl == DATA) {
		if (ff->destinationID.id != (unsigned char) ARPID) {
			PRINT_DEBUG("todo error");
			return;
		}

		PRINT_DEBUG("ARP Data, ff=%p", ff);

		if (ff->dataFrame.pduLength < sizeof(struct arp_hdr)) {
			PRINT_DEBUG("The declared length is not equal to the actual length. pkt_len=%u len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
			freeFinsFrame(ff);
			return;
		} else if (ff->dataFrame.pduLength > sizeof(struct arp_hdr)) {
			PRINT_DEBUG("The declared length is not equal to the actual length. pkt_len=%u len=%u", sizeof(struct arp_hdr), ff->dataFrame.pduLength);
		}

		fins_to_arp(ff, packet); //extract arp hdr from the fins frame
		host_to_net(packet); //convert it into the right format (e.g. htons issue etc.)
		arp_msg_ptr = &arp_msg;
		arp_hdr_to_msg(packet, arp_msg_ptr); //convert the hdr into an internal ARP message (e.g. use uint64_t instead of unsigned char)

		print_msgARP(arp_msg_ptr);

		if (check_valid_arp(arp_msg_ptr) == 1) {
			PRINT_DEBUG("ARP Data valid");

			update_cache(arp_msg_ptr);

			if ((arp_msg_ptr->target_IP_addrs == interface_IP_addrs) && (arp_msg_ptr->operation == ARP_OP_REQUEST)) {
				arp_out(REPLYDATA); //generate reply
			} else if ((arp_msg_ptr->target_IP_addrs == interface_IP_addrs) && (arp_msg_ptr->operation == ARP_OP_REPLY)) {
				target_IP_addrs = arp_msg.sender_IP_addrs;
				arp_out(REPLYCONTROL); //generate fins control carrying neighbor's MAC address
			}
		}
	} else if (ff->dataOrCtrl == CONTROL) {/**as a request received from the ethernet stub-- IP address is provided in this fins control frame*/
		if (ff->destinationID.id != (unsigned char) ARPID) {
			PRINT_DEBUG("todo error");
			//TODO not possible? unless switch not working right or
			return;
		}

		if (ff->ctrlFrame.opcode == 333/*WRITEREQUEST*/) {
			PRINT_DEBUG("ARP Control, ff=%p", ff);

			memcpy(fins_IP_address, ff->ctrlFrame.paramterValue, PROTOCOLADDRSLEN);
			target_IP_addrs = gen_IP_addrs(fins_IP_address[0], fins_IP_address[1], fins_IP_address[2], fins_IP_address[3]);

			/**request initiated by the ethernet stub*/
			if (search_list(cache_list, target_IP_addrs) == 0) { //i.e. not found
				arp_out(REQUESTDATA); //generate arp request for MAC address and send out to the network
			} else {
				arp_out(REPLYCONTROL); //generate fins control carrying MAC address foe ethernet
			}
		}
	} else {
		PRINT_DEBUG("todo error")
	}

	print_cache();
}

/**@brief this function sends a fins frame outside the modulebased on what has been received
 @param response indicates what kind of a fins frame (ctrl. or data) and the type of ARP has
 to be sent out
 */
void arp_out(int response) {

	//struct finsFrame fins_arp_out; /**<This is the fins frame which will be sent out. It can be either data or control*/
	struct finsFrame *fins_arp_out = (struct finsFrame*) malloc(sizeof(struct finsFrame));

	if (response == REQUESTDATA) {
		//arp_out_request(target_IP_addrs, fins_arp_out);
	} else if (response == REPLYDATA) {
		arp_out_reply(fins_arp_out);
	} else if (response == REPLYCONTROL) {
		arp_out_ctrl(target_IP_addrs, fins_arp_out);
	} else {
		PRINT_DEBUG("problem: response=%d", response);
	}
	//output fins_arp_out to queue
	arp_to_switch(fins_arp_out);
}

/**@brief This function is only activated once the cache already has the MAC
 * address of the sought IP address. It sends out a Fins control frame to the ethernet stub
 * @param sought_IP_addrs is the IP address whose associated MAC address is sought
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_ctrl(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out) {
	PRINT_DEBUG("sought_IP_addrs=%u ff=%p", sought_IP_addrs, fins_arp_out);

	fins_arp_out->destinationID.id = ETHERSTUBID;
	fins_arp_out->dataOrCtrl = CONTROL;
	fins_arp_out->ctrlFrame.senderID = ARPID;
	fins_arp_out->ctrlFrame.opcode = 222/*READREPLY*/;
	MAC_addrs_conversion(search_MAC_addrs(sought_IP_addrs, cache_list), fins_MAC_address);
	fins_arp_out->ctrlFrame.paramterValue = fins_MAC_address;
}

/**@brief This function sends out a fins frame that passes an arp request out to the network
 * @param sought_IP_addrs is the IP address whose associated MAC address is sought
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_request(struct finsFrame *ff, uint32_t dst_ip, uint32_t src_ip, uint64_t src_mac) {

	PRINT_DEBUG("sought_IP_addrs=%u ff=%p", dst_ip, ff);

	gen_requestARP_new(&arp_msg, src_mac, src_ip, 0, dst_ip);
	arp_msg_to_hdr(&arp_msg, packet);
	host_to_net(packet);
	print_arp_hdr(packet);
	//arp_to_fins(packet, ff); /**arp request to be sent to network*/

	metadata *params = ff->metaData;
	if (params == NULL) {
		PRINT_ERROR("failed to create matadata: ff=%p", ff);
		return;
	}

	//metadata_writeToElement(params, "src_ip", (uint32_t *) pckt_arp->sender_MAC_addrs, META_TYPE_INT);
	//metadata_writeToElement(params, "dst_ip", (uint32_t *) pckt_arp->target_IP_addrs, META_TYPE_INT);
	//metadata_writeToElement(params, "src_mac", pckt_arp->sender_MAC_addrs, META_TYPE_STRING) ;
	//metadata_writeToElement(params, "dst_mac", pckt_arp->target_MAC_addrs, META_TYPE_STRING) ;

	uint32_t type = (uint32_t) ARP_TYPE;
	metadata_writeToElement(params, "ether_type", &type, META_TYPE_INT);

	ff->destinationID.id = ETHERSTUBID;
	ff->dataOrCtrl = DATA;
	ff->dataFrame.pdu = (unsigned char *) packet;
	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = sizeof(struct arp_hdr);
	ff->metaData = params;

	arp_to_switch(ff);
}

/**@brief This function sends out a fins frame with a reply arp in response to a request
 * from the network
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_reply(struct finsFrame *ff) {
	PRINT_DEBUG("ff=%p", ff);

	struct arp_message arp_msg_reply;

	gen_replyARP(&arp_msg, &arp_msg_reply);
	arp_msg_to_hdr(&arp_msg_reply, packet);
	host_to_net(packet);
	print_arp_hdr(packet);
	arp_to_fins(packet, ff); /**arp reply to be sent to network */

	arp_to_switch(ff);
}
