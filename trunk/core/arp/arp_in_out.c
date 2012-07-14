/*
 * arp_in_out.c
 *
 *  Created on: Oct 18, 2010
 *      Author: Syed Amaar Ahmad
 */

#include <stdio.h>
#include <stdlib.h>
#include<inttypes.h>
#include "finstypes.h"
#include "arp.h"
#include "finsdebug.h"
#include "metadata.h"

struct finsFrame *fins_arp_in; /**<This is the pointer to the fins frame received by the ARP module*/

/**@brief this function receives an arp message from outside and processes it
 * @param fins_received is the pointer to the fins frame which has been received by the ARP module
 */
void arp_in(struct finsFrame *fins_received) {

	struct ARP_message *arp_msg_ptr;

	fins_arp_in = fins_received;

	/**request or reply received from the network and as transmitted by the ethernet stub*/
	if (fins_arp_in->dataOrCtrl == DATA && (fins_arp_in->destinationID.id == (unsigned char) ARPID)) {
		PRINT_DEBUG("ARP Data, ff=%d", (int)fins_received);

		fins_to_arp(fins_arp_in, packet); //extract arp hdr from the fins frame
		host_to_net(packet); //convert it into the right format (e.g. htons issue etc.)
		arp_msg_ptr = &arp_msg;
		arp_hdr_to_msg(packet, arp_msg_ptr); //convert the hdr into an internal ARP message (e.g. use uint64_t instead of unsigned char)

		print_msgARP(arp_msg_ptr);

		if (check_valid_arp(arp_msg_ptr) == 1) {
			PRINT_DEBUG("ARP Data valid");

			update_cache(arp_msg_ptr);

			if ((arp_msg_ptr->target_IP_addrs == interface_IP_addrs) && (arp_msg_ptr->operation == ARPREQUESTOP)) {
				arp_out(REPLYDATA); //generate reply
			} else if ((arp_msg_ptr->target_IP_addrs == interface_IP_addrs) && (arp_msg_ptr->operation == ARPREPLYOP)) {
				target_IP_addrs = arp_msg.sender_IP_addrs;
				arp_out(REPLYCONTROL); //generate fins control carrying neighbor's MAC address
			}
		}
	} else if ((fins_arp_in->dataOrCtrl == CONTROL) && (fins_arp_in->ctrlFrame.opcode == WRITEREQUEST)
			&& (fins_arp_in->destinationID.id == (unsigned char) ARPID)) {/**as a request received from the ethernet stub-- IP address is provided in this fins control frame*/
		PRINT_DEBUG("ARP Control, ff=%d", (int)fins_received);

		memcpy(fins_IP_address, fins_arp_in->ctrlFrame.paramterValue, PROTOCOLADDRSLEN);
		target_IP_addrs = gen_IP_addrs(fins_IP_address[0], fins_IP_address[1], fins_IP_address[2], fins_IP_address[3]);

		/**request initiated by the ethernet stub*/
		if (search_list(ptr_cacheHeader, target_IP_addrs) == 0) { //i.e. not found
			arp_out(REQUESTDATA); //generate arp request for MAC address and send out to the network
		} else {
			arp_out(REPLYCONTROL); //generate fins control carrying MAC address foe ethernet
		}
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
		arp_out_request(target_IP_addrs, fins_arp_out);
	} else if (response == REPLYDATA) {
		arp_out_reply(fins_arp_out);
	} else if (response == REPLYCONTROL) {
		arp_out_ctrl(target_IP_addrs, fins_arp_out);
	} else {
		PRINT_DEBUG("problem: response=%d", response);
	}
	//output fins_arp_out to queue
	output_arp_queue(fins_arp_out);
}

/**@brief This function is only activated once the cache already has the MAC
 * address of the sought IP address. It sends out a Fins control frame to the ethernet stub
 * @param sought_IP_addrs is the IP address whose associated MAC address is sought
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_ctrl(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out) {
	PRINT_DEBUG("arp_out_request: sought_IP_addrs=%u ff=%d", sought_IP_addrs, (int)fins_arp_out);

	fins_arp_out->destinationID.id = ETHERSTUBID;
	fins_arp_out->dataOrCtrl = CONTROL;
	fins_arp_out->ctrlFrame.senderID = ARPID;
	fins_arp_out->ctrlFrame.opcode = READREPLY;
	MAC_addrs_conversion(search_MAC_addrs(sought_IP_addrs, ptr_cacheHeader), fins_MAC_address);
	fins_arp_out->ctrlFrame.paramterValue = fins_MAC_address;
}

/**@brief This function sends out a fins frame that passes an arp request out to the network
 * @param sought_IP_addrs is the IP address whose associated MAC address is sought
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_request(uint32_t sought_IP_addrs, struct finsFrame *fins_arp_out) {

	PRINT_DEBUG("arp_out_request: sought_IP_addrs=%u ff=%d", sought_IP_addrs, (int)fins_arp_out);

	gen_requestARP(sought_IP_addrs, &arp_msg);
	arp_msg_to_hdr(&arp_msg, packet);
	host_to_net(packet);
	print_arp_hdr(packet);
	arp_to_fins(packet, fins_arp_out); /**arp request to be sent to network*/
}

/**@brief This function sends out a fins frame with a reply arp in response to a request
 * from the network
 * @param fins_arp_out points to the fins frame which will be sent from the module
 * */
void arp_out_reply(struct finsFrame *fins_arp_out) {
	PRINT_DEBUG("arp_out_reply: ff=%d", (int)fins_arp_out);

	struct ARP_message arp_msg_reply;

	gen_replyARP(&arp_msg, &arp_msg_reply);
	arp_msg_to_hdr(&arp_msg_reply, packet);
	host_to_net(packet);
	print_arp_hdr(packet);
	arp_to_fins(packet, fins_arp_out); /**arp reply to be sent to network */
}

/**@brief to be completed. A fins frame is written to the 'wire'*/
void output_arp_queue(struct finsFrame *fins_arp_out) {
	if (fins_arp_out->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("output_arp_queue: Entered: ff=%d meta=%d", (int)fins_arp_out, (int) fins_arp_out->ctrlFrame.metaData);
	} else if (fins_arp_out->dataOrCtrl == DATA) {
		PRINT_DEBUG("output_arp_queue: Entered: ff=%d meta=%d", (int)fins_arp_out, (int) fins_arp_out->dataFrame.metaData);
	} else {
		PRINT_DEBUG("output_arp_queue: Entered: ff=%d type=%d", (int)fins_arp_out, fins_arp_out->dataOrCtrl);
	}

	if (sem_wait(&ARP_to_Switch_Qsem)) {
		PRINT_ERROR("ARP_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(fins_arp_out, ARP_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&ARP_to_Switch_Qsem);
		return;
	}

	PRINT_DEBUG("");
	sem_post(&ARP_to_Switch_Qsem);
}
