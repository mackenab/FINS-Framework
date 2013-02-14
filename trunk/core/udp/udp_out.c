/**@file udp_out.c
 * udp_out.c
 *
 *  Created on: Jul 2, 2010
 *      Author: Abdallah Abdallah
 */
#include "udp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <finstypes.h>

/**
 * @brief Creates a new FDF to be sent to the dataswitch for all outgoing data, data headed to another computer
 * @params ff - Is the "raw" fins frame from the socket.
 *
 *The new FDF is created from the raw FF. This raw FF was received from the socket stub. The other important peice
 *is the the metadata. It must contain the IP source and destination as well as the Source port and Destination port.
 *The PDU length also must be included in the FDF to calculate the length of the UDP datagram. Before the data is
 *placed in the new FDF, the checksum is first calculated and placed within the UDP datagram's header.
 */

extern struct udp_statistics udpStat;

extern struct udp_sent_list *udp_sent_packet_list;

void udp_out_fdf(struct finsFrame* ff) {

	//struct finsFrame* newFF;
	//struct udp_metadata_parsed parsed_meta;

	//struct udp_packet packet_host;
	struct udp_packet *packet_netw;
	uint16_t packet_length;

	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != DATA) {
		// release FDF here
		PRINT_ERROR("shouldn't reach here");
		return;
	}
	if (ff->dataFrame.directionFlag != DOWN) {
		// release FDF here
		PRINT_ERROR("shouldn't reach here");
		return;
	}
	if (ff->destinationID.id != UDP_ID) {
		// release FDF here
		PRINT_ERROR("shouldn't reach here");
		return;
	}

	PRINT_DEBUG("UDP_out, ff=%p, meta=%p", ff, ff->metaData);

	//print_finsFrame(ff);

	packet_length = ff->dataFrame.pduLength + U_HEADER_LEN;

	if (packet_length > IP_MAXLEN) {
		PRINT_ERROR("todo error, data too long max 65536, len=%d", packet_length);
	}

	uint8_t *udp_dataunit = (uint8_t *) secure_malloc(packet_length);
	packet_netw = (struct udp_packet *) udp_dataunit;
	uint8_t *pdu = ff->dataFrame.pdu;

	/** constructs the UDP packet from the FDF and the meta data */

	//#########################
#ifdef DEBUG
	if (1) {
		uint8_t *temp = (uint8_t *) secure_malloc(ff->dataFrame.pduLength + 1);
		memcpy(temp, pdu, ff->dataFrame.pduLength);
		temp[ff->dataFrame.pduLength] = '\0';
		PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength, temp);
		free(temp);
	}
#endif
	//#########################

	uint32_t dst_port;
	uint32_t src_port;

	uint32_t dst_ip;
	uint32_t src_ip;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_src_ip", &src_ip);
	secure_metadata_readFromElement(params, "send_src_port", &src_port);
	secure_metadata_readFromElement(params, "send_dst_ip", &dst_ip);
	secure_metadata_readFromElement(params, "send_dst_port", &dst_port);

	uint32_t protocol = UDP_PROTOCOL;
	secure_metadata_writeToElement(params, "send_protocol", &protocol, META_TYPE_INT32);

	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */

	//packet_host.u_src = srcbuf16;
	//packet_host.u_dst = dstbuf16;
	//packet_host.u_len = packet_length;
	//packet_host.u_cksum = 0;
	packet_netw->u_src = htons((uint16_t) src_port);
	packet_netw->u_dst = htons((uint16_t) dst_port);
	packet_netw->u_len = htons(packet_length);
	packet_netw->u_cksum = 0;
	memcpy(packet_netw->u_data, pdu, ff->dataFrame.pduLength);

	PRINT_DEBUG("src=%u/%u, dst=%u/%u, pkt_len=%u", src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port, packet_length);

	uint16_t checksum = UDP_checksum(packet_netw, htonl(src_ip), htonl(dst_ip));
	packet_netw->u_cksum = htons(checksum);
	//packet_netw->u_cksum = 0;
	PRINT_DEBUG("checksum (h):0x%x", checksum);

	//PRINT_DEBUG("%u,%u", src_ip, dst_ip);

	PRINT_DEBUG("pkt_netw: %d,%d,%d,0x%x", packet_netw->u_src, packet_netw->u_dst, packet_netw->u_len, packet_netw->u_cksum);

	//ff->dataFrame.pdu = udp_dataunit;
	/* creates a new FDF to be sent out */
	PRINT_DEBUG("%p", udp_dataunit);
	//(int)ff->dataFrame.pdu);

	//newFF = create_ff(DATA, DOWN, IPV4_ID, packet_length, udp_dataunit, meta);

	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = IPV4_ID;
	ff->destinationID.next = NULL;

	//ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = packet_length;
	ff->dataFrame.pdu = udp_dataunit;
	//ff->metaData = params;

	//PRINT_DEBUG("newff=0x%x, pdu=0x%x", (int)newFF, (int)newFF->dataFrame.pdu);

	//print_finsFrame(newFF);
	//print_finsFrame(ff);
	udpStat.totalSent++;

	struct finsFrame *ff_clone = cloneFinsFrame(ff);

	if (udp_to_switch(ff)) {
		struct udp_sent *sent = udp_sent_create(ff_clone, src_ip, src_port, dst_ip, dst_port);

		if (udp_sent_list_has_space(udp_sent_packet_list)) {
			udp_sent_list_append(udp_sent_packet_list, sent);
			PRINT_DEBUG ("sent_packet_list=%p, len=%u, max=%u", udp_sent_packet_list, udp_sent_packet_list->len, udp_sent_packet_list->max);

			gettimeofday(&sent->stamp, 0);
		} else {
			//PRINT_DEBUG("Clearing sent_packet_list");
			//udp_sent_list_gc(udp_sent_packet_list, UDP_MSL_TO_DEFAULT);

			//if (!udp_sent_list_has_space(udp_sent_packet_list)) {
			PRINT_DEBUG("Dropping head of sent_packet_list");
			struct udp_sent *old = udp_sent_list_remove_front(udp_sent_packet_list);
			udp_sent_free(old);
			//}
			udp_sent_list_append(udp_sent_packet_list, sent);
			PRINT_DEBUG ("sent_packet_list=%p, len=%u, max=%u", udp_sent_packet_list, udp_sent_packet_list->len, udp_sent_packet_list->max);

			gettimeofday(&sent->stamp, 0);
		}
	} else {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff_clone);
		freeFinsFrame(ff);
	}

	//PRINT_DEBUG("freeing: ff=%p", ff);
	PRINT_DEBUG("freeing: pdu=%p", pdu);
	free(pdu);
}
