/**@file udp_in.c
 * udp_in.c
 *
 *  Created on: Jun 29, 2010
 *      Author: Abdallah Abdallah
 */
#include "udp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief removes the UDP header information from an incoming datagram passing it on to the socket.
 * @param ff- the fins frame most likely recieved from IP through the dataswitch.
 *
 * udp_in moves the UDP header information into the metadata. Then it constructs a new FDF destined
 * for the socket with this new metadata.The PDU now points to the data that was inside of the UDP
 * datagram. Prior to this however, the checksum is verified.
 */

void udp_in_fdf(struct fins_module *module, struct finsFrame* ff) {
	struct udp_data *md = (struct udp_data *) module->data;

	PRINT_DEBUG("UDP_in ff=%p", ff);
	/* point to the necessary data in the FDF */
	PRINT_DEBUG("%d", (int)ff);
	struct udp_header* packet = (struct udp_header*) ff->dataFrame.pdu;

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "recv_protocol", &protocol);
	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "recv_family", &family);
	uint32_t src_ip;
	secure_metadata_readFromElement(ff->metaData, "recv_src_ipv4", &src_ip);
	uint32_t dst_ip;
	secure_metadata_readFromElement(ff->metaData, "recv_dst_ipv4", &dst_ip);

	/* begins checking the UDP packets integrity */
	/** TODO Fix the length check below , I will highlighted for now */
	uint32_t hlen = ntohs(packet->u_len);
	if (ff->dataFrame.pduLength != hlen) {
		md->stats.mismatchingLengths++;
		md->stats.totalBadDatagrams++;

		PRINT_DEBUG("UDP_in");
		freeFinsFrame(ff);
		return;
	}

	/* the packet is does have an "Ignore checksum" value and fails the checksum, it is thrown away */
	uint16_t checksum = UDP_checksum((struct udp_packet*) packet, htonl(src_ip), htonl(dst_ip));

	uint32_t src_port = ntohs(packet->u_src);
	uint32_t dst_port = ntohs(packet->u_dst);

	PRINT_DEBUG("proto=%u, src=%u/%u, dst=%u/%u", protocol, src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port);PRINT_DEBUG("UDP_checksum=%u, checksum=%u", checksum, ntohs(packet->u_cksum));

	if (packet->u_cksum != IGNORE_CHEKSUM) {
		if (checksum != 0) {
			md->stats.badChecksum++;
			md->stats.totalBadDatagrams++;
			PRINT_ERROR("bad checksum=0x%x, calc=0x%x", packet->u_cksum, checksum);
			freeFinsFrame(ff);
			return;
		}
	} else {
		md->stats.noChecksum++;
		PRINT_DEBUG("ignore checksum=%d", md->stats.noChecksum);
	}

	secure_metadata_writeToElement(ff->metaData, "recv_src_port", &src_port, META_TYPE_INT32);
	secure_metadata_writeToElement(ff->metaData, "recv_dst_port", &dst_port, META_TYPE_INT32);

	PRINT_DEBUG("PDU Length including UDP header %d", ff->dataFrame.pduLength);PRINT_DEBUG("PDU Length %d", (int)(ff->dataFrame.pduLength - U_HEADER_LEN));

	int leng = ff->dataFrame.pduLength;
	ff->dataFrame.pduLength = leng - U_HEADER_LEN;

	uint8_t *old = ff->dataFrame.pdu;
	uint8_t *pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
	memcpy(pdu, old + U_HEADER_LEN, ff->dataFrame.pduLength);
	ff->dataFrame.pdu = pdu;

	//#########################
#ifdef DEBUG
	uint8_t *temp = (uint8_t *) secure_malloc(ff->dataFrame.pduLength + 1);
	memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	temp[ff->dataFrame.pduLength] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength, temp);
	free(temp);
#endif
	//#########################

	md->stats.totalRecieved++;
	PRINT_DEBUG("UDP total recv'd=%d, ff=%p, meta=%p", md->stats.totalRecieved, ff, ff->metaData);
	if (!module_send_flow(module, ff, UDP_FLOW_DAEMON)) {
		PRINT_ERROR("send to switch error, ff=%p", ff);
		freeFinsFrame(ff);
	}

	PRINT_DEBUG("Freeing: pdu=%p", old);
	free(old);
}
