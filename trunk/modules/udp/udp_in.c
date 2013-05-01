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
	struct udp_data *data = (struct udp_data *) module->data;

	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != FF_DATA) {
		// release FDF here
		freeFinsFrame(ff);
		return;
	}
	if (ff->dataFrame.directionFlag != DIR_UP) {
		// release FDF here
		freeFinsFrame(ff);
		return;
	}
	if (ff->destinationID != module->index) { //TODO update to get from metadata??
		// release FDF here
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("UDP_in ff=%p", ff);
	/* point to the necessary data in the FDF */
	PRINT_DEBUG("%d", (int)ff);
	struct udp_header* packet = (struct udp_header*) ff->dataFrame.pdu;

	uint32_t protocol;
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_port;
	uint32_t dst_port;

	metadata *meta = ff->metaData;
	secure_metadata_readFromElement(meta, "recv_protocol", &protocol);
	secure_metadata_readFromElement(meta, "recv_src_ip", &src_ip);
	secure_metadata_readFromElement(meta, "recv_dst_ip", &dst_ip);

	/* begins checking the UDP packets integrity */
	/** TODO Fix the length check below , I will highlighted for now */
	/**
	 if (meta->u_pslen != packet->u_len) {
	 data->udpStat.mismatchingLengths++;
	 data->udpStat.totalBadDatagrams ++;
	 PRINT_DEBUG("UDP_in");

	 return;
	 }
	 */
	if (protocol != UDP_PROTOCOL) {
		data->udpStat.wrongProtocol++;
		data->udpStat.totalBadDatagrams++;
		PRINT_ERROR("wrong proto=%d", protocol);

		return;
	}

	/* the packet is does have an "Ignore checksum" value and fails the checksum, it is thrown away */
	/** TODO Correct the implementation of the function UDP_checksum
	 * Now it will be called as a dummy function
	 * */

	uint16_t checksum = UDP_checksum((struct udp_packet*) packet, htonl(src_ip), htonl(dst_ip));

	src_port = ntohs(packet->u_src);
	dst_port = ntohs(packet->u_dst);

	PRINT_DEBUG("proto=%u, src=%u/%u, dst=%u/%u", protocol, src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port);
	PRINT_DEBUG("UDP_checksum=%u, checksum=%u", checksum, ntohs(packet->u_cksum));

	if (packet->u_cksum != IGNORE_CHEKSUM) {
		if (checksum != 0) {
			data->udpStat.badChecksum++;
			data->udpStat.totalBadDatagrams++;
			PRINT_ERROR("bad checksum=0x%x, calc=0x%x", packet->u_cksum, checksum);

			return;
		}
	} else {
		data->udpStat.noChecksum++;
		PRINT_DEBUG("ignore checksum=%d", data->udpStat.noChecksum);
	}

	//metadata *udp_meta = (metadata *)fins_malloc (sizeof(metadata));
	//metadata_create(udp_meta);

	secure_metadata_writeToElement(meta, "recv_src_port", &src_port, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_dst_port", &dst_port, META_TYPE_INT32);

	/* put the header into the meta data*/
	//	meta->u_destPort = packet->u_dst;
	//	meta->u_srcPort = packet->u_src;
	/* construct a FDF to send to the sockets */

	PRINT_DEBUG("PDU Length including UDP header %d", ff->dataFrame.pduLength);
	PRINT_DEBUG("PDU Length %d", (int)(ff->dataFrame.pduLength - U_HEADER_LEN));

	//ff->dataFrame.pdu = ff->dataFrame.pdu + U_HEADER_LEN;

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

	if (!module_send_flow(module, ff, UDP_FLOW_DAEMON)) {
		PRINT_ERROR("send to switch error, ff=%p", ff);
		freeFinsFrame(ff);
	}

	PRINT_DEBUG("Freeing: pdu=%p", old);
	free(old);
}
