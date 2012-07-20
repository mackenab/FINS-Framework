/**@file udp_in.c
 * udp_in.c
 *
 *  Created on: Jun 29, 2010
 *      Author: Abdallah Abdallah
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "udp.h"

/**
 * @brief removes the UDP header information from an incoming datagram passing it on to the socket.
 * @param ff- the fins frame most likely recieved from IP through the dataswitch.
 *
 * udp_in moves the UDP header information into the metadata. Then it constructs a new FDF destined
 * for the socket with this new metadata.The PDU now points to the data that was inside of the UDP
 * datagram. Prior to this however, the checksum is verified.
 */

extern struct udp_statistics udpStat;

void udp_in(struct finsFrame* ff) {

	struct finsFrame *newFF;

	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != DATA) {
		// release FDF here
		freeFinsFrame(ff);
		return;
	}
	if (ff->dataFrame.directionFlag != UP) {
		// release FDF here
		freeFinsFrame(ff);
		return;
	}
	if (ff->destinationID.id != UDPID) {
		// release FDF here
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("UDP_in ff=%x", (int)ff);
	/* point to the necessary data in the FDF */
	PRINT_DEBUG("%d", (int)ff);
	struct udp_header* packet = (struct udp_header*) ((ff->dataFrame).pdu);
	metadata* meta = ff->dataFrame.metaData;

	uint16_t protocol_type;
	unsigned long srcip;
	unsigned long dstip;
	uint16_t src_port;
	uint16_t dst_port;

	metadata_readFromElement(meta, "protocol", &protocol_type);
	metadata_readFromElement(meta, "src_ip", &srcip);
	metadata_readFromElement(meta, "dst_ip", &dstip);

	/* begins checking the UDP packets integrity */
	/** TODO Fix the length check below , I will highlighted for now */
	/**
	 if (meta->u_pslen != packet->u_len) {
	 udpStat.mismatchingLengths++;
	 udpStat.totalBadDatagrams ++;
	 PRINT_DEBUG("UDP_in");

	 return;
	 }
	 */
	if (protocol_type != UDP_PROTOCOL) {
		udpStat.wrongProtocol++;
		udpStat.totalBadDatagrams++;
		PRINT_DEBUG("wrong proto=%d", protocol_type);

		return;
	}

	/* the packet is does have an "Ignore checksum" value and fails the checksum, it is thrown away */
	/** TODO Correct the implementation of the function UDP_checksum
	 * Now it will be called as a dummy function
	 * */

	uint16_t checksum = UDP_checksum((struct udp_packet*) packet, htonl(srcip), htonl(dstip));

	PRINT_DEBUG("proto=%d , src=%lu:%u, dst=%lu:%u", (int)protocol_type, srcip, packet->u_dst, dstip, packet->u_src);
	PRINT_DEBUG("UDP_checksum=%u checksum=%u", checksum, ntohs(packet->u_cksum));

	if (packet->u_cksum != IGNORE_CHEKSUM) {
		if (checksum != 0) {
			udpStat.badChecksum++;
			udpStat.totalBadDatagrams++;
			PRINT_DEBUG("bad checksum=%x, calc=%x", packet->u_cksum, checksum);

			return;
		}

	} else {
		udpStat.noChecksum++;
		PRINT_DEBUG("ignore checksum=%d", udpStat.noChecksum);

	}

	//metadata *udp_meta = (metadata *)malloc (sizeof(metadata));
	//metadata_create(udp_meta);

	src_port = ntohs(packet->u_src);
	dst_port = ntohs(packet->u_dst);

	PRINT_DEBUG("proto=%d , src=%d:%d, dst=%d:%d", (int)protocol_type, (int)srcip, (int)src_port, (int)dstip, (int)dst_port);

	metadata_writeToElement(meta, "src_port", &src_port, META_TYPE_INT);
	metadata_writeToElement(meta, "dst_port", &dst_port, META_TYPE_INT);

	/* put the header into the meta data*/
	//	meta->u_destPort = packet->u_dst;
	//	meta->u_srcPort = packet->u_src;
	/* construct a FDF to send to the sockets */

	PRINT_DEBUG("PDU Length including UDP header %d", (ff->dataFrame).pduLength);
	PRINT_DEBUG("PDU Length %d", ((ff->dataFrame).pduLength) - U_HEADER_LEN);

	ff->dataFrame.pdu = ff->dataFrame.pdu + U_HEADER_LEN;

	//#########################
	u_char *temp = (u_char *) malloc(ff->dataFrame.pduLength - U_HEADER_LEN + 1);
	memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength - U_HEADER_LEN);
	temp[ff->dataFrame.pduLength - U_HEADER_LEN] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength-U_HEADER_LEN, temp);
	free(temp);
	//#########################

	//newFF = create_ff(DATA, UP, SOCKETSTUBID, ((int)(ff->dataFrame.pdu) - U_HEADER_LEN), &((ff->dataFrame).pdu), meta);
	newFF = create_ff(DATA, UP, SOCKETSTUBID, ((ff->dataFrame).pduLength) - U_HEADER_LEN, ((ff->dataFrame).pdu), meta);

	PRINT_DEBUG("newff=%x, PDU Len=%d", (int)newFF, (newFF->dataFrame).pduLength);
	//print_finsFrame(newFF);

	sendToSwitch(newFF);

	PRINT_DEBUG("freeing: ff=%x", (int) ff);
	//freeFinsFrame(ff); //can't since using meta
	//free(ff->dataFrame.pdu); //TODO fix free problem right here
	free(ff);
}

