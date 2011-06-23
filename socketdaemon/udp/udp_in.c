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
		return;
	}
	if (ff->dataFrame.directionFlag != UP) {
		// release FDF here
		return;
	}
	if (ff->destinationID.id != UDPID) {
		// release FDF here
		return;
	}

	PRINT_DEBUG("UDP_in");
	/* point to the necessary data in the FDF */
	PRINT_DEBUG("%d",ff);
	struct udp_header* packet = (struct udp_header*) ((ff->dataFrame).pdu);
	metadata* meta = ff->dataFrame.metaData;

	uint16_t protocol_type;
	unsigned long srcip;
	unsigned long dstip;

	metadata_readFromElement(meta, "protocol", &protocol_type);
	metadata_readFromElement(meta, "ipsrc", &srcip);
	metadata_readFromElement(meta, "ipdst", &dstip);


	PRINT_DEBUG("UDP_in");

	/* begins checking the UDP packets integrity */
	/** TODO Fix the lenght check below , I will highlighted for now */
	/**
	 if (meta->u_pslen != packet->u_len) {
	 udpStat.mismatchingLengths++;
	 udpStat.totalBadDatagrams ++;
	 PRINT_DEBUG("UDP_in");

	 return;
	 }
	 */
	PRINT_DEBUG("UDP_in");

	if (protocol_type != UDP_PROTOCOL) {
		udpStat.wrongProtocol++;
		udpStat.totalBadDatagrams++;
		PRINT_DEBUG("UDP_in");

		return;
	} PRINT_DEBUG("UDP_in");

	/* the packet is does have an "Ignore checksum" value and fails the checksum, it is thrown away */
	/** TODO Correct the implementation of the function UDP_checksum
	 * Now it will be called as a dummy function
	 * */
	/**
	 if (packet->u_cksum != IGNORE_CHEKSUM ){
	 if(UDP_checksum(packet, meta) != 0) {
	 udpStat.badChecksum++;
	 udpStat.totalBadDatagrams ++;
	 PRINT_DEBUG("UDP_in");

	 return;
	 }

	 }else{
	 udpStat.noChecksum++;
	 PRINT_DEBUG("UDP_in");

	 }
	 PRINT_DEBUG("UDP_in");
	 */
	//metadata *udp_meta = (metadata *)malloc (sizeof(metadata));
	//metadata_create(udp_meta);
	PRINT_DEBUG("%d , %d, %d, %d, %d", protocol_type,srcip,dstip,
			packet->u_dst,packet->u_src);

	metadata_writeToElement(meta, "portdst", &packet->u_dst, META_TYPE_INT);
	metadata_writeToElement(meta, "portsrc", &packet->u_src, META_TYPE_INT);

	/* put the header into the meta data*/
	//	meta->u_destPort = packet->u_dst;
	//	meta->u_srcPort = packet->u_src;

	/* construct a FDF to send to the sockets */
	PRINT_DEBUG("UDP_in");

	ff->dataFrame.pdu = ff->dataFrame.pdu + U_HEADER_LEN;
	PRINT_DEBUG("UDP_in"); PRINT_DEBUG("PDU Length including UDP header %d", (ff->dataFrame).pduLength); PRINT_DEBUG("PDU Length %d", ((ff->dataFrame).pduLength) - U_HEADER_LEN);

	//newFF = create_ff(DATA, UP, SOCKETSTUBID, ((int)(ff->dataFrame.pdu) - U_HEADER_LEN), &((ff->dataFrame).pdu), meta);
	newFF = create_ff(DATA, UP, SOCKETSTUBID, ((ff->dataFrame).pduLength)
			- U_HEADER_LEN, ((ff->dataFrame).pdu), meta);

	PRINT_DEBUG("PDU Length %d", (newFF->dataFrame).pduLength);

	//print_finsFrame(newFF);

	//freeFinsFrame(ff);
	PRINT_DEBUG("UDP_in");

	sendToSwitch(newFF);
}

