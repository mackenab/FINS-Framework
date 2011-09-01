/**@file udp_out.c
 * udp_out.c
 *
 *  Created on: Jul 2, 2010
 *      Author: Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <finstypes.h>
#include "udp.h"

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

void udp_out(struct finsFrame* ff) {

	struct finsFrame* newFF;
	struct udp_metadata_parsed parsed_meta;

	struct udp_packet packet;
	struct udp_packet packet_noninversed;
	int packet_length;

	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != DATA) {
		// release FDF here
		return;
	}
	if (ff->dataFrame.directionFlag != DOWN) {
		// release FDF here
		return;
	}
	if (ff->destinationID.id != UDPID) {
		// release FDF here
		return;
	}

	PRINT_DEBUG("UDP_out");

	//print_finsFrame(ff);


	metadata* meta = (ff->dataFrame).metaData;

	u_char *udp_dataunit = (u_char *) malloc((ff->dataFrame).pduLength
			+ U_HEADER_LEN);

	packet_length = (ff->dataFrame).pduLength + U_HEADER_LEN;
	/** constructs the UDP packet from the FDF and the meta data */
	PRINT_DEBUG("%d", ff->dataFrame.pduLength);

	uint16_t dstbuf16;
	uint16_t srcbuf16;

	uint32_t dstbuf;
	uint32_t srcbuf;

	uint32_t dstip;
	uint32_t srcip;

	PRINT_DEBUG("UDP_out");
	metadata_readFromElement(meta, "dstport", &dstbuf);
	metadata_readFromElement(meta, "srcport", &srcbuf);
	metadata_readFromElement(meta, "dstip", &dstip);
	metadata_readFromElement(meta, "srcip", &srcip);
	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */
	dstbuf16 = (uint16_t) dstbuf;
	srcbuf16 = (uint16_t) srcbuf;

	packet_noninversed.u_dst = dstbuf16;
	packet_noninversed.u_src = srcbuf16;
	packet_noninversed.u_len = ((ff->dataFrame).pduLength) + U_HEADER_LEN;
	packet_noninversed.u_cksum = 0;
	memcpy(packet_noninversed.u_data, (ff->dataFrame).pdu,
			(ff->dataFrame).pduLength);

	PRINT_DEBUG("%d,%d,%d,%d",packet_noninversed.u_dst,packet_noninversed.u_src,packet_noninversed.u_len,packet_noninversed.u_cksum );

	/*
	 int i=0;
	 PRINT_DEBUG("%d",(ff->dataFrame).pduLength);
	 while (i < (ff->dataFrame).pduLength)
	 {
	 PRINT_DEBUG("%c,%d",packet_noninversed.u_data[i],i);

	 i++;
	 }
	 */

	(packet.u_dst) = htons(dstbuf16);
	(packet.u_src) = htons(srcbuf16);
	/* calculates the UDP length by adding the UDP header length to the length of the data */
	packet.u_len = htons(((ff->dataFrame).pduLength) + U_HEADER_LEN);

	/** TODO ignore the checksum for now
	 * Will be fixed later
	 */
	/** Invalidation disabled value = 0xfed2*/
	/*

	 parsed_meta.u_destPort = htons( dstbuf16);
	 parsed_meta.u_srcPort = htons( srcbuf16);

	 parsed_meta.u_IPdst = htonl( dstip);
	 parsed_meta.u_IPsrc = htonl( srcip);
	 parsed_meta.u_pslen = htons( packet_length);
	 parsed_meta.u_prcl = htons( UDP_PROTOCOL);
	 packet.u_cksum = 0;
	 */

	parsed_meta.u_IPsrc = (srcip);
	parsed_meta.u_IPdst = (dstip);

	//	parsed_meta.u_IPsrc = IP4_ADR_P2N(172,31,54,87);
	//	parsed_meta.u_IPdst = IP4_ADR_P2N(172,31,51,249);

	parsed_meta.u_pslen = (packet_noninversed.u_len);
	parsed_meta.u_prcl = (UDP_PROTOCOL);

	PRINT_DEBUG("%d,%d,%d,%d,",parsed_meta.u_IPsrc,parsed_meta.u_IPdst,parsed_meta.u_pslen,
			parsed_meta.u_prcl);

	parsed_meta.u_destPort = dstbuf16;
	parsed_meta.u_srcPort = (srcbuf16);

	//	packet.u_cksum = UDP_checksum(&packet_noninversed, &parsed_meta);
	//	packet.u_cksum = htons(packet.u_cksum);
	packet.u_cksum = 0;
	PRINT_DEBUG("%x",packet.u_cksum);

	PRINT_DEBUG("%d,%d", srcip, dstip);

	PRINT_DEBUG("%d,%d,%d,%x", packet.u_src,packet.u_dst,packet.u_len,packet.u_cksum);

	//	packet.u_cksum = UDP_checksum(&packet, meta);												/* calculates ands stores the real checksum in the checksum field */
	/* need to be careful in the line ^ above ^, the metadata needs to have the s
	 * ource and destination IPS in order to calculate the checksum
	 * */

	//printf("The checksum Value is %d", packet.u_cksum);
	/**
	 int i=0;
	 while (i < ff->dataFrame.pduLength)
	 {
	 PRINT_DEBUG("%d",ff->dataFrame.pdu[i]);
	 i++;

	 }

	 */

	//	packet.u_cksum = 30;

	PRINT_DEBUG("UDP_out");
	memcpy(udp_dataunit, &packet, U_HEADER_LEN); /* copies the UDP packet into the memory that has been allocated for the PDU */
	//	PRINT_DEBUG("%d, %d",(ff->dataFrame).pdu, ff->dataFrame.pduLength);

	memcpy(udp_dataunit + U_HEADER_LEN, (ff->dataFrame).pdu,
			ff->dataFrame.pduLength); /* moves the pointer 8 bytes to account for those empty 8 bytes*/
	;
	//	PRINT_DEBUG("%d",packet.u_len);

	/**
	 memcpy(test, udp_dataunit, packet_length);
	 test [packet_length] = '\0';
	 i=0;
	 while (i < packet_length)
	 {
	 PRINT_DEBUG("%d",test[i]);
	 i++;

	 }



	 //free (ff->dataFrame.pdu);
	 PRINT_DEBUG("%s",test);
	 PRINT_DEBUG("%d",udp_dataunit);
	 */

	ff->dataFrame.pdu = udp_dataunit;
	/* creates a new FDF to be sent out */
	PRINT_DEBUG("%d",ff->dataFrame.pdu);

	PRINT_DEBUG("UDP_out");

	newFF = create_ff(DATA, DOWN, IPV4ID, packet_length, ff->dataFrame.pdu,
			ff->dataFrame.metaData);

	PRINT_DEBUG("%d",newFF->dataFrame.pdu);

	print_finsFrame(newFF);
	udpStat.totalSent++;
	PRINT_DEBUG("UDP_out");

	sendToSwitch(newFF);
}
