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

void udp_out(struct finsFrame* ff)
{

	struct finsFrame* newFF;
	struct udp_metadata_parsed parsed_meta;

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

	print_finsFrame(ff);

	struct udp_header packet;
	struct udp_packet check_packet;
	u_char test[100];
	metadata* meta = (ff->dataFrame).metaData;

	u_char *udp_dataunit = (u_char *)malloc( (ff->dataFrame).pduLength + U_HEADER_LEN );

/** constructs the UDP packet from the FDF and the meta data */
	PRINT_DEBUG("%d", ff->dataFrame.pduLength);

	uint32_t dstbuf;
	uint32_t srcbuf;
	uint32_t dstip;
	uint32_t srcip;

	PRINT_DEBUG("UDP_out");
	metadata_readFromElement(meta,"dstport",&dstbuf);
	metadata_readFromElement(meta,"srcport",&srcbuf);
	metadata_readFromElement(meta,"dstip",&dstip);
	metadata_readFromElement(meta,"srcip",&srcip);
/** fixing the values because of the conflict between uint16 type and
 * the 32 bit META_INT_TYPE
 */
	packet.u_dst = dstbuf;
	packet.u_src = srcbuf;

	PRINT_DEBUG("%d, %d", (packet.u_dst),(packet.u_src));

	(packet.u_dst) = htons(packet.u_dst);
	(packet.u_src) = htons(packet.u_src);
	/* calculates the UDP length by adding the UDP header length to the length of the data */
	int packet_length;
	packet_length= ( ((ff->dataFrame).pduLength) + U_HEADER_LEN );;
	packet.u_len = htons( ((ff->dataFrame).pduLength) + U_HEADER_LEN );


 /** TODO ignore the checksum for now
 * Will be fixed later
 */
	/** Invalidation disabled value = 0xfed2*/


	parsed_meta.u_destPort = htons( packet.u_dst);
	parsed_meta.u_srcPort = htons( packet.u_src);
	parsed_meta.u_IPdst = htonl( dstip);
	parsed_meta.u_IPsrc = htonl( dstip);
	parsed_meta.u_pslen = htons( packet_length);
	parsed_meta.u_prcl = htons( UDP_PROTOCOL);
	packet.u_cksum = 0;


	memcpy(&check_packet,&packet,U_HEADER_LEN);
	memcpy(&check_packet,ff->dataFrame.pdu,ff->dataFrame.pduLength);
	packet.u_cksum = UDP_checksum(&check_packet,&parsed_meta);																			/* stores a value of zero in the checksum field so that it can be calculated */


PRINT_DEBUG("%d,%d,%d,%d", packet.u_src,packet.u_dst,packet.u_len,packet.u_cksum);

//	packet.u_cksum = UDP_checksum(&packet, meta);												/* calculates ands stores the real checksum in the checksum field */
/* need to be careful in the line ^ above ^, the metadata needs to have the source and destination IPS in order to calculate the checksum */

	//printf("The checksum Value is %d", packet.u_cksum);
	int i=0;
	while (i < ff->dataFrame.pduLength)
	{
		PRINT_DEBUG("%d",ff->dataFrame.pdu[i]);
		i++;

	}
	PRINT_DEBUG("UDP_out");
	memcpy(udp_dataunit, &packet, U_HEADER_LEN);											/* copies the UDP packet into the memory that has been allocated for the PDU */
//	PRINT_DEBUG("%d, %d",(ff->dataFrame).pdu, ff->dataFrame.pduLength);

	memcpy(udp_dataunit + U_HEADER_LEN ,(ff->dataFrame).pdu, ff->dataFrame.pduLength);		/* moves the pointer 8 bytes to account for those empty 8 bytes*/;
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

	newFF = create_ff(DATA, DOWN, IPV4ID, packet_length, ff->dataFrame.pdu, ff->dataFrame.metaData);

	PRINT_DEBUG("%d",newFF->dataFrame.pdu);


	print_finsFrame(newFF);
	udpStat.totalSent++;
	PRINT_DEBUG("UDP_out");

	sendToSwitch(newFF);
}
