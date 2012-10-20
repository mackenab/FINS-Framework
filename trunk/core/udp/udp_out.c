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
	u_char *udp_dataunit = (u_char *) malloc(packet_length);
	packet_netw = (struct udp_packet *) udp_dataunit;
	u_char *pdu = ff->dataFrame.pdu;

	/** constructs the UDP packet from the FDF and the meta data */

	//#########################
	u_char *temp = (u_char *) malloc(ff->dataFrame.pduLength + 1);
	memcpy(temp, pdu, ff->dataFrame.pduLength);
	temp[ff->dataFrame.pduLength] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength, temp);
	free(temp);
	//#########################

	uint16_t dst_port;
	uint16_t src_port;

	uint32_t dst_ip;
	uint32_t src_ip;

	metadata *params = ff->metaData;

	int ret = 0;
	ret += metadata_readFromElement(params, "src_ip", &src_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(params, "src_port", &src_port) == CONFIG_FALSE;
	ret += metadata_readFromElement(params, "dst_ip", &dst_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(params, "dst_port", &dst_port) == CONFIG_FALSE;

	if (ret) {
		//TODO error
		PRINT_ERROR("todo error");
	}

	uint8_t protocol = UDP_PROTOCOL;
	metadata_writeToElement(params, "protocol", &protocol, META_TYPE_INT);

	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */

	//packet_host.u_src = srcbuf16;
	//packet_host.u_dst = dstbuf16;
	//packet_host.u_len = packet_length;
	//packet_host.u_cksum = 0;
	packet_netw->u_src = htons(src_port);
	packet_netw->u_dst = htons(dst_port);
	packet_netw->u_len = htons(packet_length);
	packet_netw->u_cksum = 0;
	memcpy(packet_netw->u_data, pdu, ff->dataFrame.pduLength);

	PRINT_DEBUG("src=%u/%u, dst=%u/%u, pkt_len=%u", src_ip, src_port, dst_ip, dst_port, packet_length);

	/*
	 int i=0;
	 PRINT_DEBUG("%d",ff->dataFrame.pduLength);
	 while (i < ff->dataFrame.pduLength)
	 {
	 PRINT_DEBUG("%c,%d",packet_noninversed.u_data[i],i);

	 i++;
	 }
	 */

	//(packet.u_dst) = htons(dstbuf16);
	//(packet.u_src) = htons(srcbuf16);
	/* calculates the UDP length by adding the UDP header length to the length of the data */
	//packet.u_len = htons((ff->dataFrame.pduLength) + U_HEADER_LEN);
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

	/*
	 parsed_meta.u_IPsrc = (srcip);
	 parsed_meta.u_IPdst = (dstip);

	 //	parsed_meta.u_IPsrc = IP4_ADR_P2N(172,31,54,87);
	 //	parsed_meta.u_IPdst = IP4_ADR_P2N(172,31,51,249);

	 parsed_meta.u_pslen = (packet_netw.u_len);
	 parsed_meta.u_prcl = (UDP_PROTOCOL);

	 PRINT_DEBUG("%d,%d,%d,%d,", parsed_meta.u_IPsrc, parsed_meta.u_IPdst, parsed_meta.u_pslen, parsed_meta.u_prcl);

	 parsed_meta.u_destPort = dstbuf16;
	 parsed_meta.u_srcPort = (srcbuf16);
	 */

	uint16_t checksum = UDP_checksum(packet_netw, htonl(src_ip), htonl(dst_ip));
	packet_netw->u_cksum = htons(checksum);
	//packet_netw->u_cksum = 0;
	PRINT_DEBUG("checksum (h):%x", checksum);

	//PRINT_DEBUG("%u,%u", src_ip, dst_ip);

	PRINT_DEBUG("pkt_netw: %d,%d,%d,%x", packet_netw->u_src, packet_netw->u_dst, packet_netw->u_len, packet_netw->u_cksum);

	//	packet.u_cksum = UDP_checksum(&packet, meta);												/* calculates ands stores the real checksum in the checksum field */
	/* need to be careful in the line ^ above ^, the metadata needs to have the s
	 * ource and destination IPS in order to calculate the checksum
	 * */

	//printf("The checksum Value is %d", packet.u_cksum);
	/**
	 int i=0;
	 while (i < ff->dataFrame.pduLength)
	 {
	 PRINT_DEBUG("%d",pdu[i]);
	 i++;

	 }

	 */

	//	packet.u_cksum = 30;
	//memcpy(udp_dataunit, &packet_netw, U_HEADER_LEN); /* copies the UDP packet into the memory that has been allocated for the PDU */
	//	PRINT_DEBUG("%d, %d",pdu, ff->dataFrame.pduLength);
	//memcpy(udp_dataunit + U_HEADER_LEN, pdu, ff->dataFrame.pduLength); /* moves the pointer 8 bytes to account for those empty 8 bytes*/
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



	 //free (pdu);
	 PRINT_DEBUG("%s",test);
	 PRINT_DEBUG("%d",udp_dataunit);
	 */

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

	//PRINT_DEBUG("newff=%x, pdu=%x", (int)newFF, (int)newFF->dataFrame.pdu);

	//print_finsFrame(newFF);
	print_finsFrame(ff);
	udpStat.totalSent++;

	//sendToSwitch(newFF);
	udp_to_switch(ff);

	//PRINT_DEBUG("freeing: ff=%p", ff);
	PRINT_DEBUG("freeing: pdu=%p", pdu);
	free(pdu);
	//free(udp_dataunit);
	//free(ff);
}
