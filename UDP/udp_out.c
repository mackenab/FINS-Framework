/**@file udp_out.c
 * udp_out.c
 *
 *  Created on: Jul 2, 2010
 *      Author: alex
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "finstype.h"
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
	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != 0) {
		// release FDF here
		return;
	}
	if (ff->dataFrame.directionFlag != 1) {
		// release FDF here
		return;
	}
	if (ff->destinationID != UDPID) {
		// release FDF here
		return;
	}

	struct udp_packet packet;
	struct udp_metadata_parsed* meta = ff->dataFrame.metaData;

	/* constructs the UDP packet from the FDF and the meta data */

	unsigned char* ptrToPDU = ff->dataFrame.pdu;												/* assigns a pointer to the PDU location*/
	ptrToPDU -= U_HEADER_LEN;																	/* moves the pointer 8 bytes to account for those empty 8 bytes*/

	memcpy(&packet.u_data,ptrToPDU, ff->dataFrame.pduLength); 									/* Copies the actual data into the data section of the UDP packet. The +U_HEADER_LEN is because of leaving 8 bytes free in the input Queue */
	packet.u_dst = meta->u_destPort;															/* gets the destination port from the metadata */
	packet.u_src = meta->u_srcPort;																/* gets the source port from the metadata */
	packet.u_len = ff->dataFrame.pduLength + U_HEADER_LEN;										/* calculates the UDP length by adding the UDP header length to the length of the data */
	meta->u_pslen = packet.u_len;
	meta->u_prcl = UDP_PROTOCOL;
	packet.u_cksum = 0;																			/* stores a value of zero in the checksum field so that it can be calculated */
	packet.u_cksum = UDP_checksum(&packet, meta);												/* calculates ands stores the real checksum in the checksum field */

	/* need to be careful in the line ^ above ^, the metadata needs to have the source and destination IPS in order to calculate the checksum */

	//printf("The checksum Value is %d", packet.u_cksum);

	memcpy(&(ff->dataFrame.pdu), &packet, U_HEADER_LEN);											/* copies the UDP packet into the memory that has been allocated for the PDU */


	/* creates a new FDF to be sent out */

	struct finsFrame* newFF = create_ff(DATA, DOWN, IPID, packet.u_len, ff->dataFrame.pdu, ff->dataFrame.metaData);

	udpStat.totalSent++;

	//sendToSwitch(newFDF);
}
