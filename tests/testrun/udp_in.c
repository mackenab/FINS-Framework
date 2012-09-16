/**@file udp_in.c
 * udp_in.c
 *
 *  Created on: Jun 29, 2010
 *      Author: alex
 */
#include "IP4.h"
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

void udp_to_switch(struct finsFrame * newFF){

	PRINT_DEBUG("send to switch has been just called");
	struct udp_metadata_parsed meta;
	memcpy(&meta,&(newFF->dataFrame.metaData), sizeof(struct udp_metadata_parsed));

	PRINT_DEBUG("PortSrc:%u, PortSrc:%u",meta.u_srcPort, meta.u_destPort);
	PRINT_DEBUG("IPsrc:%u, IPdst:%u",meta.u_IPsrc, meta.u_IPdst)
}
void udp_in(struct finsFrame* ff) {
	PRINT_DEBUG("UDP_in has been just called");
	/* read the FDF and make sure everything is correct*/
	if (ff->dataOrCtrl != 0) {
		// release FDF here
		PRINT_ERROR("it is not data");
		return;
	}
	if (ff->dataFrame.directionFlag != 0) {
		// release FDF here
		PRINT_ERROR("wrong direction");
		return;
	}
	if (ff->destinationID != UDPID) {
		// release FDF here
		PRINT_ERROR("wrong destination ID");
		return;
	}

	/* point to the necessary data in the FDF */
	struct udp_packet* packet = (struct udp_packet*)ff->dataFrame.pdu;
	struct udp_metadata_parsed* meta = (struct udp_metadata_parsed*)ff->dataFrame.metaData;


	/* begins checking the UDP packets integrity */
	if (meta->u_pslen != htons(packet->u_len)) {
		PRINT_DEBUG("UDP length:%u", packet->u_len);
		udpStat.mismatchingLengths++;
		udpStat.totalBadDatagrams ++;
		PRINT_ERROR("wrong length");
		return;
	}

	if (meta->u_prcl != UDP_PROTOCOL) {
		udpStat.wrongProtocol++;
		udpStat.totalBadDatagrams++;
		PRINT_ERROR("it is not UDP segment, I wont parse it");
		return;
	}

	/* the packet is does not have an "Ignore checksum" value and fails the checksum, it is thrown away */
	if (packet->u_cksum != IGNORE_CHEKSUM ){
			if(UDP_checksum(packet, meta) != 0) {
				udpStat.badChecksum++;
				udpStat.totalBadDatagrams ++;
				PRINT_ERROR("checksum ERROR");
				return;
			}

	}else{
		udpStat.noChecksum++;
	}
	/* put the header into the meta data*/
	meta->u_destPort = packet->u_dst;
	meta->u_srcPort = packet->u_src;

	/* construct a FDF to send to the sockets */

	ff->dataFrame.pdu += U_HEADER_LEN;
	struct finsFrame newFF;
	newFF = create_ff(DATA, UP, SOCKETSTUBID, ((int)(ff->dataFrame.pdu) - U_HEADER_LEN), (ff->dataFrame.pdu), (unsigned char*)meta);

	udp_to_switch(&newFF);
}

