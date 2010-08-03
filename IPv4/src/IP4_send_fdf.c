/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "IP4.h"

void IP4_send_fdf_in(struct ip4_header* pheader, struct ip4_packet* ppacket)
{
	struct finsFrame fins_frame;
	PRINT_DEBUG("IP4_send_fdf_in() called");
	fins_frame.dataOrCtrl = DATA;
	switch (pheader->protocol)
	{
	case IP4_PT_TCP:
		fins_frame.destinationID = TCPID;
		break;
	case IP4_PT_UDP:
		fins_frame.destinationID = TCPID;
		break;
	case IP4_PT_ICMP:
		fins_frame.destinationID = 0;// todo: ICMPID should be decided
		break;
	}
	fins_frame.dataFrame.directionFlag = UP;
	fins_frame.dataFrame.pduLength = pheader->packet_length;
	fins_frame.dataFrame.pdu = ppacket->ip_data;
	//fins_frame.dataFrame.metaData = .....// todo: metadata needs to be filled with whatever needs to be in meta data
	output_queue_write(fins_frame);

}

void IP4_send_fdf_out(struct ip4_packet* ppacket,
		struct ip4_next_hop_info next_hop, uint16_t length)
{
	struct finsFrame fins_frame;
	PRINT_DEBUG("IP4_send_fdf_out() called.");
	fins_frame.dataOrCtrl = DATA;
	fins_frame.destinationID = ETHERSTUBID;
	fins_frame.dataFrame.directionFlag = DOWN;
	fins_frame.dataFrame.pduLength = length;
	fins_frame.dataFrame.pdu = (unsigned char *)ppacket;
	//fins_frame.dataFrame.metaData = ..... // todo: meta data needs to be filled with the required info.
	output_queue_write(fins_frame);
}

//todo: needs to be replaced by something meaningful
void output_queue_write(struct finsFrame fins_frame){

}
