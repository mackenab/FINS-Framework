/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

extern finsQueue IPv4_to_Switch_Queue;
extern sem_t IPv4_to_Switch_Qsem;

void IP4_send_fdf_in(struct ip4_header* pheader, struct ip4_packet* ppacket) {

	struct finsFrame *fins_frame = (struct finsFrame *) malloc(
			sizeof(struct finsFrame));
	char *data;
	PRINT_DEBUG("IP4_send_fdf_in() called");
	fins_frame->dataOrCtrl = DATA;
	switch (pheader->protocol) {
	case IP4_PT_TCP:
		fins_frame->destinationID.id = TCPID;
		break;
	case IP4_PT_UDP:
		fins_frame->destinationID.id = UDPID;
		break;
	case IP4_PT_ICMP:
		fins_frame->destinationID.id = ICMPID;// todo: ICMPID should be decided
		break;
	}PRINT_DEBUG();
	fins_frame->destinationID.next = NULL;
	fins_frame->dataFrame.directionFlag = UP;
	fins_frame->dataFrame.pduLength = pheader->packet_length
			- pheader->header_length;
	//	fins_frame->dataFrame.pduLength = pheader->packet_length - 20;
	data = (char *) malloc(pheader->packet_length - pheader->header_length);
	memcpy(data, ppacket->ip_data, pheader->packet_length
			- pheader->header_length);
	fins_frame->dataFrame.pdu = data;
	/**	char ssss[20];
	 memcpy(ssss,(ppacket->ip_data)+ 8, (pheader->packet_length - pheader->header_length) -8);
	 ssss [(pheader->packet_length - pheader->header_length) -8 ];
	 PRINT_DEBUG("%s",ssss);
	 */
	metadata *ipv4_meta = (metadata *) malloc(sizeof(metadata));

	metadata_create(ipv4_meta);

	IP4addr srcaddress = ppacket->ip_src;
	IP4addr dstaddress = ppacket->ip_dst;
	uint16_t protocol = ppacket->ip_proto; /* protocol number should  be 17 from metadata */
	/** Filling into the metadata with sourceIP, DestinationIP, and ProtocolNumber */

	metadata_writeToElement(ipv4_meta, "ipsrc", &srcaddress, META_TYPE_INT);
	metadata_writeToElement(ipv4_meta, "ipdst", &dstaddress, META_TYPE_INT);
	metadata_writeToElement(ipv4_meta, "protocol", &protocol, META_TYPE_INT);
	fins_frame->dataFrame.metaData = ipv4_meta;
	PRINT_DEBUG("protocol %d ,srcip %d,dstip %d", protocol,srcaddress,dstaddress);

	sendToSwitch_IPv4(fins_frame);

}

void IP4_send_fdf_out(struct finsFrame *ff, struct ip4_packet* ppacket,
		struct ip4_next_hop_info next_hop, uint16_t length) {

	if (ff == NULL) {

		PRINT_DEBUG("forwarded frame equal NULL");
		exit(1);

	}

	//print_finsFrame(ff);
	struct finsFrame *fins_frame = (struct finsFrame *) malloc(
			sizeof(struct finsFrame));
	char *data;
	PRINT_DEBUG("IP4_send_fdf_out() called.");
	fins_frame->dataOrCtrl = DATA;
	(fins_frame->destinationID).id = ETHERSTUBID;
	(fins_frame->destinationID).next = NULL;
	(fins_frame->dataFrame).directionFlag = DOWN;
	(fins_frame->dataFrame.metaData) = ff->dataFrame.metaData;
	(fins_frame->dataFrame).pduLength = length + IP4_MIN_HLEN;
	//(fins_frame->dataFrame).pdu = (unsigned char *)ppacket;


	data = (char *) malloc(length + IP4_MIN_HLEN);

	memcpy(data, ppacket, IP4_MIN_HLEN);
	memcpy(data + IP4_MIN_HLEN, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	(fins_frame->dataFrame).pdu = data;

	//print_finsFrame(fins_frame);
	free(ff);
	//fins_frame.dataFrame.metaData = ..... // todo: meta data needs to be filled with the required info.
	sendToSwitch_IPv4(fins_frame);
}

//todo: needs to be replaced by something meaningful
void sendToSwitch_IPv4(struct finsFrame *fins_frame) {

	sem_wait(&IPv4_to_Switch_Qsem);
	write_queue(fins_frame, IPv4_to_Switch_Queue);
	sem_post(&IPv4_to_Switch_Qsem);
	PRINT_DEBUG("sendToSwitch_IPv4 DONE");

}
