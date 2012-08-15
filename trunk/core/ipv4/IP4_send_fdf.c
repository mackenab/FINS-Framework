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

void IP4_send_fdf_in(struct finsFrame *ff, struct ip4_header* pheader, struct ip4_packet* ppacket) {

	//struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	PRINT_DEBUG("IP4_send_fdf_in() called, ff=%p", ff);
	//ff->dataOrCtrl = DATA;
	PRINT_DEBUG("protocol # %d", pheader->protocol);
	switch (pheader->protocol) {
	case IP4_PT_TCP:
		ff->destinationID.id = TCPID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_UDP:
		ff->destinationID.id = UDPID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_ICMP:
		//ff->destinationID.id = SOCKETSTUBID;
		ff->destinationID.id = ICMPID; // todo: ICMPID should be decided
		ff->destinationID.next = NULL;
		break;
	default:
		PRINT_DEBUG("todo error");
		break;
	}

	PRINT_DEBUG("");
	//ff->dataFrame.directionFlag = UP;
	if (pheader->packet_length < pheader->header_length) {
		PRINT_DEBUG("pduLen error, dropping");
		freeFinsFrame(ff);
		return;
	}

	ff->dataFrame.pduLength = pheader->packet_length - pheader->header_length;
	u_char *pdu = ff->dataFrame.pdu;
	//	ff->dataFrame.pduLength = pheader->packet_length - 20;
	u_char *data = (u_char *) malloc(ff->dataFrame.pduLength);
	memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
	ff->dataFrame.pdu = data;
	/**	char ssss[20];
	 memcpy(ssss,(ppacket->ip_data)+ 8, (pheader->packet_length - pheader->header_length) -8);
	 ssss [(pheader->packet_length - pheader->header_length) -8 ];
	 PRINT_DEBUG("%s",ssss);
	 */

	//metadata *ipv4_meta = (metadata *) malloc(sizeof(metadata));
	//metadata_create(ipv4_meta);
	metadata *ipv4_meta = ff->dataFrame.metaData;

	//IP4addr srcaddress = ppacket->ip_src;
	//IP4addr dstaddress = ppacket->ip_dst;
	IP4addr srcaddress = pheader->source;
	IP4addr dstaddress = pheader->destination;
	PRINT_DEBUG("protocol # %d src=%u, dst=%u", ppacket->ip_proto, (uint32_t)srcaddress, (uint32_t)dstaddress);
	uint16_t protocol = ppacket->ip_proto; /* protocol number should  be 17 from metadata */
	/** Filling into the metadata with sourceIP, DestinationIP, and ProtocolNumber */

	metadata_writeToElement(ipv4_meta, "src_ip", &srcaddress, META_TYPE_INT);
	metadata_writeToElement(ipv4_meta, "dst_ip", &dstaddress, META_TYPE_INT);
	metadata_writeToElement(ipv4_meta, "protocol", &protocol, META_TYPE_INT);
	//ff->dataFrame.metaData = ipv4_meta;
	PRINT_DEBUG("protocol %d, srcip %lu, dstip %lu", protocol, srcaddress, dstaddress);

	sendToSwitch_IPv4(ff);

	PRINT_DEBUG("Freeing pdu=%p", pdu);
	free(pdu);
}

void IP4_send_fdf_out(struct finsFrame *ff, struct ip4_packet* ppacket, struct ip4_next_hop_info next_hop, uint16_t length) {

	if (ff == NULL) {

		PRINT_DEBUG("forwarded frame equal NULL");
		exit(1);

	}

	/*
	 //print_finsFrame(ff);
	 struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	 char *data;
	 PRINT_DEBUG("IP4_send_fdf_out() called, ff=%p newff=%p", ff, fins_frame);
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
	 (fins_frame->dataFrame).pdu = (u_char *) data;

	 //print_finsFrame(fins_frame);
	 sendToSwitch_IPv4(fins_frame);
	 */

	metadata *params = ff->dataFrame.metaData;

	uint32_t type = (uint32_t) IP4_ETH_TYPE;
	metadata_writeToElement(params, "ether_type", &type, META_TYPE_INT);

	u_char *pdu = ff->dataFrame.pdu;
	PRINT_DEBUG("IP4_send_fdf_out() called, ff=%p", ff);
	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = ETHERSTUBID;
	ff->destinationID.next = NULL;
	//ff->dataFrame.directionFlag = DOWN;
	//ff->dataFrame.metaData = ff->dataFrame.metaData;
	ff->dataFrame.pduLength = length + IP4_MIN_HLEN;

	u_char *data = (u_char *) malloc(length + IP4_MIN_HLEN);
	memcpy(data, ppacket, IP4_MIN_HLEN);
	memcpy(data + IP4_MIN_HLEN, pdu, length);
	ff->dataFrame.pdu = data;

	//print_finsFrame(fins_frame);
	sendToSwitch_IPv4(ff);

	//PRINT_DEBUG("Freeing ff=%p", ff);
	PRINT_DEBUG("Freeing pdu=%p", pdu);
	free(pdu);
}

//todo: needs to be replaced by something meaningful
void sendToSwitch_IPv4(struct finsFrame *ff) {

	sem_wait(&IPv4_to_Switch_Qsem);
	write_queue(ff, IPv4_to_Switch_Queue);
	sem_post(&IPv4_to_Switch_Qsem);
	PRINT_DEBUG("sendToSwitch_IPv4 DONE");

}
