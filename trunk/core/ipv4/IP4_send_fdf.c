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
		ff->destinationID.id = TCP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_UDP:
		ff->destinationID.id = UDP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_ICMP:
		ff->destinationID.id = ICMP_ID;
		ff->destinationID.next = NULL;
		break;
	default:
		PRINT_DEBUG("todo error")
		;
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
	metadata *ipv4_meta = ff->metaData;

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
	//ff->metaData = ipv4_meta;
	PRINT_DEBUG("protocol %d, srcip %lu, dstip %lu", protocol, srcaddress, dstaddress);

	ipv4_to_switch(ff);

	PRINT_DEBUG("Freeing pdu=%p", pdu);
	free(pdu);
}

void IP4_send_fdf_out(struct finsFrame *ff, struct ip4_packet* ppacket, struct ip4_next_hop_info next_hop, uint16_t length) {

	if (ff == NULL) {

		PRINT_ERROR("forwarded frame equal NULL");
		exit(-1);

	}

	/*
	 //print_finsFrame(ff);
	 struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	 char *data;
	 PRINT_DEBUG("IP4_send_fdf_out() called, ff=%p newff=%p", ff, fins_frame);
	 fins_frame->dataOrCtrl = DATA;
	 (fins_frame->destinationID).id = INTERFACE_ID;
	 (fins_frame->destinationID).next = NULL;
	 (fins_frame->dataFrame).directionFlag = DOWN;
	 (fins_frame->metaData) = ff->metaData;
	 (fins_frame->dataFrame).pduLength = length + IP4_MIN_HLEN;
	 //(fins_frame->dataFrame).pdu = (unsigned char *)ppacket;

	 data = (char *) malloc(length + IP4_MIN_HLEN);

	 memcpy(data, ppacket, IP4_MIN_HLEN);
	 memcpy(data + IP4_MIN_HLEN, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	 (fins_frame->dataFrame).pdu = (u_char *) data;

	 //print_finsFrame(fins_frame);
	 sendToSwitch_IPv4(fins_frame);
	 */

	//char dst_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//char src_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//char dst_mac[] = { 0x00, 0x1c, 0xbf, 0x86, 0xd2, 0xda }; // Mark Machine
	//char dst_mac[] = { 0x00, 0x1c, 0xbf, 0x87, 0x1a, 0xfd }; //same to itself
	//jreed MAC addresses
	//char src_mac[] = { 0x08, 0x00, 0x27, 0x12, 0x34, 0x56 }; //made up
	//char src_mac[] = { 0x08, 0x00, 0x27, 0x44, 0x55, 0x66 }; //HAF FINS-dev_env eth0, bridged
	//char src_mac[] = { 0x08, 0x00, 0x27, 0x11, 0x22, 0x33 }; //HAF FINS-dev_env eth1, nat
	//char src_mac[] = { 0x08, 0x00, 0x27, 0xa5, 0x5f, 0x13 }; //HAF Vanilla-dev_env eth0
	//char src_mac[] = { 0x08, 0x00, 0x27, 0x16, 0xc7, 0x9b }; //HAF Vanilla-dev_env eth1
	uint64_t src_mac = 0x080027445566;

	//char dst_mac[] = { 0xf4, 0x6d, 0x04, 0x49, 0xba, 0xdd }; //HAF host
	//char dst_mac[] = { 0x08, 0x00, 0x27, 0x44, 0x55, 0x66 }; //HAF FINS-dev_env eth0, bridged
	//char dst_mac[] = { 0x08, 0x00, 0x27, 0x11, 0x22, 0x33 }; //HAF FINS-dev_env eth1, nat
	//char dst_mac[] = { 0x08, 0x00, 0x27, 0x16, 0xc7, 0x9b }; //HAF Vanilla-dev eth 1
	//char dst_mac[] = { 0xa0, 0x21, 0xb7, 0x71, 0x0c, 0x87 }; //Router 192.168.1.1 //LAN port
	//char dst_mac[] = { 0xa0, 0x21, 0xb7, 0x71, 0x0c, 0x88 }; //Router 192.168.1.1 //INET port
	//char dst_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; //eth broadcast
	uint64_t dst_mac = 0xf46d0449badd;

	//TODO get mac addr from ARP, by sending FCF

	metadata *params = ff->metaData;

	uint32_t ether_type = (uint32_t) IP4_ETH_TYPE;
	metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);
	metadata_writeToElement(params, "src_mac", &src_mac, META_TYPE_INT64);
	metadata_writeToElement(params, "ether_type", &ether_type, META_TYPE_INT);

	PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

	u_char *pdu = ff->dataFrame.pdu;
	PRINT_DEBUG("IP4_send_fdf_out() called, ff=%p", ff);
	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = INTERFACE_ID;
	ff->destinationID.next = NULL;
	//ff->dataFrame.directionFlag = DOWN;
	//ff->metaData = ff->metaData;
	ff->dataFrame.pduLength = length + IP4_MIN_HLEN;

	u_char *data = (u_char *) malloc(length + IP4_MIN_HLEN);
	memcpy(data, ppacket, IP4_MIN_HLEN);
	memcpy(data + IP4_MIN_HLEN, pdu, length);
	ff->dataFrame.pdu = data;

	//print_finsFrame(fins_frame);
	ipv4_to_switch(ff);

	//PRINT_DEBUG("Freeing ff=%p", ff);
	PRINT_DEBUG("Freeing pdu=%p", pdu);
	free(pdu);
}

int ipv4_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p meta=%p", ff, ff->metaData);
	if (sem_wait(&IPv4_to_Switch_Qsem)) {
		PRINT_ERROR("Interface_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, IPv4_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&IPv4_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&IPv4_to_Switch_Qsem);

	return 0;
}
