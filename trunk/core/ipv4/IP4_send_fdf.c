/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

finsQueue IPv4_to_Switch_Queue;
sem_t IPv4_to_Switch_Qsem;

extern IP4addr my_ip_addr;

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

	//PRINT_DEBUG("address=%u, interface=%u", (uint32_t)next_hop.address, next_hop.interface);
	PRINT_DEBUG("address=%u, interface=%lu", (uint32_t)next_hop.address, next_hop.interface);
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

	if (store_list_has_space()) {
		metadata *params = (metadata *) malloc(sizeof(metadata));
		if (params == NULL) {
			PRINT_ERROR("metadata creation failed");
			exit(-1);
		}
		metadata_create(params);

		//uint32_t src_ip = my_ip_addr; //TODO get these from next hop info
		//uint32_t dst_ip = ntohl(ppacket->ip_dst);
		uint32_t src_ip = next_hop.interface; //TODO get this value from interface list with hop.interface as the index
		uint32_t dst_ip = next_hop.address;

		uint32_t exec_call = EXEC_ARP_GET_ADDR;
		metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
		metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT);
		metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);

		struct finsFrame *ff_arp = (struct finsFrame *) malloc(sizeof(struct finsFrame));
		if (ff_arp == NULL) {
			PRINT_ERROR("ff_arp alloc error");
			exit(-1);
		}

		ff_arp->dataOrCtrl = CONTROL;
		ff_arp->destinationID.id = ARP_ID;
		ff_arp->destinationID.next = NULL;
		ff_arp->metaData = params;

		uint32_t serial_num = gen_control_serial_num();

		ff_arp->ctrlFrame.senderID = IP_ID;
		ff_arp->ctrlFrame.serialNum = serial_num;
		ff_arp->ctrlFrame.opcode = CTRL_EXEC;

		ipv4_to_switch(ff_arp);

		//TODO store IP fdf
		struct ip4_store *store = store_create(serial_num, ff, pdu);
		store_list_insert(store);
	} else {
		PRINT_DEBUG("todo error");
		//TODO expand store space? remove first stored packet, send error message, & store new packet?
	}
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
