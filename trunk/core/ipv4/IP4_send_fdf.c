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

extern IP4addr my_ip_addr;

void IP4_send_fdf_in(struct finsFrame *ff, struct ip4_header* pheader, struct ip4_packet* ppacket) {
	PRINT_DEBUG("Entered: ff=%p, pheader=%p, ppacket=%p", ff, pheader, ppacket);

	if (pheader->packet_length < pheader->header_length) {
		PRINT_ERROR("pduLen error, dropping");
		freeFinsFrame(ff);
		return;
	}

	//struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	//ff->dataOrCtrl = DATA;
	uint32_t protocol = pheader->protocol; /* protocol number should  be 17 from metadata */
	switch (protocol) {
	case IP4_PT_ICMP:
		ff->destinationID.id = ICMP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_TCP:
		ff->destinationID.id = TCP_ID;
		ff->destinationID.next = NULL;
		break;
	case IP4_PT_UDP:
		ff->destinationID.id = UDP_ID;
		ff->destinationID.next = NULL;
		break;
	default:
		PRINT_ERROR("todo error");
		break;
	}

	//metadata *ipv4_meta = (metadata *) malloc(sizeof(metadata));
	//metadata_create(ipv4_meta);
	metadata *params = ff->metaData;

	IP4addr src_ip = pheader->source; //ppacket->ip_src;
	IP4addr dst_ip = pheader->destination; //ppacket->ip_dst;

	metadata_writeToElement(params, "recv_protocol", &protocol, META_TYPE_INT32);
	metadata_writeToElement(params, "recv_src_ip", &src_ip, META_TYPE_INT32);
	metadata_writeToElement(params, "recv_dst_ip", &dst_ip, META_TYPE_INT32);

	uint32_t recv_ttl = pheader->ttl;
	metadata_writeToElement(params, "recv_ttl", &recv_ttl, META_TYPE_INT32);

	//ff->metaData = ipv4_meta;
	PRINT_DEBUG("protocol=%u, src_ip=%lu, dst_ip=%lu, recv_ttl=%u", protocol, src_ip, dst_ip, recv_ttl);

	//ff->dataFrame.directionFlag = UP;
	//ff->dataFrame.pduLength = pheader->packet_length - 20;

	switch (protocol) {
	case IP4_PT_ICMP:
		//leave pdu/pdueLength same
		break;
	case IP4_PT_TCP:
	case IP4_PT_UDP:
		ff->dataFrame.pduLength = pheader->packet_length - pheader->header_length;
		uint8_t *pdu = ff->dataFrame.pdu;
		uint8_t *data = (uint8_t *) malloc(ff->dataFrame.pduLength);
		if (data == NULL) {
			PRINT_ERROR("ip pdu alloc fail");
			exit(-1);
		}

		memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
		ff->dataFrame.pdu = data;

		PRINT_DEBUG("Freeing pdu=%p", pdu);
		free(pdu);
		break;
	default:
		PRINT_ERROR("todo error");
		break;
	}

	ipv4_to_switch(ff);
}

void IP4_send_fdf_out(struct finsFrame *ff, struct ip4_packet* ppacket, struct ip4_next_hop_info next_hop, uint16_t length) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	PRINT_DEBUG("address=%u, interface=%u", (uint32_t)next_hop.address, next_hop.interface);

	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = INTERFACE_ID;
	ff->destinationID.next = NULL;
	//ff->metaData = ff->metaData;

	//ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = length + IP4_MIN_HLEN;

	uint8_t *pdu = ff->dataFrame.pdu;
	ff->dataFrame.pdu = (uint8_t *) malloc(length + IP4_MIN_HLEN);
	if (ff->dataFrame.pdu == NULL) {
		PRINT_ERROR("ipv4 pdu alloc fail");
		exit(-1);
	}
	memcpy(ff->dataFrame.pdu, ppacket, IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu + IP4_MIN_HLEN, pdu, length);

	uint64_t src_mac = 0x001d09b35512ull;
	uint64_t dst_mac = 0xf46d0449baddull; //jreed HAF-reed
	//uint64_t dst_mac = 0xa021b7710c87ull; //jreed home wifi
	uint32_t ether_type = IP4_ETH_TYPE;
	metadata_writeToElement(ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
	metadata_writeToElement(ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);
	metadata_writeToElement(ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
	ipv4_to_switch(ff);

	/*
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

		metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT32);
		metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT32);

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
		ff_arp->ctrlFrame.serial_num = serial_num;
		ff_arp->ctrlFrame.opcode = CTRL_EXEC;
		ff_arp->ctrlFrame.param_id = EXEC_ARP_GET_ADDR;

		ff_arp->ctrlFrame.data_len = 0;
		ff_arp->ctrlFrame.data = NULL;

		ipv4_to_switch(ff_arp);

		//TODO store IP fdf
		struct ip4_store *store = store_create(serial_num, ff, pdu);
		store_list_insert(store);
	} else {
		PRINT_ERROR("todo error");
		//TODO expand store space? remove first stored packet, send error message, & store new packet?
		//free(pdu);
	}
	*/
	free(pdu); //TODO comment when uncomment ARP stuff
}
