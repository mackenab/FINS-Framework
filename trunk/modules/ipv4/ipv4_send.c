/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "ipv4_internal.h"

void ipv4_send_fdf_in(struct fins_module *module, struct finsFrame *ff, struct ip4_header *pheader, struct ip4_packet *ppacket) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, pheader=%p, ppacket=%p", module, ff, pheader, ppacket);

	if (pheader->packet_length < pheader->header_length) {
		PRINT_ERROR("pduLen error, dropping");
		freeFinsFrame(ff);
		return;
	}

	uint32_t protocol = pheader->protocol; //TODO change to flow based
	uint32_t family = AF_INET;
	uint32_t src_ip = pheader->source; //ppacket->ip_src;
	uint32_t dst_ip = pheader->destination; //ppacket->ip_dst;
	uint32_t recv_ttl = pheader->ttl;
	PRINT_DEBUG("protocol=%u, src_ip=%u, dst_ip=%u, recv_ttl=%u", protocol, src_ip, dst_ip, recv_ttl);

	metadata *meta = ff->metaData;
	secure_metadata_writeToElement(meta, "recv_protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_family", &family, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_src_ipv4", &src_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_dst_ipv4", &dst_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_ttl", &recv_ttl, META_TYPE_INT32);

	uint32_t flow;
	uint8_t *pdu = ff->dataFrame.pdu;
	uint8_t *data;

	switch (protocol) {
	case IP4_PT_ICMP:
		flow = IPV4_FLOW_ICMP;

		//leave pdu/pdueLength same
		break;
	case IP4_PT_TCP:
		flow = IPV4_FLOW_TCP;

		ff->dataFrame.pduLength = pheader->packet_length - pheader->header_length;
		data = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
		ff->dataFrame.pdu = data;

		PRINT_DEBUG("Freeing: pdu=%p", pdu);
		free(pdu);
		break;
	case IP4_PT_UDP:
		flow = IPV4_FLOW_UDP;

		ff->dataFrame.pduLength = pheader->packet_length - pheader->header_length;
		data = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(data, ppacket->ip_data, ff->dataFrame.pduLength);
		ff->dataFrame.pdu = data;

		PRINT_DEBUG("Freeing: pdu=%p", pdu);
		free(pdu);
		break;
	default:
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
		//exit(-1);
		return;
	}

	if (!module_send_flow(module, ff, flow)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}
}

void ipv4_send_fdf_out(struct fins_module *module, struct finsFrame *ff, struct ip4_packet* ppacket, uint32_t address, int32_t if_index) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p, ppacket=%p, address=%u, if_index=%d", module, ff, ff->metaData, ppacket, address, if_index);

	uint32_t length = ff->dataFrame.pduLength;
	uint8_t *pdu = ff->dataFrame.pdu;

	ff->dataFrame.pduLength += IP4_MIN_HLEN;
	ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
	memcpy(ff->dataFrame.pdu, ppacket, IP4_MIN_HLEN);
	memcpy(ff->dataFrame.pdu + IP4_MIN_HLEN, pdu, length);

	uint32_t ether_type = IP4_ETH_TYPE;
	secure_metadata_writeToElement(ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
	secure_metadata_writeToElement(ff->metaData, "send_if_index", &if_index, META_TYPE_INT32);
	secure_metadata_writeToElement(ff->metaData, "send_dst_ipv4", &address, META_TYPE_INT32);

	if (!module_send_flow(module, ff, IPV4_FLOW_INTERFACE)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}

	PRINT_DEBUG("Freeing: pdu=%p", pdu);
	free(pdu);
}
