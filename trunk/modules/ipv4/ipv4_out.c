/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4_internal.h"
#include <finsqueue.h>

int ipv4_route_dst_test(struct route_record *route, uint32_t *dst) {
	return ((addr4_get_ip(&route->dst) & addr4_get_ip(&route->mask)) == (*dst & addr4_get_ip(&route->mask))) || (addr4_get_ip(&route->dst) == IPV4_ADDR_ANY_IP);
}

void ipv4_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct ipv4_data *md = (struct ipv4_data *) module->data;

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "send_protocol", &protocol);
	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "send_family", &family);

	uint32_t src_ip;
	secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
	uint32_t dst_ip;
	secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);
	PRINT_DEBUG("protocol=%u, src_ip=%u, dst_ip=%u", protocol, src_ip, dst_ip);

	struct ip4_packet_header pkt;
	struct ip4_packet *pkt_buf = (struct ip4_packet *) &pkt;
	ipv4_const_header(pkt_buf, src_ip, dst_ip, protocol);

	uint32_t send_ttl = 0;
	if (metadata_readFromElement(ff->metaData, "send_ttl", &send_ttl) == META_TRUE) {
		pkt_buf->ip_ttl = send_ttl;
	}

	uint32_t send_tos = 0;
	if (metadata_readFromElement(ff->metaData, "send_tos", &send_tos) == META_TRUE) {
		//TODO implement
	}

	//keep routing table sorted (envi & local), search through routing table, find best match (last match)
	struct route_record *route = (struct route_record *) list_find_last1(md->route_list, ipv4_route_dst_test, &dst_ip);
	if (route != NULL) {
		PRINT_DEBUG("next_hop: interface=%d, dst=%u, gw=%u", route->if_index, addr4_get_ip(&route->dst), addr4_get_ip(&route->gw));
		uint32_t address;
		if (addr4_get_ip(&route->gw) == IPV4_ADDR_ANY_IP) { //dst in on our subnet, contact directly
			address = addr4_get_ip(&route->dst);
		} else { //dst outside our subnet, contact via gw
			address = addr4_get_ip(&route->gw);
		}

		uint32_t loopback = 0;
		if (md->addr_loopback != NULL) {
			//table should catch pkts to self & direct to LL
			if (md->addr_loopback->if_index == route->if_index) {
				loopback = 1;
			}
		} else {
			//see if loops back by checking each address, though should be caught by routing table & directed to LL
			struct addr_record *addr = (struct addr_record *) list_find1(md->addr_list, addr_ipv4_test, &address);
			if (addr != NULL) {
				loopback = 1;
			}
		}

		if (loopback != 0) {
			PRINT_DEBUG("internal, routing back to netw layer");
			struct timeval current;
			gettimeofday(&current, 0);
			secure_metadata_writeToElement(ff->metaData, "recv_stamp", &current, META_TYPE_INT64);

			secure_metadata_writeToElement(ff->metaData, "recv_protocol", &protocol, META_TYPE_INT32);
			secure_metadata_writeToElement(ff->metaData, "recv_family", &family, META_TYPE_INT32);
			secure_metadata_writeToElement(ff->metaData, "recv_src_ipv4", &src_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(ff->metaData, "recv_dst_ipv4", &dst_ip, META_TYPE_INT32);

			if (send_ttl) {
				secure_metadata_writeToElement(ff->metaData, "recv_ttl", &send_ttl, META_TYPE_INT32);
			}
			if (send_tos) {
				secure_metadata_writeToElement(ff->metaData, "recv_tos", &send_tos, META_TYPE_INT32);
			}

			ff->dataFrame.directionFlag = DIR_UP;

			uint32_t flow;
			switch (protocol) {
			case IP4_PT_ICMP:
				flow = IPV4_FLOW_ICMP;

				uint16_t length = ff->dataFrame.pduLength;
				pkt_buf->ip_fragoff = htons(0);
				pkt_buf->ip_id = htons(0);
				pkt_buf->ip_len = htons(length + IP4_MIN_HLEN);
				pkt_buf->ip_cksum = 0;
				pkt_buf->ip_cksum = ipv4_checksum(pkt_buf, IP4_MIN_HLEN);

				uint8_t *pdu = ff->dataFrame.pdu;
				ff->dataFrame.pduLength += IP4_MIN_HLEN;
				ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
				memcpy(ff->dataFrame.pdu, pkt_buf, IP4_MIN_HLEN);
				memcpy(ff->dataFrame.pdu + IP4_MIN_HLEN, pdu, length);

				PRINT_DEBUG("Freeing: pdu=%p", pdu);
				free(pdu);
				break;
			case IP4_PT_TCP:
				flow = IPV4_FLOW_TCP;
				break;
			case IP4_PT_UDP:
				flow = IPV4_FLOW_UDP;
				break;
			default:
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
				//exit(-1);
				return;
			}

			if (!module_send_flow(module, ff, flow)) {
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
			}
		} else {
			//send normally
			/** TODO
			 * finding out what is wrong with the fragmentation and reimplement it
			 * correctly
			 * Notice that the current implementation support mutlithreading
			 * while the basic opf the implemented fragmentation is based on having one
			 * global packet to hold the contents
			 */
			/**
			 //struct ip4_fragment fragment;
			 while (more_fragments)
			 {
			 fragment = IP4_fragment_data(data, length, offset, IP4_PCK_LEN
			 - IP4_MIN_HLEN);
			 memcpy(fragment.data, pkt_buf->ip_data,
			 fragment.data_length);
			 pkt_buf->ip_fragoff = htons(fragment.first >> 3);
			 pkt_buf->ip_len = htons(fragment.data_length
			 + IP4_MIN_HLEN);
			 more_fragments = fragment.more_fragments;
			 next_hop = IP4_next_hop(dst_ip);
			 if (next_hop.interface>=0)
			 {
			 stats.outfragments++;
			 PRINT_DEBUG("");
			 print_finsFrame(ff);
			 IP4_send_fdf_out(ff, pkt_buf, next_hop, fragment.data_length);
			 }
			 else
			 {
			 PRINT_DEBUG("No route to the dst_ip, packet discarded");
			 }
			 more_fragments = fragment.more_fragments;
			 offset = fragment.last + 1;
			 }
			 */

			uint16_t length = ff->dataFrame.pduLength;
			pkt_buf->ip_fragoff = htons(0);
			pkt_buf->ip_id = htons(0);
			pkt_buf->ip_len = htons(length + IP4_MIN_HLEN);
			pkt_buf->ip_cksum = 0;
			pkt_buf->ip_cksum = ipv4_checksum(pkt_buf, IP4_MIN_HLEN);

			ipv4_send_fdf_out(module, ff, pkt_buf, address, route->if_index);
		}
	} else {
		PRINT_ERROR("todo error");
		//no route to send FDF, send error FCF?
	}
}
