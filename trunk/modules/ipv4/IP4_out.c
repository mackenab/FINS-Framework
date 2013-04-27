/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4_internal.h"
#include <finsqueue.h>

void IP4_out(struct fins_module *module, struct finsFrame *ff, uint16_t length, uint32_t source, uint32_t protocol) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, len=%u, src=%u, proto=%u", ff, ff->metaData, length, source, protocol);

	//print_finsFrame(ff);
	//char *data = (char *) ((ff->dataFrame).pdu);

	//uint8_t more_fragments = 1;
	//uint16_t offset = 0;
	uint32_t destination;

	struct ip4_next_hop_info next_hop;
	//struct ip4_fragment fragment;
	struct ip4_packet_header construct_packet;
	struct ip4_packet *construct_packet_buffer;

	//construct_packet_buffer = &construct_packet;
	construct_packet_buffer = (struct ip4_packet *) &construct_packet;

	metadata *meta = ff->metaData;
	secure_metadata_readFromElement(meta, "send_dst_ip", &destination);

	PRINT_DEBUG("src_ip=%u, dst_ip=%u", source, destination);

	IP4_const_header(construct_packet_buffer, source, destination, protocol);

	uint32_t send_ttl = 0;
	if (metadata_readFromElement(meta, "send_ttl", &send_ttl) == META_TRUE) {
		construct_packet_buffer->ip_ttl = send_ttl;
	}

	uint32_t send_tos = 0;
	if (metadata_readFromElement(meta, "send_tos", &send_tos) == META_TRUE) {
		//TODO implement
	}

	next_hop = IP4_next_hop(module, destination);
	PRINT_DEBUG("next_hop: address=%u, interface=%u", next_hop.address, next_hop.interface);
	if (next_hop.interface) {
		//stats.outfragments++;
		uint32_t my_host_ip_addr = 0; //TODO remove/fix, is for compiling
		if (next_hop.address == my_host_ip_addr || next_hop.address == my_host_ip_addr) {
			PRINT_DEBUG("internal, routing back to netw layer");
			struct timeval current;
			gettimeofday(&current, 0);
			secure_metadata_writeToElement(meta, "recv_stamp", &current, META_TYPE_INT64);

			secure_metadata_writeToElement(meta, "recv_protocol", &protocol, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "recv_src_ip", &source, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "recv_dst_ip", &destination, META_TYPE_INT32);

			if (send_ttl) {
				secure_metadata_writeToElement(meta, "recv_ttl", &send_ttl, META_TYPE_INT32);
			}
			if (send_tos) {
				secure_metadata_writeToElement(meta, "recv_tos", &send_tos, META_TYPE_INT32);
			}

			ff->dataFrame.directionFlag = DIR_UP;

			//module_to_switch(module, ff);
			if (!module_send_flow(module, (struct fins_module_table *) module->data, ff, IPV4_FLOW_UP)) {
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
			}
		} else {
			/** TODO
			 * finding out what is wrong with the fragmentation and reimplement it
			 * correctly
			 * Notice that the current implementation support mutlithreading
			 * while the basic opf the implemented fragmentation is based on having one
			 * global packet to hold the contents
			 */
			/**
			 while (more_fragments)
			 {
			 fragment = IP4_fragment_data(data, length, offset, IP4_PCK_LEN
			 - IP4_MIN_HLEN);
			 memcpy(fragment.data, construct_packet_buffer->ip_data,
			 fragment.data_length);
			 construct_packet_buffer->ip_fragoff = htons(fragment.first >> 3);
			 construct_packet_buffer->ip_len = htons(fragment.data_length
			 + IP4_MIN_HLEN);
			 more_fragments = fragment.more_fragments;
			 next_hop = IP4_next_hop(destination);
			 if (next_hop.interface>=0)
			 {
			 stats.outfragments++;
			 PRINT_DEBUG("");
			 print_finsFrame(ff);
			 IP4_send_fdf_out(ff, construct_packet_buffer, next_hop, fragment.data_length);
			 }
			 else
			 {
			 PRINT_DEBUG("No route to the destination, packet discarded");
			 }
			 more_fragments = fragment.more_fragments;
			 offset = fragment.last + 1;
			 }

			 */
			construct_packet_buffer->ip_fragoff = htons(0);
			construct_packet_buffer->ip_id = htons(0);
			construct_packet_buffer->ip_len = htons(length + IP4_MIN_HLEN);
			construct_packet_buffer->ip_cksum = 0;
			construct_packet_buffer->ip_cksum = IP4_checksum(construct_packet_buffer, IP4_MIN_HLEN);

			//print_finsFrame(ff);
			IP4_send_fdf_out(module, ff, construct_packet_buffer, next_hop, length);
			return;
		}
	}
}
