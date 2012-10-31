/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

extern struct ip4_stats stats;

//extern struct ip4_packet *construct_packet_buffer;
void IP4_out(struct finsFrame *ff, uint16_t length, IP4addr source, uint8_t protocol) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, len=%u, src=%lu, proto=%u", ff, ff->metaData, length, source, protocol);

	//print_finsFrame(ff);
	//char *data = (char *) ((ff->dataFrame).pdu);
	PRINT_DEBUG("");

	//uint8_t more_fragments = 1;
	//uint16_t offset = 0;
	IP4addr destination;

	struct ip4_next_hop_info next_hop;
	//struct ip4_fragment fragment;
	struct ip4_packet_header construct_packet;
	struct ip4_packet *construct_packet_buffer;

	//construct_packet_buffer = &construct_packet;
	construct_packet_buffer = (struct ip4_packet *) &construct_packet;
	PRINT_DEBUG("");

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "send_dst_ip", &destination) == META_FALSE;

	if (ret) {
		PRINT_ERROR("todo error");

		//TODO error
	}

	PRINT_DEBUG("");

	IP4_const_header(construct_packet_buffer, source, destination, protocol);

	uint32_t send_ttl;
	if (metadata_readFromElement(ff->metaData, "send_ttl", &send_ttl) == META_TRUE) {
		construct_packet_buffer->ip_ttl = send_ttl;
	}

	uint32_t tos;
	if (metadata_readFromElement(ff->metaData, "send_tos", &tos) == META_TRUE) {
		//TODO implement
	}

	PRINT_DEBUG("");
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

	next_hop = IP4_next_hop(destination);
	if (next_hop.interface >= 0) {
		//stats.outfragments++;
		PRINT_DEBUG("");
		//print_finsFrame(ff);
		IP4_send_fdf_out(ff, construct_packet_buffer, next_hop, length);
	} else {
		PRINT_ERROR("No route to the destination, packet discarded");
		freeFinsFrame(ff);
	}
}
