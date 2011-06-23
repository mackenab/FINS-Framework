/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"

extern struct ip4_stats stats;

//extern struct ip4_packet *construct_packet_buffer;
void IP4_out(struct finsFrame *ff, uint16_t length, IP4addr source,
		uint8_t protocol) {

	PRINT_DEBUG("");
	//print_finsFrame(ff);
	char *data = (char *) ((ff->dataFrame).pdu);
	PRINT_DEBUG("");

	uint8_t more_fragments = 1;
	uint16_t offset = 0;
	IP4addr destination;

	struct ip4_next_hop_info next_hop;
	struct ip4_fragment fragment;
	struct ip4_packet_header construct_packet;
	struct ip4_packet *construct_packet_buffer;

	construct_packet_buffer = &construct_packet;
	PRINT_DEBUG("");

	metadata_readFromElement(ff->dataFrame.metaData, "dstip", &destination);

	PRINT_DEBUG("");

	IP4_const_header(construct_packet_buffer, source, destination, protocol);
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
	construct_packet_buffer->ip_cksum = IP4_checksum(construct_packet_buffer,
			IP4_MIN_HLEN);

	next_hop = IP4_next_hop(destination);
	if (next_hop.interface >= 0) {
		//stats.outfragments++;
		PRINT_DEBUG("");
		//print_finsFrame(ff);
		IP4_send_fdf_out(ff, construct_packet_buffer, next_hop, length);
	} else {
		PRINT_DEBUG("No route to the destination, packet discarded");
	}

}
