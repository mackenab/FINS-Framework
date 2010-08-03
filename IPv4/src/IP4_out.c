/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "IP4.h"

extern struct ip4_stats stats;

struct ip4_packet *construct_packet_buffer;
void IP4_out(void *data, uint16_t length, IP4addr source, IP4addr destination,
		uint8_t protocol)
{
	uint8_t more_fragments = 1;
	uint16_t offset = 0;
	struct ip4_next_hop_info next_hop;
	struct ip4_fragment fragment;
	IP4_const_header(construct_packet_buffer, source, destination, protocol);
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
		if (next_hop.interface>=0){
			stats.outfragments++;
			IP4_send_fdf_out(construct_packet_buffer, next_hop, fragment.data_length);
		}else{
			PRINT_DEBUG("No route to the destination, packet discarded");
		}
		more_fragments = fragment.more_fragments;
		offset = fragment.last + 1;
	}

}
