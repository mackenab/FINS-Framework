/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "IP4.h"

extern struct ip4_stats stats;

extern struct ip4_packet *construct_packet_buffer;
void IP4_out(void *data, uint16_t length, IP4addr source, IP4addr destination,
		uint8_t protocol)
{
	PRINT_DEBUG("%u.%u.%u.%u \t", (unsigned int) source >> 24,
					(unsigned int) (source >> 16) & 0xFF,
					(unsigned int) (source >> 8) & 0xFF,
					(unsigned int) source & 0xFF);
	uint8_t more_fragments = 1;
	uint16_t offset = 0;
	struct ip4_next_hop_info next_hop;
	struct ip4_fragment fragment;
	IP4_const_header(construct_packet_buffer, source, destination, protocol);
	while (more_fragments)
	{
		fragment = IP4_fragment_data(data, length, offset, IP4_PCK_LEN
				- IP4_MIN_HLEN);
		memcpy(construct_packet_buffer->ip_data, fragment.data,
				fragment.data_length); // todo: Don't crash on length<8
		//todo: Check for memory leaks-> very likely!!
		construct_packet_buffer->ip_fragoff = htons(fragment.first >> 3);
		construct_packet_buffer->ip_len = htons(fragment.data_length
				+ IP4_MIN_HLEN);
		more_fragments = fragment.more_fragments;
		next_hop = IP4_next_hop(destination);
		if (next_hop.interface>=0){
			construct_packet_buffer->ip_cksum = IP4_checksum(construct_packet_buffer,IP4_MIN_HLEN);
			IP4_send_fdf_out(construct_packet_buffer, next_hop, fragment.data_length+IP4_MIN_HLEN);
			stats.outfragments++;
		}else{
			PRINT_DEBUG("No route to the destination, packet discarded");
		}
		more_fragments = fragment.more_fragments;
		offset = fragment.last + 1;
	}

}
