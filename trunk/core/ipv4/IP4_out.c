/*
 * IP4_out.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <finsqueue.h>

extern struct ip4_stats stats;
extern uint32_t my_ip_addr;

//extern struct ip4_packet *construct_packet_buffer;
void IP4_out(struct finsFrame *ff, uint16_t length, uint32_t source, uint32_t protocol) {
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

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_dst_ip", &destination);

	PRINT_DEBUG("src_ip=%u, dst_ip=%u", source, destination);

	IP4_const_header(construct_packet_buffer, source, destination, protocol);

	uint32_t send_ttl = 0;
	if (metadata_readFromElement(params, "send_ttl", &send_ttl) == META_TRUE) {
		construct_packet_buffer->ip_ttl = send_ttl;
	}

	uint32_t send_tos = 0;
	if (metadata_readFromElement(params, "send_tos", &send_tos) == META_TRUE) {
		//TODO implement
	}

	next_hop = IP4_next_hop(destination);
	PRINT_DEBUG("next_hop: address=%u, interface=%u", next_hop.address, next_hop.interface);
	if (next_hop.interface) {
		//stats.outfragments++;
		if (next_hop.address == my_ip_addr || next_hop.address == my_ip_addr) {
			PRINT_DEBUG("internal, routing back to netw layer");

			secure_metadata_writeToElement(params, "recv_protocol", &protocol, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "recv_src_ip", &source, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "recv_dst_ip", &destination, META_TYPE_INT32);

			if (send_ttl) {
				secure_metadata_writeToElement(params, "recv_ttl", &send_ttl, META_TYPE_INT32);
			}
			if (send_tos) {
				secure_metadata_writeToElement(params, "recv_tos", &send_tos, META_TYPE_INT32);
			}

			//ff->dataOrCtrl = DATA;
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
				PRINT_ERROR("invalid protocol: protocol=%u", protocol);
				freeFinsFrame(ff);
				return;
			}
			//ff->metaData = params;

			ff->dataFrame.directionFlag = DIR_UP;

			ipv4_to_switch(ff);
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
			IP4_send_fdf_out(ff, construct_packet_buffer, next_hop, length);
			return;
		}
	}
}
