/**
 * @file IP4_in.c
 * @author Rado Petrik
 * @brief Branch handling incoming traffic
 */

#include "IP4.h"

extern struct ip4_stats stats;
/**
 * @brief Function processing all the incoming packets
 *
 * Responsible for parsing, checking reassembling and passing packets out.
 */
void IP4_in(struct ip4_packet* ppacket, int len)
{

	stats.receivedtotal++;
	/* Parse the header. Some of the items only needed to be inserted into FDF meta data*/
	struct ip4_header header;
	header.source = ntohl(ppacket->ip_src);
	header.destination = ntohl(ppacket->ip_dst);
	header.version = IP4_VER(ppacket);
	header.header_length = IP4_HLEN(ppacket);
	header.differentiated_service = ppacket->ip_dif;
	header.packet_length = ntohs(ppacket->ip_len);
	header.id = ntohs(ppacket->ip_id);
	header.flags = (uint8_t) (IP4_FLG(ntohs(ppacket->ip_fragoff));
	header.fragmentation_offset = ntohs(ppacket->ip_fragoff) & IP4_FRAGOFF;
	header.ttl = ppacket->ip_ttl;
	header.protocol = ppacket->ip_proto;
	header.checksum = ntohs(ppacket->ip_cksum);


	/* Check packet version */
	if (header.version != IP4_VERSION)
	{
		stats.badver++;
		stats.droppedtotal++;
		PRINT_ERROR("Packet ID %d has a wrong IP version (%d)", header.id,header.version);
		//free ppacket
		return;
	}

	/* Check minimum header length */
	if (header.header_length < IP4_MIN_HLEN)
	{
		stats.badhlen++;
		stats.droppedtotal++;
		PRINT_ERROR("Packet header length (%d) in packet ID %d is smaller than the defined minimum (20).",header.header_length, header.id);
		//free ppacket
		return;
	}

	/* Check the integrity of the header. Drop the packet if corrupted header.*/
	if (IP4_checksum(ppacket, IP4_HLEN(ppacket)) != 0)
	{
		stats.badsum++;
		stats.droppedtotal++;
		PRINT_ERROR("Checksum check failed on packet ID %d, non zero result: %d",header.id, IP4_checksum(ppacket, IP4_HLEN(ppacket)));
		//free ppacket
		return;
	}

	/* Check the length of the packet. If physical shorter than the declared in the header
	 * drop the packet
	 */
	if (header.packet_length != len)
	{
		stats.badlen++;
		PRINT_DEBUG("The declared length is not equal to the actual length.");
		if (header.packet_length > len)
		{
			stats.droppedtotal++;
			//free ppacket
			return;
		}
	}

	/* Check the destination address, if not our, forward*/
	if (IP4_dest_check(header.destination) == 0)
	{
		if(IP4_forward(ppacket, header.destination, len)){
			return;
		}
		stats.droppedtotal++;
		//free ppacket
		return;
	}

	/* Check fragmentation errors */
	if ((header.flags & (IP4_DF | IP4_MF)) == (IP4_DF | IP4_MF))
	{
		stats.fragerror++;
		stats.droppedtotal++;
		PRINT_ERROR("Packet ID %d has both DF and MF flags set",header.id);
		//free ppacket
		return;
	}
	/* If not fragmented, pass out. If fragmented, call reassembly algorithm.
	 * If reassembly of an entire packet completed by this frame, pass out.
	 * Otherwise return.
	 */
	if (((header.flags & IP4_MF) | header.fragmentation_offset) == 0)
	{
		stats.delivered++;
		IP4_send_fdf_in(&header, ppacket);
		//free ppacket
		return;
	} else{
		PRINT_DEBUG("Packet ID %d is fragmented", header.id);
		struct ip4_packet* ppacket_reassembled = IP4_reass(&header, ppacket);
		//free ppacket
		if(ppacket_reassembled != NULL){
			stats.delivered++;
			stats.reassembled++;
			IP4_send_fdf_in(&header, ppacket_reassembled);
		}
		return;
	}

}
