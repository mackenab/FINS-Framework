/**
 * @file IP4_in.c
 * @author Rado Petrik
 * @brief Branch handling incoming traffic
 */

#include "ipv4_internal.h"

/**
 * @brief Function processing all the incoming packets
 *
 * Responsible for parsing, checking reassembling and passing packets out.
 */
void ipv4_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct ipv4_data *md = (struct ipv4_data *) module->data;

	struct ip4_packet* ppacket = (struct ip4_packet*) ff->dataFrame.pdu;
	int len = ff->dataFrame.pduLength;

	md->stats.receivedtotal++;
	/* Parse the header. Some of the items only needed to be inserted into FDF meta data*/
	struct ip4_header header;
	header.source = ntohl(ppacket->ip_src);
	header.destination = ntohl(ppacket->ip_dst);
	header.version = IP4_VER(ppacket);
	header.header_length = IP4_HLEN(ppacket);
	header.differentiated_service = ppacket->ip_dif;
	header.packet_length = ntohs(ppacket->ip_len);
	header.id = ntohs(ppacket->ip_id);
	header.flags = (uint8_t) (IP4_FLG(ntohs(ppacket->ip_fragoff)));
	header.fragmentation_offset = ntohs(ppacket->ip_fragoff) & IP4_FRAGOFF;
	header.ttl = ppacket->ip_ttl;
	header.protocol = ppacket->ip_proto;
	PRINT_DEBUG("protocol number is %d", header.protocol);
	header.checksum = ntohs(ppacket->ip_cksum);
	PRINT_DEBUG("");

	/** Check packet version */
	if (header.version != IP4_VERSION) {
		md->stats.badver++;
		md->stats.droppedtotal++;
		PRINT_ERROR("Packet ID %d has a wrong IP version (%d)", header.id, header.version);
		//free ppacket
		return;
	}
	PRINT_DEBUG("");

	/* Check minimum header length */
	if (header.header_length < IP4_MIN_HLEN) {
		PRINT_ERROR("Packet header length (%d) in packet ID %d is smaller than the defined minimum (20).", header.header_length, header.id);
		md->stats.badhlen++;
		md->stats.droppedtotal++;

		//free ppacket
		freeFinsFrame(ff);
		return;
	}
	int hlen = IP4_HLEN(ppacket);
	PRINT_DEBUG("hdr_len=%u, hlen=%u", header.header_length, IP4_HLEN(ppacket));

	/* Check the integrity of the header. Drop the packet if corrupted header.*/
	if (ipv4_checksum(ppacket, hlen) != 0) { //TODO check this checksum, don't think it does uneven?
		PRINT_ERROR("Checksum check failed on packet ID %d, non zero result: %d", header.id, ipv4_checksum(ppacket, IP4_HLEN(ppacket)));
		md->stats.badsum++;
		md->stats.droppedtotal++;

		//free ppacket
		freeFinsFrame(ff);
		return;
	}
	PRINT_DEBUG("");

	/* Check the length of the packet. If physical shorter than the declared in the header
	 * drop the packet
	 */
	if (header.packet_length != len) {
		md->stats.badlen++;
		PRINT_DEBUG("The declared length is not equal to the actual length. pkt_len=%u len=%u", header.packet_length, len);
		if (header.packet_length > len) {
			PRINT_DEBUG("The header length is even longer than the len");
			md->stats.droppedtotal++;

			//free ppacket
			freeFinsFrame(ff);
			return;
		}
	}
	PRINT_DEBUG("");

	if (header.ttl == 0) {
		PRINT_ERROR("todo");
		//TODO discard packet & send TTL icmp to sender

		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("src=%u, dst=%u (hostf)", header.source, header.destination);
	/* Check the destination address, if not our, forward*/
	if (header.destination != IPV4_ADDR_ANY_IP && header.destination != IPV4_ADDR_EVERY_IP) { //TODO check this
		struct addr_record *addr = (struct addr_record *) list_find1(md->addr_list, addr_ipv4_test, &header.destination);
		if (addr == NULL) {
			addr = (struct addr_record *) list_find1(md->addr_list, addr_bdcv4_test, &header.destination);
			if (addr == NULL) {
				if (ipv4_forward(module, ff, ppacket, header.destination, len)) { //TODO disabled atm
					md->stats.forwarded++;
					PRINT_DEBUG("");
				} else {
					md->stats.droppedtotal++;
					PRINT_DEBUG("");
					freeFinsFrame(ff);
				}
				return;
			}
		}
	}
	PRINT_DEBUG("");

	/* Check fragmentation errors */
	if ((header.flags & (IP4_DF | IP4_MF)) == (IP4_DF | IP4_MF)) {
		md->stats.fragerror++;
		md->stats.droppedtotal++;
		PRINT_ERROR("Packet ID %d has both DF and MF flags set", header.id);
		//free ppacket
		freeFinsFrame(ff);
		return;
	}
	/* If not fragmented, pass out. If fragmented, call reassembly algorithm.
	 * If reassembly of an entire packet completed by this frame, pass out.
	 * Otherwise return.
	 */
	PRINT_DEBUG("");

	if (((header.flags & IP4_MF) | header.fragmentation_offset) == 0) {
		md->stats.delivered++;
		PRINT_DEBUG("");

		ipv4_send_fdf_in(module, ff, &header, ppacket);
	} else {
		PRINT_ERROR("todo");
		//TODO fix this!! convert to module based
		PRINT_DEBUG("Packet ID %d is fragmented", header.id);
		struct ip4_packet* ppacket_reassembled = NULL; //IP4_reass(&header, ppacket);
		//free ppacket
		if (ppacket_reassembled != NULL) {
			md->stats.delivered++;
			md->stats.reassembled++;
			ipv4_send_fdf_in(module, ff, &header, ppacket_reassembled);
		} else {

		}
	}
}
