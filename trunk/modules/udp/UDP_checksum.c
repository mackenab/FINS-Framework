/**@file UDP_checksum.c
 * UDP_checksum.c
 *
 *  Created on: Jun 28, 2010
 *      Author: Abdallah Abdallah
 */
#include "udp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <finstypes.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @brief calculates the checksum for a UDP datagram.
 * @param pcket is the UDP packet containing both its header and the data
 * @param meta is the necessary data to used in the pseudoheader.
 *
 *  The checksum is calculated by looping first through the metadata's pseudoheader information and summing it.
 *  Then the it loops through the UDP packet header. Next the length of the datagram is checked. It is then made
 *  to be even if it is odd, or otherwise left alone. This is necessary to guarantee we don't add a random block of
 *  memory as it is being added in 2 byte chunks. for this reason the length is divided by 2. The data is then
 *  looped through summing it with the previous loops. It is then shifted to remove all carries. The one's complement
 *  is taken and returned.
 *  If the datagram is correct, the returned value should be zero. However, this function can be used to calculate
 *  the true checksum by setting the checksum field to 0 and using the returned value as the checksum.
 */

/**
 * @brief calculates the checksum for a UDP datagram.
 * @param pcket is the UDP packet containing both its header and the data
 * @param meta is the necessary data to used in the pseudoheader.
 *
 *  The checksum is calculated by looping first through the metadata's pseudoheader information and summing it.
 *  Then the it loops through the UDP packet header. Next the length of the datagram is checked. It is then made
 *  to be even if it is odd, or otherwise left alone. This is necessary to guarantee we don't add a random block of
 *  memory as it is being added in 2 byte chunks. for this reason the length is divided by 2. The data is then
 *  looped through summing it with the previous loops. It is then shifted to remove all carries. The one's complement
 *  is taken and returned.
 *  If the datagram is correct, the returned value should be zero. However, this function can be used to calculate
 *  the true checksum by setting the checksum field to 0 and using the returned value as the checksum.
 */

struct checksum_udp_hdr {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zeros;
	uint8_t protocol;
	uint16_t udp_len;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t data[];
};

//assume all inputs are in network format, returns checksum in host format
uint16_t UDP_checksum(struct udp_packet* pcket_netw, uint32_t src_ip_netw, uint32_t dst_ip_netw) {
	PRINT_DEBUG("Entered: (N) src_ip=%u (0x%x), dst_ip=%u (0x%x)", src_ip_netw, src_ip_netw, dst_ip_netw, dst_ip_netw);

	int i;
	uint8_t *pt;
	uint32_t sum = 0;

	//packet is in network format
	struct in_addr temp_src;
	temp_src.s_addr = src_ip_netw;
	PRINT_DEBUG("src_ip='%s'", inet_ntoa(temp_src));
	struct in_addr temp_dst;
	temp_dst.s_addr = dst_ip_netw;
	PRINT_DEBUG("dst_ip='%s'", inet_ntoa(temp_dst));

	struct checksum_udp_hdr hdr;
	hdr.src_addr = src_ip_netw;
	hdr.dst_addr = dst_ip_netw;
	hdr.zeros = 0;
	hdr.protocol = UDP_PT_UDP;
	hdr.udp_len = pcket_netw->u_len;

	pt = (uint8_t *) &hdr;
	for (i = 0; i < 12; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i, *(ptr+1), *(ptr+1), i+1, *(ptr+2), *(ptr+2));
		sum += (*pt << 8) + *(pt + 1);
	}

	uint16_t len = ntohs(pcket_netw->u_len);
	PRINT_DEBUG("len=%d", len);

	pt = (uint8_t *) pcket_netw;
	if (len & 0x1) {
		//PRINT_DEBUG("uneven: %u=%2x (%u), %2x (%u)", len-1, ptr[len-1], ptr[len-1], 0, 0);
		sum += pt[--len] << 8;
	}

	for (i = 0; i < len; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i, *(ptr+1), *(ptr+1), i+1, *(ptr+2), *(ptr+2));
		sum += (*pt << 8) + *(pt + 1);
		//if (sum >> 16) {sum = ++sum & 0xFFFF;} //alternative to while loop
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;
	//return htons((uint16_t) sum);
	return (uint16_t) sum;
}

