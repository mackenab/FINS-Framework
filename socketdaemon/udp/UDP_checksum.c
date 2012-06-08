/**@file UDP_checksum.c
 * UDP_checksum.c
 *
 *  Created on: Jun 28, 2010
 *      Author: Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <finstypes.h>
#include "udp.h"

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
unsigned short UDP_checksum(struct udp_packet* pcket, uint32_t src_ip, uint32_t dst_ip) {

	int i;
	//packet is in network format
	uint32_t sum = 0;

	//fake IP header
	sum += ((uint16_t)(src_ip >> 16)) + ((uint16_t)(src_ip & 0xFFFF));
	sum += ((uint16_t)(dst_ip >> 16)) + ((uint16_t)(dst_ip & 0xFFFF));
	sum += (uint16_t) UDP_PROTOCOL;
	sum += IP_HEADER_LEN + pcket->u_len;

	//fake UDP header
	sum += pcket->u_src;
	sum += pcket->u_dst;
	sum += pcket->u_len;
	//checksum set to 0

	uint16_t *ptr = (uint16_t *) pcket->u_data;
	uint16_t data_len = ntohs(pcket->u_len) - U_HEADER_LEN;
	PRINT_DEBUG("pkt=%u ptr=%u *ptr=%u data_len=%d", (unsigned int)pcket, ptr, *ptr, data_len);
	for (i = 0; i < data_len; i += 2) {
		sum += *ptr++;
	}

	if (data_len & 0x1) {
		sum += *ptr & 0xFF00;
	}

	sum = (sum & 0xFFFF) + (sum & 0xFFFF0000);
	if (sum & 0x00010000) {
		sum++;
	}

	sum = ~sum;
	return ((uint16_t) sum);
}

