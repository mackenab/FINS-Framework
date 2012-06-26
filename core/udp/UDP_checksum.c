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
	uint8_t *ptr;
	uint32_t sum = 0;

	//packet is in network format

	//fake IP header
	ptr = (uint8_t *) &src_ip;
	for (i = 0, ptr--; i < 4; i += 2) {
		sum += (*++ptr << 8) + *++ptr;
	}

	ptr = (uint8_t *) &dst_ip;
	for (i = 0, ptr--; i < 4; i += 2) {
		sum += (*++ptr << 8) + *++ptr;
	}

	sum += (UDP_PROTOCOL); //TODO check!
	sum += pcket->u_len;

	ptr = (uint8_t *) pcket;

	uint16_t len = ntohs(pcket->u_len);
	if (len & 0x1) {
		sum += ptr[--len] << 8;
	}

	for (i = 0, ptr--; i < len; i += 2) {
		PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i, *(ptr+1), *(ptr+1), i+1, *(ptr+2), *(ptr+2));
		sum += (*++ptr << 8) + *++ptr;
		//if (sum >> 16) {sum = ++sum & 0xFFFF;} //alternative to while loop
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;
	return htons((uint16_t) sum);
}

