/*
 * IP4_const_prelim_header.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "IP4.h"

extern IP4addr my_ip_addr;
extern IP4addr my_mask;

void IP4_const_header(struct ip4_packet *packet, IP4addr source, IP4addr destination,
		uint8_t protocol)
{
	static uint16_t unique_id;

	packet->ip_verlen = IP4_VERSION << 4;
	packet->ip_verlen |= IP4_MIN_HLEN / 4;
	packet->ip_dif = 0;
	packet->ip_id = htons(unique_id++);
	packet->ip_ttl = IP4_INIT_TTL;
	packet->ip_proto = protocol;
	packet->ip_src = htonl(source);
	packet->ip_dst = htonl(destination);
}
