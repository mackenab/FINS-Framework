/*
 * IP4_forward.c
 *
 *  Created on: Jul 20, 2010
 *      Author: rado
 */
#include "IP4.h"

extern struct ip4_stats stats;

int IP4_forward(struct ip4_packet* ppacket, IP4addr dest, uint16_t length){
	struct ip4_next_hop_info next_hop = IP4_next_hop(dest);
	if(next_hop.interface>=0){
		IP4_send_fdf_out(ppacket, next_hop, length);
		return 1;
	}
	stats.cantforward++;
	return 0;
}
