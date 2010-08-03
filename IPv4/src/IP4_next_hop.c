/*
 * IP4_next_hop.c
 *
 *  Created on: Jul 21, 2010
 *      Author: rado
 */
#include "IP4.h"

extern struct ip4_routing_table* routing_table;

struct ip4_next_hop_info IP4_next_hop(IP4addr dst)
{
	struct ip4_next_hop_info info;
	IP4addr mask;
	struct ip4_routing_table* current_table_entry = routing_table;
	while (current_table_entry != NULL)
	{
		mask = 0xffff << (IP4_ALEN * 8 - current_table_entry->mask);
		if (((current_table_entry->dst & mask) == (dst & mask))
				| (current_table_entry->dst == 0)) // if dst=0, this is the default route, always match
		{
			if (current_table_entry->gw == 0) // dst host in on our net, can be contacted directly
			{
				info.address = dst;
				info.interface = current_table_entry->interface;
				return info;
			} else // dst host is outside of our net, needs to be contacted via gw
			{
				info.address = current_table_entry->gw;
				info.interface = current_table_entry->interface;
				return info;
			}
		}
		current_table_entry = current_table_entry->next_entry;
	}
	info.interface = -1;
	return info;
}
