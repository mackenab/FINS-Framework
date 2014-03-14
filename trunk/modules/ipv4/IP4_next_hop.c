/*
 * IP4_next_hop.c
 *
 *  Created on: Jul 21, 2010
 *      Author: rado
 */
#include "ipv4_internal.h"

struct ip4_next_hop_info IP4_next_hop(struct fins_module *module, uint32_t dst) {
	PRINT_DEBUG("Entered: module=%p, dst=%u", module, dst);

	struct ip4_next_hop_info info;
	//uint32_t mask;
	struct ip4_routing_table* current_table_entry = routing_table;
	while (current_table_entry != NULL) {
		//mask = (uint32_t)((0xffffffff << (8*IP4_ALEN - current_table_entry->mask)) & 0xffffffff);
		PRINT_DEBUG("table->dst=%u, mask=0x%x, table=0x%x, dst=0x%x",
				current_table_entry->dst, current_table_entry->mask, current_table_entry->dst & current_table_entry->mask, dst & current_table_entry->mask);
		if (((current_table_entry->dst & current_table_entry->mask) == (dst & current_table_entry->mask)) || (current_table_entry->dst == 0)) { //if dst=0, this is the default route, always match
			if (current_table_entry->gw == 0) { //dst host in on our net, can be contacted directly
				info.address = dst;
				info.interface = current_table_entry->interface;
				PRINT_DEBUG("Exited: dst=%u, metric=%u", dst, current_table_entry->metric);
				return info;
			} else { //dst host is outside of our net, needs to be contacted via gw
				info.address = current_table_entry->gw;
				info.interface = current_table_entry->interface;
				PRINT_DEBUG("Exited: dst=%u, metric=%u", dst, current_table_entry->metric);
				return info;
			}
		}
		current_table_entry = current_table_entry->next_entry;
	}
	PRINT_DEBUG("Exited: dst=%u, none", dst);
	info.interface = 0; //shouldn't happen
	return info;
}
