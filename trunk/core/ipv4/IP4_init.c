/**
 * @brief
 *
 */

#include "ipv4.h"

//extern struct ip4_packet *construct_packet_buffer;
extern struct ip4_routing_table* routing_table;
extern struct ip4_stats stats;

void IP4_init(void) {
	PRINT_DEBUG("entered IP4_init");
	//construct_packet_buffer = (struct ip4_packet*) malloc(IP4_PCK_LEN);
	PRINT_DEBUG("after constr pckt buff");
	routing_table = IP4_sort_routing_table(IP4_get_routing_table());
	PRINT_DEBUG("after ip4 sort route table");
	memset(&stats, 0, sizeof(struct ip4_stats));
	PRINT_DEBUG("after memset");
#ifdef DEBUG
	IP4_print_routing_table(routing_table);
#endif
	return;
}
