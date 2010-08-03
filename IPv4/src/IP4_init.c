/**
 * @brief
 *
 */

#include "IP4.h"

extern struct ip4_packet *construct_packet_buffer;
extern struct ip4_routing_table* routing_table;
extern struct ip4_stats stats;

void IP4_init(int argc, char *argv[])
{
	construct_packet_buffer = (struct ip4_packet*) malloc(IP4_PCK_LEN);
	routing_table=IP4_sort_routing_table(IP4_get_routing_table());
	memset(&stats,0,sizeof(struct ip4_stats));
#ifdef DEBUG
	IP4_print_routing_table(routing_table);
#endif
	return;
}
