/**
 * @file IP4.c
 * @brief FINS module - Internet Protocol version 4
 *
 * Main function of the module.
 */


#include "IP4.h"


IP4addr my_ip_addr = IP4_ADR_P2N(172,31,165,252);
IP4addr my_mask = IP4_ADR_P2N(255, 255, 255, 0);
struct ip4_routing_table* routing_table;
struct ip4_stats stats;



int main(int argc, char *argv[])
{
	IP4_init(argc, argv);
	char a[]="test";
	IP_testharness_init(a);
	struct finsFrame ff;

	int i;
	for(i=0;i<30;i++)
	{
		IP4_receive_fdf(&ff);
	}
	IP_testharness_terminate();

	return EXIT_SUCCESS;
}
