/**
 * @file IP4.c
 * @brief FINS module - Internet Protocol version 4
 *
 * Main function of the module.
 */

#include "ipv4.h"
#include <queueModule.h>

IP4addr my_ip_addr;
IP4addr loopback = IP4_ADR_P2H(127, 0, 0, 1);
IP4addr my_mask;
struct ip4_routing_table* routing_table;
struct ip4_packet *construct_packet_buffer;
struct ip4_stats stats;

void ipv4_init() {
	PRINT_DEBUG("IPv4 Started");
	ipv4_running = 1;

	/* find a way to get the IP of the desired interface automatically from the system
	 * or from a configuration file
	 */

	my_ip_addr = IP4_ADR_P2H(192, 168, 1, 20);
	//my_ip_addr = IP4_ADR_P2H(127, 0, 0, 1);
	//my_ip_addr = IP4_ADR_P2H(172, 31, 63, 231);
	//my_ip_addr = IP4_ADR_P2H(172, 31, 53, 114);
	/** TODO get the IP of the default interface from
	 * the configuration file (To Be done by the initialization primary thread
	 * before invokiung the IPv4 thread). Same for the mask value. It can be also
	 * read dynamically from the conventional stack before taking any action to get
	 * the conventional stack down (Using the iptables API)
	 *
	 */
	PRINT_DEBUG("%lu", my_ip_addr);
	my_mask = IP4_ADR_P2H(255, 255, 255, 0);

	//ADDED mrd015 !!!!!
#ifndef BUILD_FOR_ANDROID
	IP4_init();
#endif

	while (ipv4_running) {
		IP4_receive_fdf();
		PRINT_DEBUG("");
		//	free(ff);

	}

	PRINT_DEBUG("IPv4 Terminating");
}

void ipv4_shutdown() {
	ipv4_running = 0;

	//TODO expand this
}

void ipv4_free() {
	//TODO free all module related mem
}
