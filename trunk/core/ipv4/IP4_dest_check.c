/*
 * IP4_is_my_ip.c
 *
 *  Created on: Jun 11, 2010
 *      Author: rado
 *
 *      Function compares the supplied destination address to the list of the hosts IP addresses
 *      Returns 1 if address is our, 0 if not.
 *      It is aware of broadcast addresses as well
 */

#include "ipv4.h"

int IP4_dest_check(uint32_t destination) {
	uint32_t subnet_broadcast = my_host_ip_addr | (~my_host_mask);
	uint32_t network_broadcast;

	if (IP4_CLASSA(my_host_ip_addr)) {
		network_broadcast = my_host_ip_addr | (~IP4_ADR_P2H(255, 0, 0, 0));
	} else if (IP4_CLASSB(my_host_ip_addr)) {
		network_broadcast = my_host_ip_addr | (~IP4_ADR_P2H(255, 255, 0, 0));
	} else if (IP4_CLASSC(my_host_ip_addr)) {
		network_broadcast = my_host_ip_addr | (~IP4_ADR_P2H(255, 255, 255, 0));
	}

	if (destination == my_host_ip_addr || destination == IP4_ADR_P2H(127,0,0,1)
			|| destination == subnet_broadcast || destination
			== network_broadcast || destination == IP4_ADR_P2H(255,255,255,255)
			|| destination == IP4_ADR_P2H(0,0,0,0)) {
		return (1);
	}
	return (0);
}
