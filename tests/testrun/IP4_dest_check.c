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

#include "IP4.h"

extern IP4addr my_ip_addr;
extern IP4addr my_mask;


int IP4_dest_check(IP4addr destination)
{
	IP4addr subnet_broadcast = my_ip_addr | (~my_mask);
	IP4addr network_broadcast;

	if (IP4_CLASSA(my_ip_addr))
	{
		network_broadcast = my_ip_addr | (~IP4_ADR_P2N(255, 0, 0, 0));
	} else if (IP4_CLASSB(my_ip_addr))
	{
		network_broadcast = my_ip_addr | (~IP4_ADR_P2N(255, 255, 0, 0));
	} else if (IP4_CLASSC(my_ip_addr))
	{
		network_broadcast = my_ip_addr | (~IP4_ADR_P2N(255, 255, 255, 0));
	}

	if(		destination == my_ip_addr ||
			destination == IP4_ADR_P2N(127,0,0,1) ||
			destination == subnet_broadcast ||
			destination == network_broadcast ||
			destination == IP4_ADR_P2N(255,255,255,255) ||
			destination == IP4_ADR_P2N(0,0,0,0)
	)
	{
		return (1);
	}
	return (0);
}
