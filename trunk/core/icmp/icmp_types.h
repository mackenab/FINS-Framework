/**
 * icmp_types.h
 *
 *  Created on: Jul 20, 2011
 *      Author: Mark Hutcheson
 */

#ifndef ICMP_TYPES_H_
#define ICMP_TYPES_H_

#include <stdint.h>

//Structure for sending finsFrames that are ICMP error frames. More fields can be safely added as we add
//implementation for more ICMP error types
struct icmperrormsg
{
	uint8_t		type;	//ICMP packet type
	uint8_t		code;	//And code
	uint16_t	datalen;	//Length of data
	//Data. Should I store as a pointer?
	uint8_t *	data;
};

#endif
