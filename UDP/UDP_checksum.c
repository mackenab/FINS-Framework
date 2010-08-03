/**@file UDP_checksum.c
 * UDP_checksum.c
 *
 *  Created on: Jun 28, 2010
 *      Author: alex
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "finstype.h"
#include "udp.h"

/**
 * @brief calculates the checksum for a UDP datagram.
 * @param pcket is the UDP packet containing both its header and the data
 * @param meta is the necessary data to used in the pseudoheader.
 *
 *  The checksum is calculated by looping first through the metadata's pseudoheader information and summing it.
 *  Then the it loops through the UDP packet header. Next the length of the datagram is checked. It is then made
 *  to be even if it is odd, or otherwise left alone. This is necessary to guarantee we don't add a random block of
 *  memory as it is being added in 2 byte chunks. for this reason the length is divided by 2. The data is then
 *  looped through summing it with the previous loops. It is then shifted to remove all carries. The one's complement
 *  is taken and returned.
 *  If the datagram is correct, the returned value should be zero. However, this function can be used to calculate
 *  the true checksum by setting the checksum field to 0 and using the returned value as the checksum.
 */
unsigned short UDP_checksum(struct udp_packet* pcket,
		struct udp_metadata_parsed* meta) {

	int i;
	int ucksum;
	ucksum = 0;
	unsigned short* ptr = (unsigned short*) meta;
	unsigned short checkreturn;
	unsigned short length = meta->u_pslen;

	for (i = 0; i < 6; ++i) {										/* loops 6 times to get all data from the psuedoheader which was in the metadata */
		ucksum += *ptr++;
	}
//	printf("\nThe sum of the pseudo header: %u\n",ucksum);

	ptr = (unsigned short *) pcket;

	for (i = 0; i < U_HEADER_LEN/2; ++i) {							/*loops through the UDP header summing it up*/
//		printf("\n the value of the UDP header: %d\n", *ptr);
		ucksum += *ptr++;
	}

	if (length % 2) {
		((char *) pcket)[length] = 0;						/* pads the data if the length is an odd number*/
		length += 1;

	}
	length >>= 1; 											/*divides the length by two because we are taking 2 bytes at a time*/

	for (i = U_HEADER_LEN/2; i < length; ++i) {				/* starts the ptr on the data, following the header, and loops through it*/
//		printf("\n the value of the data is %d\n", htons(*ptr));
		ucksum += htons(*ptr++);									/* htons was used for the test, I don't believe it is needed in a real implementation */
	}
	ucksum = (ucksum >> 16) + (ucksum & 0xffff);
	ucksum += (ucksum >> 16); /* ucksum is now the complete addition but still needs to be complimented */


	 checkreturn = (unsigned short) (~ucksum & 0xffff);
	// printf("The calculated checksum is %u\n", checkreturn);		/* returns the checksum. If it is an incoming file to be processes, the checksum is 0 */
	 return checkreturn;
}

