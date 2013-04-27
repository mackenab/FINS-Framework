/*------------------------------------------------------------------------
 *  cksum  -  Return 16-bit ones complement of 16-bit ones complement sum
 *------------------------------------------------------------------------
 */

#include "ipv4_internal.h"

uint16_t IP4_checksum(struct ip4_packet* ptr, int length) {

	int sum = 0;
	u_short ret = 0;
	uint16_t *w = (uint16_t*) ptr;
	int nleft = length;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ret = ~sum;
	return (ret);
}
