/*
 * IP4_forward.c
 *
 *  Created on: Jul 20, 2010
 *      Author: rado
 */
#include "ipv4_internal.h"

int ipv4_forward(struct fins_module *module, struct finsFrame *ff, struct ip4_packet* ppacket, uint32_t dest, uint16_t length) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct ipv4_data *md = (struct ipv4_data *) module->data;

	return 0; //to disable

	struct ip4_next_hop_info next_hop = IP4_next_hop(module, dest); //TODO fix this, returning stacked memory is dangerous
	if (next_hop.interface >= 0) {
		//IP4_send_fdf_out(ff, ppacket, next_hop, length); //TODO uncommenct/fix
		return 1;
	}
	md->stats.cantforward++;
	return 0;
}
