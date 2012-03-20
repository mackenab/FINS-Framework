/*
 * @file tcp_out.c
 *
 *  @date Jun 21, 2011
 *      @author Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "tcp.h"

void tcp_out(struct finsFrame *ff) {
	//receiving straight data from the APP layer, process/package into segment
	uint32_t srcip;
	uint32_t dstip;
	uint32_t srcbuf;
	uint32_t dstbuf;
	uint16_t srcbuf16;
	uint16_t dstbuf16;
	struct tcp_segment *tcp_seg;

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &srcip); //host
	metadata_readFromElement(meta, "dstip", &dstip); //remote
	metadata_readFromElement(meta, "srcport", &srcbuf);
	metadata_readFromElement(meta, "dstport", &dstbuf);
	srcbuf16 = (uint16_t) srcbuf;
	dstbuf16 = (uint16_t) dstbuf;

	//demultiplex by connection
	tcp_seg = fins_to_tcp(ff);

	struct tcp_connection *connection = find_tcp_connection(srcip, dstip,
			tcp_seg->src_port, tcp_seg->dst_port); //TODO check if right

	if (connection == NULL) {
		//create a new connection
		connection = create_tcp_connection(srcip, srcbuf16, dstip, dstbuf16); //TODO check if this is right
		//initialize it

		//setup threads - may push to later
	}

	//detect which call it is: connect, listen/accept, read, write, close?

	//write_queue;
	//send_queue;
}
