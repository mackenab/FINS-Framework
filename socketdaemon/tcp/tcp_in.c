/*
 * @file tcp_in.c
 *
 *  @date Jun 21, 2011
 *      @author Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "tcp.h"

extern struct tcp_connection* connections; //The list of current connections we have

void *recv_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;



	//if ACK


	//if data

}

void tcp_in(struct finsFrame *ff) {
	//First things first. Check the checksum, and discard if it's bad.
	if (TCP_checksum(ff)) //check if this function works correctly
			{
		//Packet is bad if checksum != 0
		PRINT_DEBUG("Bad checksum in TCP packet. Dropping...");
		return;
	}

	uint32_t srcip;
	uint32_t dstip;
	uint32_t srcbuf;
	uint32_t dstbuf;
	uint16_t srcbuf16;
	uint16_t dstbuf16;
	struct tcp_segment *tcp_seg;
	struct tcp_connection *conn;
	int ret;

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &srcip); //host
	metadata_readFromElement(meta, "dstip", &dstip); //remote
	metadata_readFromElement(meta, "srcport", &srcbuf);
	metadata_readFromElement(meta, "dstport", &dstbuf);
	srcbuf16 = (uint16_t) srcbuf;
	dstbuf16 = (uint16_t) dstbuf;

	//demultiplex by connection
	tcp_seg = fins_to_tcp(ff);
	if (tcp_seg) {
		conn = find_tcp_connection(dstip, srcip, tcp_seg->dst_port,
				tcp_seg->src_port); //TODO check if right, is reversed
		if (conn) {
			//spin off another thread

			/*
			 while ((ret = sem_wait(&conn->recv_queue->sem)) == -1
			 && errno == EINTR)
			 ;
			 if (ret == -1 && errno != EINTR) {
			 PRINT_ERROR("sem_wait prob");
			 exit(-1);
			 }

			 if (has_space(conn->recv_queue, tcp_seg->datalen)) {
			 if (insert_FF(conn->recv_queue, ff, tcp_seg->seq_num,
			 tcp_seg->datalen)) {
			 PRINT_DEBUG("Duplicate or overlapping. Dropping...");
			 } else {
			 //fine
			 }

			 } else {
			 PRINT_DEBUG("Recv queue overflow. Dropping...");
			 }

			 sem_post(&conn->recv_queue->sem);
			 */
		} else {
			PRINT_DEBUG("Found no connection. Dropping...");
		}
	} else {
		PRINT_DEBUG("Bad tcp seg. Dropping...");
	}

	/*//See if this has the next expected sequence number.
	 if(tcp->seq_num == next_expected_seq)	//If so, forward to application as-is.
	 {
	 //next_expected_seq += tcp->datalen;	//Increment our next expected sequence number to be the next part of the data that we want


	 }
	 else									//If not, stick in queue for later. We could drop it, but that's lame
	 {

	 }*/

	//recv_queue
	//read_queue
}
