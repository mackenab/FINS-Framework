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

extern struct tcp_connection* conn_list; //The list of current connections we have

void *recv_thread(void *local) {
	struct tcp_thread_data *data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = data->conn;
	struct tcp_segment *tcp_seg = data->tcp_seg;

	//PRINT_DEBUG("thread for conn=%d", conn);

	/*
	 //First things first. Check the checksum, and discard if it's bad.
	 if (TCP_checksum(ff)) //check if this function works correctly
	 {
	 //Packet is bad if checksum != 0
	 PRINT_DEBUG("Bad checksum in TCP packet. Dropping...");
	 return;
	 }
	 */

	//if ACK
	//if data
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

}

void tcp_in(struct finsFrame *ff) {
	uint32_t srcip;
	uint32_t dstip;
	struct tcp_segment *tcp_seg;
	struct tcp_connection *conn;
	pthread_t thread;
	struct tcp_thread_data *data;
	int ret;

	//this handles if it's a FDF atm

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &srcip); //host
	metadata_readFromElement(meta, "dstip", &dstip); //remote

	tcp_seg = fins_to_tcp(ff);
	if (tcp_seg) {
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		conn = conn_find(dstip, srcip, tcp_seg->dst_port, tcp_seg->src_port); //TODO check if right, is reversed
		sem_post(&conn_list_sem);

		if (conn) {
			if (sem_wait(&conn->conn_sem)) {
				PRINT_ERROR("conn->conn_sem wait prob");
				exit(-1);
			}
			if (conn->recv_threads < MAX_RECV_THREADS) {
				data = (struct tcp_thread_data *) malloc(
						sizeof(struct tcp_thread_data));
				data->conn = conn;
				data->tcp_seg = tcp_seg;

				if (pthread_create(&thread, NULL, recv_thread, (void *) conn)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
				conn->recv_threads++;
			} else {
				PRINT_DEBUG("Too many recv threads=%d. Dropping...",
						conn->recv_threads);
			}
			sem_post(&conn->conn_sem);
		} else {
			PRINT_DEBUG("Found no connection. Dropping...");
		}
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}
}
