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

	uint16_t calc;
	struct tcp_node *node;
	struct tcp_node *temp;

	calc = tcp_checksum(conn->rem_addr, conn->host_addr, tcp_seg);

	if (tcp_seg->checksum != calc) {
		PRINT_ERROR("Checksum: recv=%u calc=%u\n", tcp_seg->checksum, calc);
	} else {
		if (tcp_seg->flags & FLAG_ACK) {
			//check if valid ACK
			if (conn->host_seq_num <= tcp_seg->ack_num
					&& tcp_seg->ack_num <= conn->host_seq_end) {
				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->send_queue wait prob");
					exit(-1);
				}

				if (tcp_seg->ack_num == conn->host_seq_num) {
					//check for FR
					if (conn->gbn_flag) {
						conn->first_flag = 1;
					}

					//Cong

					//dup++
				} else if (tcp_seg->ack_num == conn->host_seq_end) {
					//remove all
					while (!queue_is_empty(conn->send_queue)) {
						temp = queue_remove_front(conn->send_queue);
						free(temp->data);
						free(temp);
					}

					conn->host_seq_num = tcp_seg->ack_num;
					if (conn->gbn_flag) {
						conn->first_flag = 1;
					}

					//RTT

					//Cong

					//dup = 0
				} else {
					node = conn->send_queue->front;
					while (node != NULL) {
						if (tcp_seg->ack_num == node->seq_num) {
							break;
						}
						node = node->next;
					}
					if (node != NULL) {
						while (!queue_is_empty(conn->send_queue)
								&& conn->send_queue->front != node) {
							temp = queue_remove_front(conn->send_queue);

							free(temp->data);
							free(temp);
						}

						//valid ACK
						conn->host_seq_num = tcp_seg->ack_num;
						if (conn->gbn_flag) {
							conn->first_flag = 1;
						}

						//RTT

						//Cong

						//dup = 0
					} else {
						PRINT_DEBUG("Invalid ACK: was not sent.");
					}
				}
				sem_post(&conn->send_queue->sem);
			} else {
				PRINT_DEBUG("Invalid ACK: out of sent window.");
			}
		}
	}
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
			if (conn->running_flag) {
				if (sem_wait(&conn->conn_sem)) {
					PRINT_ERROR("conn->conn_sem wait prob");
					exit(-1);
				}
				if (conn->recv_threads < MAX_RECV_THREADS) {
					data = (struct tcp_thread_data *) malloc(
							sizeof(struct tcp_thread_data));
					data->conn = conn;
					data->tcp_seg = tcp_seg;

					if (pthread_create(&thread, NULL, recv_thread,
							(void *) conn)) {
						PRINT_ERROR(
								"ERROR: unable to create recv_thread thread.");
						exit(-1);
					}
					conn->recv_threads++;
				} else {
					PRINT_DEBUG("Too many recv threads=%d. Dropping...",
							conn->recv_threads);
				}
				sem_post(&conn->conn_sem);
			}
		} else {
			PRINT_DEBUG("Found no connection. Dropping...");
		}
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}
}
