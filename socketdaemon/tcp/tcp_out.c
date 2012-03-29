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

uint8_t thread_count = 0;

void *write_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = data->conn;
	struct tcp_segment *tcp_seg = data->tcp_seg;

	//detect which call it is: connect, listen/accept, read, write, close? atm this will always be FDF
	//for now treat as write call with the data to write

	//check connection status, if has handshaked

	//-------test data
	int called_len = 10;
	uint8_t *called_data = (uint8_t *) malloc(called_len * sizeof(uint8_t));
	//-------

	uint8_t *ptr = called_data;
	int index = 0;
	int len;
	int space;
	uint8_t *buf;

	if (sem_wait(&conn->write_sem)) {
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}

	while (index < called_len) {
		if (sem_wait(&conn->write_queue->sem)) {
			PRINT_ERROR("conn->write_queue->sem wait prob");
			exit(-1);
		}

		space = conn->write_queue->max - conn->write_queue->len;
		if (space > 0) {
			len = called_len - index;
			if (len > space) {
				len = space;
			}

			buf = (uint8_t *) malloc(len * sizeof(uint8_t));
			memcpy(buf, ptr, len);
			ptr += len;
			index += len;

			queue_append(conn->write_queue, buf, len, 0, 0);

			if (conn->main_wait_flag) {
				PRINT_DEBUG("posting to wait_sem\n");
				sem_post(&conn->main_wait_sem);
			}
		}

		sem_post(&conn->write_queue->sem);
	}

	sem_post(&conn->write_sem);
}

void tcp_out(struct finsFrame *ff) {
	//receiving straight data from the APP layer, process/package into segment
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
		conn = conn_find(srcip, dstip, tcp_seg->src_port, tcp_seg->dst_port); //TODO check if right
		if (conn == NULL) {
			//create a new connection
			if (conn_has_space(1)) {
				conn = conn_create(srcip, tcp_seg->src_port, dstip,
						tcp_seg->dst_port);
				conn_append(conn);
			} else {
				sem_post(&conn_list_sem);
				return;
			}
		}
		sem_post(&conn_list_sem);

		if (sem_wait(&conn->conn_sem)) {
			PRINT_ERROR("conn->conn_sem wait prob");
			exit(-1);
		}
		if (conn->write_threads < MAX_WRITE_THREADS) {
			data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			data->conn = conn;
			data->tcp_seg = tcp_seg;

			//spin off thread to handle
			if (pthread_create(&thread, NULL, write_thread, (void *) data)) {
				PRINT_ERROR("ERROR: unable to create write_thread thread.");
				exit(-1);
			}
			conn->write_threads++;
		} else {
			PRINT_DEBUG("Too many write threads=%d. Dropping...",
					conn->write_threads);
		}
		sem_post(&conn->conn_sem);
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}
}
