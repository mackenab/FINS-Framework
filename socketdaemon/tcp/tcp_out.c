/*
 * @file tcp_out.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "tcp.h"

void *write_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;
	uint8_t *called_data = thread_data->data_raw;
	uint32_t called_len = thread_data->data_len;

	//detect which call it is: connect, listen/accept, read, write, close? atm this will always be FDF
	//for now treat as write call with the data to write

	//check connection status, if has handshaked

	uint8_t *ptr = called_data;
	int index = 0;
	int len;
	int space;
	uint8_t *buf;
	struct tcp_node *node;

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

			node = node_create(buf, len, 0, 0);
			queue_append(conn->write_queue, node);

			if (conn->main_wait_flag) {
				PRINT_DEBUG("posting to wait_sem\n");
				sem_post(&conn->main_wait_sem);
			}
		} else {
			PRINT_DEBUG("waiting on send_wait_sem len=%d\n",
					conn->write_queue->len);
			if (sem_wait(&conn->write_wait_sem)) {
				PRINT_ERROR("conn->send_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn->write_wait_sem, 0, 0);
			PRINT_DEBUG("left conn->send_wait_sem\n");
		}

		sem_post(&conn->write_queue->sem);
	}

	sem_post(&conn->write_sem);

	free(called_data);
	pthread_exit(NULL);
}

void tcp_out_fdf(struct finsFrame *ff) {
	//receiving straight data from the APP layer, process/package into segment
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_port_buf;
	uint32_t dst_port_buf;
	uint16_t src_port;
	uint16_t dst_port;
	struct tcp_connection *conn;
	pthread_t thread;
	struct tcp_thread_data *data;
	int ret;

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &src_ip); //host
	metadata_readFromElement(meta, "dstip", &dst_ip); //remote
	metadata_readFromElement(meta, "srcport", &src_port_buf);
	metadata_readFromElement(meta, "dstport", &dst_port_buf);
	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */
	src_port = (uint16_t) src_port_buf;
	dst_port = (uint16_t) dst_port_buf;

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, dst_ip, src_port, dst_port); //TODO check if right
	if (conn == NULL) {
		//error
		sem_post(&conn_list_sem);
		return;
	}
	sem_post(&conn_list_sem);

	if (conn->running_flag) {
		if (sem_wait(&conn->sem)) {
			PRINT_ERROR("conn->conn_sem wait prob");
			exit(-1);
		}
		if (conn->write_threads < MAX_WRITE_THREADS) {
			data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			data->conn = conn;
			data->data_raw = ff->dataFrame.pdu;
			data->data_len = ff->dataFrame.pduLength;

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
		sem_post(&conn->sem);
	}

	freeFinsFrame(ff);
}

void tcp_exec_listen(uint32_t src_ip, uint16_t src_port, uint32_t backlog) {
	//create socket //TODO multithread this portion?
	struct tcp_connection_stub *conn_stub;

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(src_ip, src_port);
	if (conn_stub == NULL) {
		if (conn_stub_has_space(1)) {
			conn_stub = conn_stub_create(src_ip, src_port, backlog);
			if (conn_stub_insert(conn_stub)) {
				//error - shouldn't happen
				conn_stub_free(conn_stub);
			}
		} else {
			//throw minor error
		}
	} else {
		//error
	}
	sem_post(&conn_stub_list_sem);
}

void tcp_exec_connect(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
		uint16_t dst_port) {
	struct tcp_connection *conn;

	//create socket //TODO multithread this portion?
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port);
	if (conn == NULL) {
		if (conn_has_space(1)) {
			conn = conn_create(src_ip, src_port, dst_ip, dst_port);
			if (conn_insert(conn)) {
				//error - shouldn't happen
				conn_free(conn);
			}
		} else {
			//throw minor error
		}
	} else {
		//error
	}
	sem_post(&conn_list_sem);
}

void tcp_exec(struct finsFrame *ff) {
	uint8_t *pt;

	switch (ff->ctrlFrame.paramterID) {
	case EXEC_LISTEN:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t backlog = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt
						- (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//error
				break;
			}

			tcp_exec_listen(src_ip, src_port, backlog);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//error
		}
		break;
	case EXEC_CONNECT:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			uint32_t dst_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t dst_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt
						- (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//error
				break;
			}

			tcp_exec_connect(src_ip, src_port, dst_ip, dst_port);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//error
		}
		break;
	case EXEC_ACCEPT:
		break;
	case EXEC_CLOSE:
		break;
	default:
		break;
	}

	freeFinsFrame(ff);
}

void tcp_out_fcf(struct finsFrame *ff) {

	//TODO fill out

	switch ((ff->ctrlFrame).opcode) {
	case CTRL_ALERT:
		break;
	case CTRL_READ_PARAM:
		break;
	case CTRL_READ_PARAM_REPLY:
		break;
	case CTRL_SET_PARAM:
		break;
	case CTRL_EXEC:
		tcp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		break;
	case CTRL_ERROR:
		break;
	default:
		break;
	}
}
