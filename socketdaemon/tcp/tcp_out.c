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
			sem_post(&conn->write_queue->sem);

			if (conn->main_wait_flag) {
				PRINT_DEBUG("posting to wait_sem\n");
				sem_post(&conn->main_wait_sem);
			}
		} else {
			sem_post(&conn->write_queue->sem);

			if (sem_wait(&conn->write_wait_sem)) {
				PRINT_ERROR("conn->send_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn->write_wait_sem, 0, 0);
			PRINT_DEBUG("left conn->send_wait_sem\n");
		}
	}

	sem_post(&conn->write_sem);

	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	conn->write_threads--;
	sem_post(&conn->sem);

	free(called_data);
	free(thread_data);
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
	struct tcp_thread_data *thread_data;
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
	sem_post(&conn_list_sem);

	if (conn) {
		if (conn->running_flag) {
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->conn_sem wait prob");
				exit(-1);
			}
			if (conn->write_threads < MAX_WRITE_THREADS) {
				thread_data = (struct tcp_thread_data *) malloc(
						sizeof(struct tcp_thread_data));
				thread_data->conn = conn;
				thread_data->data_raw = ff->dataFrame.pdu;
				thread_data->data_len = ff->dataFrame.pduLength;

				//spin off thread to handle
				if (pthread_create(&thread, NULL, write_thread,
						(void *) thread_data)) {
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
	} else {
		//TODO error
	}

	freeFinsFrame(ff);
}
void *connect_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;

	struct tcp_segment *seg;

	if (sem_wait(&conn->send_queue->sem)) {
		PRINT_ERROR("conn_stub->syn_queue->sem wait prob");
		exit(-1);
	}
	if (conn->state == CLOSED) {
		conn->state = SYN_SENT;
		conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
		conn->host_seq_end = conn->host_seq_num;

		//send SYN
		seg = tcp_create(conn);
		tcp_update(seg, conn, FLAG_SYN);
		tcp_send_seg(seg);
		tcp_free(seg);

		startTimer(conn->to_gbn_fd, conn->timeout);
	} else {
		PRINT_ERROR("connect call on non CLOSED conn");
	}
	sem_post(&conn->send_queue->sem); //TODO move sem?

	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	conn->connect_threads--;
	sem_post(&conn->sem);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_connect(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
		uint16_t dst_port) {
	struct tcp_connection *conn;
	pthread_t thread;
	struct tcp_thread_data *thread_data;
	int ret;

	//TODO remove conn_stub w/ (src_ip, src_port)

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port);
	if (conn == NULL) {
		if (conn_has_space(1)) {
			conn = conn_create(src_ip, src_port, dst_ip, dst_port);
			if (conn_insert(conn)) {
				sem_post(&conn_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_insert fail");
				conn_free(conn);
			} else {
				sem_post(&conn_list_sem);

				if (conn->running_flag) {
					if (sem_wait(&conn->sem)) {
						PRINT_ERROR("conn->sem wait prob");
						exit(-1);
					}
					if (conn->connect_threads < MAX_CONNECT_THREADS) {
						thread_data = (struct tcp_thread_data *) malloc(
								sizeof(struct tcp_thread_data));
						thread_data->conn = conn;

						if (pthread_create(&thread, NULL, connect_thread,
								(void *) thread_data)) {
							PRINT_ERROR(
									"ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
						conn->connect_threads++;
					} else {
						PRINT_DEBUG("Too many connect_threads=%d. Dropping...",
								conn->connect_threads);
					}
					sem_post(&conn->sem);
				}
			}
		} else {
			//TODO throw minor error
		}
	} else {
		//TODO error
	}
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
				PRINT_ERROR("conn_stub_insert fail");
				conn_stub_free(conn_stub);
			}
		} else {
			//TODO throw minor error
		}
	} else {
		//TODO error
	}
	sem_post(&conn_stub_list_sem);
}

void *accept_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t flags = thread_data->flags;

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	struct tcp_segment *temp_seg;

	while (conn_stub->running_flag) {
		if (sem_wait(&conn_stub->syn_queue->sem)) {
			PRINT_ERROR("conn_stub->syn_queue->sem wait prob");
			exit(-1);
		}
		if (!queue_is_empty(conn_stub->syn_queue)) {
			node = queue_remove_front(conn_stub->syn_queue);
			sem_post(&conn_stub->syn_queue->sem);

			seg = (struct tcp_segment *) node->data;

			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_find(seg->dst_ip, seg->dst_port,
					seg->src_ip, seg->src_port);
			if (conn == NULL) {
				if (conn_has_space(1)) {
					conn = conn_create(seg->dst_ip, seg->dst_port,
							seg->src_ip, seg->src_port);
					if (conn_insert(conn)) {
						//error - shouldn't happen
						sem_post(&conn_list_sem);

						PRINT_ERROR("conn_insert fail");
						conn_free(conn);
					} else {
						sem_post(&conn_list_sem);

						if (sem_wait(&conn->send_queue->sem)) {
							PRINT_ERROR("conn->recv_queue->sem wait prob");
							exit(-1);
						}
						//if SYN, send SYN ACK, SYN_RECV
						conn->state = SYN_RECV;
						conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
						conn->host_seq_end = conn->host_seq_num;
						conn->rem_seq_num = seg->seq_num;
						conn->rem_window = seg->win_size;

						//TODO process options, decide: MSS, max window size!!
						//conn_change_options(conn, tcp->options, SYN);

						//send SYN ACK
						temp_seg = tcp_create(conn);
						tcp_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
						tcp_send_seg(temp_seg);
						tcp_free(temp_seg);

						sem_post(&conn->send_queue->sem);

						tcp_free(seg);
					}
				} else {
					sem_post(&conn_list_sem);
					//TODO throw minor error
				}
			} else {
				sem_post(&conn_list_sem);
				//TODO error
			}
		} else {
			sem_post(&conn_stub->syn_queue->sem);

			if (sem_wait(&conn_stub->accept_wait_sem)) {
				PRINT_ERROR("conn_stub->accept_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem\n");
		}
	}

	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	conn_stub->accept_threads--;
	sem_post(&conn_stub->sem);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_accept(uint32_t src_ip, uint16_t src_port, uint32_t flags) {
	//create socket //TODO multithread this portion?
	struct tcp_connection_stub *conn_stub;
	pthread_t thread;
	struct tcp_thread_data *thread_data;
	int ret;

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(src_ip, src_port); //TODO check if right
	sem_post(&conn_stub_list_sem);

	if (conn_stub) {
		if (conn_stub->running_flag) {
			if (sem_wait(&conn_stub->sem)) {
				PRINT_ERROR("conn_stub->sem wait prob");
				exit(-1);
			}
			if (conn_stub->accept_threads < MAX_ACCEPT_THREADS) {
				thread_data = (struct tcp_thread_data *) malloc(
						sizeof(struct tcp_thread_data));
				thread_data->conn_stub = conn_stub;
				thread_data->flags = flags;

				//spin off thread to handle
				if (pthread_create(&thread, NULL, accept_thread,
						(void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create write_thread thread.");
					exit(-1);
				}
				conn_stub->accept_threads++;
			} else {
				PRINT_DEBUG("Too many write threads=%d. Dropping...",
						conn_stub->accept_threads);
			}
			sem_post(&conn_stub->sem);
		}
	} else {
		//TODO error
	}
}

void tcp_exec(struct finsFrame *ff) {
	uint8_t *pt;

	switch (ff->ctrlFrame.paramterID) {
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
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_connect(src_ip, src_port, dst_ip, dst_port);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
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
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_listen(src_ip, src_port, backlog);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_ACCEPT:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t flags = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_accept(src_ip, src_port, flags);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_CLOSE:
		break;
	case EXEC_CLOSE_STUB:
		break;
	case EXEC_OPT:
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
