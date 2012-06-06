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

extern int tcp_thread_count;

void *write_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	uint8_t *called_data = thread_data->data_raw;
	uint32_t called_len = thread_data->data_len;

	uint8_t *pt = called_data;
	int index = 0;
	int len;
	int space;
	uint8_t *buf;
	struct tcp_node *node;

	PRINT_DEBUG("write_thread: Entered: id=%d", id);
	if (sem_wait(&conn->write_sem)) { //func depends on write_sem, write op can't be interrupted
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		PRINT_DEBUG("");
		if (sem_wait(&conn->sem)) {
			PRINT_ERROR("conn->write_sem wait prob");
			exit(-1);
		}PRINT_DEBUG("write_thread: state=%d", conn->state);
		if (conn->state == ESTABLISHED || conn->state == CLOSE_WAIT) {
			while (conn->running_flag && index < called_len) {
				space = conn->write_queue->max - conn->write_queue->len;
				if (space > 0) {
					len = called_len - index;
					if (len > space) {
						len = space;
					}

					buf = (uint8_t *) malloc(len * sizeof(uint8_t));
					memcpy(buf, pt, len);
					pt += len;
					index += len;

					node = node_create(buf, len, 0, 0);
					queue_append(conn->write_queue, node);

					if (conn->main_wait_flag) {
						PRINT_DEBUG("posting to wait_sem\n");
						sem_post(&conn->main_wait_sem);
					}PRINT_DEBUG("");
					sem_post(&conn->sem);
				} else {
					PRINT_DEBUG("");
					sem_post(&conn->sem);

					PRINT_DEBUG("");
					if (sem_wait(&conn->write_wait_sem)) {
						PRINT_ERROR("conn->send_wait_sem prod");
						exit(-1);
					}
					sem_init(&conn->write_wait_sem, 0, 0);
					PRINT_DEBUG("left conn->send_wait_sem\n");
				}PRINT_DEBUG("");
				if (sem_wait(&conn->sem)) {
					PRINT_ERROR("conn->sem prod");
					exit(-1);
				}
			}
		} else {
			//TODO error, send/write'ing when conn sending is closed
			PRINT_DEBUG("");
		}

		//send ACK to send handler
		conn_send_jinni(conn, EXEC_TCP_SEND, 1);
	} else {
		//send NACK to send handler
		conn_send_jinni(conn, EXEC_TCP_SEND, 0);
	}

	PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("write_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
	sem_post(&conn_list_sem);

	PRINT_DEBUG("write_thread: Exited: id=%d", id);
	free(buf);
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
	int start;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	PRINT_DEBUG("tcp_out_fdf: Entered");

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "src_ip", &src_ip); //host
	metadata_readFromElement(meta, "dst_ip", &dst_ip); //remote
	metadata_readFromElement(meta, "src_port", &src_port_buf);
	metadata_readFromElement(meta, "dst_port", &dst_port_buf);
	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */
	src_port = (uint16_t) src_port_buf;
	dst_port = (uint16_t) dst_port_buf;

	PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port); //TODO check if right
	start = (conn->threads < MAX_THREADS) ? ++conn->threads : 0;
	PRINT_DEBUG("");
	sem_post(&conn_list_sem);

	if (conn) {
		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_thread_count++;
			thread_data->conn = conn;
			thread_data->data_raw = ff->dataFrame.pdu;
			thread_data->data_len = ff->dataFrame.pduLength;

			//spin off thread to handle
			if (pthread_create(&thread, NULL, write_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create write_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		//TODO error

		//TODO LISTEN: if SEND, SYN, SYN_SENT
		PRINT_DEBUG("error");
	}

	freeFinsFrame(ff);
}

void *close_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t send_ack = thread_data->flags;

	struct tcp_segment *temp_seg;
	struct tcp_node *temp_node;

	PRINT_DEBUG("close_stub_thread: Entered: id=%d", id);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}

	if (conn_stub->running_flag) {
		conn_stub_shutdown(conn_stub);

		//send ACK to close handler
		conn_stub_send_jinni(conn_stub, EXEC_TCP_CLOSE_STUB, 1);

		conn_stub_free(conn_stub);
	} else {
		//send NACK to close handler
		conn_stub_send_jinni(conn_stub, EXEC_TCP_CLOSE_STUB, 0);
	}

	PRINT_DEBUG("close_stub_thread: Exited: id=%d", id);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_close_stub(uint32_t host_ip, uint16_t host_port) {
	struct tcp_connection_stub *conn_stub;
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	PRINT_DEBUG("tcp_exec_close_stub: Entered: host=%u/%d", host_ip, host_port);
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub) {
		conn_stub_remove(conn_stub);
		start = (conn_stub->threads < MAX_THREADS) ? ++conn_stub->threads : 0;
		PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_thread_count++;
			thread_data->conn_stub = conn_stub;
			thread_data->flags = 1;

			if (pthread_create(&thread, NULL, close_stub_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
		}
	} else {
		PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);
		//TODO error
	}
}

void *connect_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;

	struct tcp_segment *temp_seg;

	PRINT_DEBUG("connect_thread: Entered: id=%d", id);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		//if CONNECT, send SYN, SYN_SENT
		PRINT_DEBUG("connect_thread: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
		conn->state = SYN_SENT;
		conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
		conn->host_seq_end = conn->host_seq_num;

		//TODO add options, for: MSS, max window size!!
		//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

		//conn_change_options(conn, tcp->options, SYN);

		//send SYN
		temp_seg = seg_create(conn);
		seg_update(temp_seg, conn, FLAG_SYN);
		seg_send(temp_seg);
		seg_free(temp_seg);

		conn->timeout = DEFAULT_GBN_TIMEOUT;
		//startTimer(conn->to_gbn_fd, conn->timeout);
	} else {
		//send NACK to connect handler
		conn_send_jinni(conn, EXEC_TCP_CONNECT, 0);
	}

	PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("connect_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
	sem_post(&conn_list_sem);

	PRINT_DEBUG("");
	sem_post(&conn->sem);

	PRINT_DEBUG("connect_thread: Exited: id=%d", id);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_connect(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	struct tcp_connection *conn;
	int start;
	struct tcp_connection_stub *conn_stub;
	struct tcp_thread_data *stub_thread_data;
	pthread_t stub_thread;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	PRINT_DEBUG("tcp_exec_connect: Entered: host=%u/%d, rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(host_ip, host_port, rem_ip, rem_port);
	if (conn == NULL) {
		if (conn_has_space(1)) {
			conn = conn_create(host_ip, host_port, rem_ip, rem_port);
			if (conn_insert(conn)) {
				conn->threads++;
				PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//if listening stub remove
				PRINT_DEBUG("");
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_find(host_ip, host_port);
				if (conn_stub) {
					conn_stub_remove(conn_stub);
					start = (conn_stub->threads < MAX_THREADS) ? ++conn_stub->threads : 0;
					PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					if (start) {
						stub_thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_thread_count++;
						stub_thread_data->conn_stub = conn_stub;
						stub_thread_data->flags = 0;

						if (pthread_create(&stub_thread, NULL, close_stub_thread, (void *) stub_thread_data)) {
							PRINT_ERROR("ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
					}
				} else {
					PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);
				}

				thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->id = tcp_thread_count++;
				thread_data->conn = conn;

				if (pthread_create(&thread, NULL, connect_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_insert fail");
				conn_shutdown(conn);
				conn_free(conn);
			}
		} else {
			PRINT_DEBUG("");
			sem_post(&conn_list_sem);

			//TODO throw minor error, list full
		}
	} else {
		PRINT_DEBUG("");
		sem_post(&conn_list_sem);

		//TODO error, existing connection already connected there
	}
}

void tcp_exec_listen(uint32_t host_ip, uint16_t host_port, uint32_t backlog) {
	struct tcp_connection_stub *conn_stub;

	PRINT_DEBUG("tcp_exec_listen: Entered: addr=%u/%d, backlog=%d", host_ip, host_port, backlog);
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub == NULL) {
		if (conn_stub_has_space(1)) {
			conn_stub = conn_stub_create(host_ip, host_port, backlog);
			if (conn_stub_insert(conn_stub)) {
				PRINT_DEBUG("");
				sem_post(&conn_stub_list_sem);
			} else {
				PRINT_DEBUG("");
				sem_post(&conn_stub_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_stub_insert fail");
				conn_stub_free(conn_stub);
			}
		} else {
			PRINT_DEBUG("");
			sem_post(&conn_stub_list_sem);
			//TODO throw minor error
		}
	} else {
		PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);
		//TODO error
	}

	//TODO send ACK to listen handler - don't? have nonblocking
}

void *accept_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t flags = thread_data->flags;

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	int start;
	struct tcp_segment *temp_seg;

	PRINT_DEBUG("accept_thread: Entered: id=%d", id);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	while (conn_stub->running_flag) {
		if (!queue_is_empty(conn_stub->syn_queue)) {
			node = queue_remove_front(conn_stub->syn_queue);
			PRINT_DEBUG("");
			sem_post(&conn_stub->sem);

			seg = (struct tcp_segment *) node->data;

			PRINT_DEBUG("");
			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_find(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
			if (conn == NULL) {
				if (conn_has_space(1)) {
					conn = conn_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
					if (conn_insert(conn)) {
						conn->threads++;
						PRINT_DEBUG("");
						sem_post(&conn_list_sem);

						PRINT_DEBUG("");
						if (sem_wait(&conn->sem)) {
							PRINT_ERROR("conn->sem wait prob");
							exit(-1);
						}
						if (conn->running_flag) {
							//if SYN, send SYN ACK, SYN_RECV
							PRINT_DEBUG("accept_thread: SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
							conn->state = SYN_RECV;
							conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
							conn->host_seq_end = conn->host_seq_num;
							conn->rem_seq_num = seg->seq_num;
							conn->rem_window = seg->win_size;

							//TODO process options, decide: MSS, max window size!!
							//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

							//conn_change_options(conn, tcp->options, SYN);

							//send SYN ACK
							temp_seg = seg_create(conn);
							seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
							seg_send(temp_seg);
							seg_free(temp_seg);
						}

						PRINT_DEBUG("");
						if (sem_wait(&conn_list_sem)) {
							PRINT_ERROR("conn_list_sem wait prob");
							exit(-1);
						}
						conn->threads--;
						PRINT_DEBUG("accept_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
						sem_post(&conn_list_sem);

						PRINT_DEBUG("");
						sem_post(&conn->sem);

						seg_free(seg);
						break;
					} else {
						PRINT_DEBUG("");
						sem_post(&conn_list_sem);

						//error - shouldn't happen
						PRINT_ERROR("conn_insert fail");
						conn_shutdown(conn);
						conn_free(conn);
					}
				} else {
					PRINT_DEBUG("");
					sem_post(&conn_list_sem);
					//TODO throw minor error
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&conn_list_sem);
				//TODO error
			}

			seg_free(seg);
		} else {
			PRINT_DEBUG("");
			sem_post(&conn_stub->sem);

			PRINT_DEBUG("");
			if (sem_wait(&conn_stub->accept_wait_sem)) {
				PRINT_ERROR("conn_stub->accept_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem\n");
		}

		PRINT_DEBUG("");
		if (sem_wait(&conn_stub->sem)) {
			PRINT_ERROR("conn_stub->sem prod");
			exit(-1);
		}
	}

	if (!conn_stub->running_flag) {
		conn_stub_send_jinni(conn_stub, EXEC_TCP_ACCEPT, 0);
	}

	PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("accept_thread: leaving thread: conn_stub=%d, threads=%d", (int)conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	PRINT_DEBUG("");
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("accept_thread: Exited: id=%d", id);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_accept(uint32_t host_ip, uint16_t host_port, uint32_t flags) {
	struct tcp_connection_stub *conn_stub;
	int start;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	struct tcp_segment *temp_seg;

	PRINT_DEBUG("tcp_exec_accept: Entered: host=%u/%d, flags=%d", host_ip, host_port, flags);
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub) {
		start = (conn_stub->threads < MAX_THREADS) ? ++conn_stub->threads : 0;
		PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_thread_count++;
			thread_data->conn_stub = conn_stub;
			thread_data->flags = flags;

			if (pthread_create(&thread, NULL, accept_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);
		//TODO error
	}
}

void *close_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;

	struct tcp_segment *temp_seg;
	struct tcp_node *temp_node;
	int open = 1;

	PRINT_DEBUG("close_thread: Entered: id=%d", id);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == ESTABLISHED) {
			PRINT_DEBUG("");
			sem_post(&conn->sem);

			PRINT_DEBUG("");
			if (sem_wait(&conn->write_sem)) {
				PRINT_ERROR("conn->write_sem wait prob");
				exit(-1);
			}

			PRINT_DEBUG("");
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			if (conn->running_flag) {
				if (conn->state == ESTABLISHED) {
					PRINT_DEBUG("close_thread: CLOSE: state=%d conn=%d", conn->state, (int)conn);
					conn->state = FIN_WAIT_1;

					//if CLOSE, send FIN, FIN_WAIT_1
					if (queue_is_empty(conn->write_queue) && conn->host_seq_num == conn->host_seq_end) {
						//send FIN
						PRINT_DEBUG("close_thread: CLOSE, send FIN, FIN_WAIT: state=%d", conn->state);
						temp_seg = seg_create(conn);
						seg_update(temp_seg, conn, FLAG_FIN);

						temp_node = node_create((uint8_t *) temp_seg, 1, temp_seg->seq_num, temp_seg->seq_num);
						queue_append(conn->send_queue, temp_node);

						seg_send(temp_seg);
					} //else piggy back it
				} else {
					//TODO figure out:
					PRINT_DEBUG("");
				}
			} else {
				//TODO figure out: conn shutting down already?
				PRINT_DEBUG("");
			}
		} else {
			//TODO figure out close call on non-establisehd conn
			PRINT_DEBUG("");

			conn_shutdown(conn);

			//send ACK to close handler
			conn_send_jinni(conn, EXEC_TCP_CLOSE, 1);

			conn_free(conn);
			open = 0;
		}
	}

	if (open) {
		PRINT_DEBUG("");
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		conn->threads--;
		PRINT_DEBUG("close_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
		sem_post(&conn_list_sem);

		PRINT_DEBUG("");
		sem_post(&conn->sem);
	}

	PRINT_DEBUG("close_thread: Exited: id=%d", id);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_close(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	struct tcp_connection *conn;
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	PRINT_DEBUG("tcp_exec_close: Entered: host=%u/%d, rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(host_ip, host_port, rem_ip, rem_port);
	if (conn) {
		start = (conn->threads < MAX_THREADS) ? ++conn->threads : 0;
		PRINT_DEBUG("");
		sem_post(&conn_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_thread_count++;
			thread_data->conn = conn;

			if (pthread_create(&thread, NULL, close_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		PRINT_DEBUG("");
		sem_post(&conn_list_sem);
		//TODO error trying to close closed connection
	}
}
