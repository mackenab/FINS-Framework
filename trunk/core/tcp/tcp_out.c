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

	/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		PRINT_DEBUG("write_thread: state=%d", conn->state);
		if (conn->state == CS_SYN_SENT || conn->state == CS_SYN_RECV) { //equiv to non blocking
			PRINT_DEBUG("write_thread: non-blocking");
			if (conn->running_flag) {
				space = conn->write_queue->max - conn->write_queue->len;
				if (space >= called_len) {
					node = node_create(called_data, called_len, 0, 0);
					queue_append(conn->write_queue, node);

					if (conn->main_wait_flag) {
						PRINT_DEBUG("posting to wait_sem\n");
						sem_post(&conn->main_wait_sem);
					}
				} else {
					/*#*/PRINT_DEBUG("");
					conn_send_daemon(conn, EXEC_TCP_SEND, 0, 2); //TODO change msg values, "error: insufficient resources"
					free(called_data);
				}
			} else {
				/*#*/PRINT_DEBUG("");
				conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
				free(called_data);
			}
		} else if (conn->state == CS_ESTABLISHED || conn->state == CS_CLOSE_WAIT) { //essentially blocking
			PRINT_DEBUG("write_thread: blocking");
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
					}

					/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
					sem_post(&conn->sem);
				} else {
					/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
					sem_post(&conn->sem);

					/*#*/PRINT_DEBUG("");
					if (sem_wait(&conn->write_wait_sem)) {
						PRINT_ERROR("conn->send_wait_sem prod");
						exit(-1);
					}
					sem_init(&conn->write_wait_sem, 0, 0);
					PRINT_DEBUG("left conn->send_wait_sem\n");
				}

				/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
				if (sem_wait(&conn->sem)) {
					PRINT_ERROR("conn->sem prod");
					exit(-1);
				}
			}

			if (conn->running_flag) {
				/*#*/PRINT_DEBUG("");
				//send ACK to send handler
				if (index == called_len) {
					conn_send_daemon(conn, EXEC_TCP_SEND, 1, 0);
				} else {
					conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1); //TODO change msg values
				}
			} else {
				/*#*/PRINT_DEBUG("");
				//send NACK to send handler
				conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
			}

			free(called_data);
		} else {
			//TODO error, send/write'ing when conn sending is closed
			PRINT_DEBUG("");
			//send NACK to send handler
			conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);

			free(called_data);
		}
	} else {
		PRINT_DEBUG("");
		//send NACK to send handler
		conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
		free(called_data);
	}

	/*#*/PRINT_DEBUG("");
	sem_post(&conn->write_sem);

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("write_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("write_thread: Exited: id=%d", id);
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

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port); //TODO check if right
	start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
	/*#*/PRINT_DEBUG("");
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

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}

	if (conn_stub->running_flag) {
		conn_stub_shutdown(conn_stub);

		//send ACK to close handler
		conn_stub_send_daemon(conn_stub, EXEC_TCP_CLOSE_STUB, 1);

		conn_stub_free(conn_stub);
	} else {
		//send NACK to close handler
		conn_stub_send_daemon(conn_stub, EXEC_TCP_CLOSE_STUB, 0);
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

	PRINT_DEBUG("tcp_exec_close_stub: Entered: host=%u/%u", host_ip, host_port);
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub) {
		conn_stub_remove(conn_stub);
		start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
		/*#*/PRINT_DEBUG("");
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

	/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == CS_CLOSED || conn->state == CS_LISTEN) {
			//if CONNECT, send SYN, SYN_SENT
			if (conn->state == CS_CLOSED) {
				PRINT_DEBUG("connect_thread: CLOSED: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			} else {
				PRINT_DEBUG("connect_thread: LISTEN: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			}
			conn->state = CS_SYN_SENT;
			conn->active_open = 1;

			conn->issn = tcp_rand(); //TODO uncomment
			conn->send_seq_num = conn->issn;
			conn->send_seq_end = conn->send_seq_num;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//TODO add options, for: MSS, max window size!!
			//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

			//conn_change_options(conn, tcp->options, SYN);

			//send SYN
			temp_seg = seg_create(conn);
			seg_update(temp_seg, conn, FLAG_SYN);
			seg_send(temp_seg);
			seg_free(temp_seg);

			conn->timeout = TCP_GBN_TO_DEFAULT;
			//startTimer(conn->to_gbn_fd, conn->timeout); //TODO fix
		} else {
			//TODO error
			PRINT_DEBUG("todo error");
			conn_send_daemon(conn, EXEC_TCP_CONNECT, 0, 0);
		}
	} else {
		//send NACK to connect handler
		conn_send_daemon(conn, EXEC_TCP_CONNECT, 0, 1);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("connect_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
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

	PRINT_DEBUG("tcp_exec_connect: Entered: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
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
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//if listening stub remove
				/*#*/PRINT_DEBUG("");
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_find(host_ip, host_port);
				if (conn_stub) {
					conn_stub_remove(conn_stub);
					start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
					/*#*/PRINT_DEBUG("");
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
					/*#*/PRINT_DEBUG("");
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
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_insert fail");
				//conn->running_flag = 0;
				//sem_post(&conn->main_wait_sem);
				conn_shutdown(conn);
				//conn_free(conn);
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

	PRINT_DEBUG("tcp_exec_listen: Entered: addr=%u/%u, backlog=%u", host_ip, host_port, backlog);
	if (sem_wait(&conn_stub_list_sem)) { //TODO change from conn_stub to conn in listen
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub == NULL) {
		if (conn_stub_has_space(1)) {
			conn_stub = conn_stub_create(host_ip, host_port, backlog);
			if (conn_stub_insert(conn_stub)) {
				/*#*/PRINT_DEBUG("");
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

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	while (conn_stub->running_flag) {
		if (!queue_is_empty(conn_stub->syn_queue)) {
			node = queue_remove_front(conn_stub->syn_queue);
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			seg = (struct tcp_segment *) node->data;

			/*#*/PRINT_DEBUG("");
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
						/*#*/PRINT_DEBUG("");
						sem_post(&conn_list_sem);

						/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
						if (sem_wait(&conn->sem)) {
							PRINT_ERROR("conn->sem wait prob");
							exit(-1);
						}
						if (conn->running_flag) { //LISTENING state
							//if SYN, send SYN ACK, SYN_RECV
							PRINT_DEBUG("accept_thread: SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
							conn->state = CS_SYN_RECV;
							conn->active_open = 0;

							conn->issn = tcp_rand(); //TODO uncomment
							conn->send_seq_num = conn->issn;
							conn->send_seq_end = conn->send_seq_num;
							conn->send_win = (uint32_t) seg->win_size;
							conn->send_max_win = conn->send_win;

							conn->irsn = seg->seq_num;
							conn->recv_seq_num = seg->seq_num + 1;
							conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

							PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
									conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
							//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

							//TODO process options, decide: MSS, max window size!!
							//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

							if (seg->opt_len) {
								process_options(conn, seg);
							}

							//conn_change_options(conn, tcp->options, SYN);

							//send SYN ACK
							temp_seg = seg_create(conn);
							seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
							seg_send(temp_seg);
							seg_free(temp_seg);

							startTimer(conn->to_gbn_fd, TCP_MSL_TO_DEFAULT);
						}

						/*#*/PRINT_DEBUG("");
						if (sem_wait(&conn_list_sem)) {
							PRINT_ERROR("conn_list_sem wait prob");
							exit(-1);
						}
						conn->threads--;
						PRINT_DEBUG("accept_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
						sem_post(&conn_list_sem);

						/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
						sem_post(&conn->sem);

						seg_free(seg);
						break;
					} else {
						PRINT_DEBUG("");
						sem_post(&conn_list_sem);

						//error - shouldn't happen
						PRINT_ERROR("conn_insert fail");
						//conn->running_flag = 0;
						//sem_post(&conn->main_wait_sem);
						conn_shutdown(conn);
						//conn_free(conn);
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
			free(node);
		} else {
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			/*#*/PRINT_DEBUG("");
			if (sem_wait(&conn_stub->accept_wait_sem)) {
				PRINT_ERROR("conn_stub->accept_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem\n");
		}

		/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
		if (sem_wait(&conn_stub->sem)) {
			PRINT_ERROR("conn_stub->sem prod");
			exit(-1);
		}
	}

	if (!conn_stub->running_flag) {
		conn_stub_send_daemon(conn_stub, EXEC_TCP_ACCEPT, 0);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("accept_thread: leaving thread: conn_stub=%d, threads=%d", (int)conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
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

	PRINT_DEBUG("tcp_exec_accept: Entered: host=%u/%u, flags=%x", host_ip, host_port, flags);
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(host_ip, host_port);
	if (conn_stub) {
		start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
		/*#*/PRINT_DEBUG("");
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

	struct tcp_segment *seg;
	int open = 1;

	PRINT_DEBUG("close_thread: Entered: id=%d", id);

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn->write_sem)) {
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}

	/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == CS_ESTABLISHED || conn->state == CS_SYN_RECV) {
			PRINT_DEBUG("close_thread: CLOSE, send FIN, FIN_WAIT_1: state=%d conn=%d", conn->state, (int) conn);
			conn->state = CS_FIN_WAIT_1;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//if CLOSE, send FIN, FIN_WAIT_1
			if (queue_is_empty(conn->write_queue) && conn->send_seq_num == conn->send_seq_end) {
				//send FIN
				if (conn->state == CS_ESTABLISHED) {
					PRINT_DEBUG("close_thread: ESTABLISHED: done, send FIN: state=%d conn=%d", conn->state, (int)conn);
				} else {
					PRINT_DEBUG("close_thread: SYN_RECV: done, send FIN: state=%d conn=%d", conn->state, (int)conn);
				}
				conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fssn = conn->send_seq_num;
				conn->fin_ack = conn->send_seq_end + 1;

				seg = seg_create(conn);
				seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
				seg_send(seg);
				seg_free(seg);

				conn->send_seq_end++;

				//TODO add TO
			} else {
				//else piggy back it
			}
		} else if (conn->state == CS_CLOSE_WAIT) {
			PRINT_DEBUG("close_thread: CLOSE_WAIT: CLOSE, send FIN, LAST_ACK: state=%d conn=%d", conn->state, (int) conn);
			conn->state = CS_LAST_ACK;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//if CLOSE, send FIN, FIN_WAIT_1
			if (queue_is_empty(conn->write_queue) && conn->send_seq_num == conn->send_seq_end) {
				//send FIN
				PRINT_DEBUG("close_thread: done, send FIN: state=%d conn=%d", conn->state, (int)conn);
				conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fssn = conn->send_seq_num;
				conn->fin_ack = conn->send_seq_end + 1;

				seg = seg_create(conn);
				seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
				seg_send(seg);
				seg_free(seg);

				conn->send_seq_end++;

				//TODO add TO
			} else {
				//else piggy back it
			}
		} else if (conn->state == CS_SYN_SENT) {
			//if CLOSE, send -, CLOSED
			PRINT_DEBUG("close_thread: SYN_SENT: CLOSE, send -, CLOSED: state=%d conn=%d", conn->state, (int) conn);
			conn->state = CS_CLOSED;

			conn_send_daemon(conn, EXEC_TCP_CLOSE, 1, 0); //TODO check move to end of last_ack/start of time_wait?

			conn_shutdown(conn);
		} else {
			//TODO figure out:
			PRINT_DEBUG("");
		}
	} else {
		//TODO figure out: conn shutting down already?
		PRINT_DEBUG("");
	}

	/*#*/PRINT_DEBUG("");
	sem_post(&conn->write_sem);

	if (open) {
		/*#*/PRINT_DEBUG("");
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		conn->threads--;
		PRINT_DEBUG("close_thread: leaving thread: conn=%d, threads=%d", (int)conn, conn->threads);
		sem_post(&conn_list_sem);

		/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
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

	PRINT_DEBUG("tcp_exec_close: Entered: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(host_ip, host_port, rem_ip, rem_port);
	if (conn) {
		start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
		/*#*/PRINT_DEBUG("");
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

void *read_param_conn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct finsFrame *ff = thread_data->ff;
	socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("read_param_conn_thread: Entered: ff=%d", (int)ff);

	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->ctrlFrame.metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == 0;
	switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
	case READ_PARAM_TCP_HOST_WINDOW:
		PRINT_DEBUG("read_param_conn_thread: param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
		if (ret) {
			PRINT_DEBUG("read_param_conn_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			value = conn->recv_win;
			/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);

			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	case READ_PARAM_TCP_SOCK_OPT:
		PRINT_DEBUG("read_param_conn_thread: param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
		if (ret) {
			PRINT_DEBUG("read_param_conn_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			//fill in with switch of opts? or have them separate?
			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			//TODO read sock opts
			/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);
			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	default:
		PRINT_DEBUG("read_param_conn_thread: Error unknown param_id=%d", param_id);
		//TODO implement?
		break;
	}

	pthread_exit(NULL);
}

void *read_param_conn_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct finsFrame *ff = thread_data->ff;
	socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("read_param_conn_stub_thread: Entered: ff=%d", (int)ff);

	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->ctrlFrame.metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == 0;
	switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
	case READ_PARAM_TCP_HOST_WINDOW:
		PRINT_DEBUG("read_param_conn_stub_thread: param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("read_param_conn_stub_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			//TODO do something? error?
			/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
			if (sem_wait(&conn_stub->sem)) {
				PRINT_ERROR("conn_stub->write_sem wait prob");
				exit(-1);
			}
			//if (value > conn_stub->host_window) {
			//conn_stub->host_window -= value;
			//} else {
			//conn_stub->host_window = 0;
			//}
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	case READ_PARAM_TCP_SOCK_OPT:
		PRINT_DEBUG("read_param_conn_stub_thread: param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("read_param_conn_stub_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			/*//fill in with switch of opts? or have them separate?
			 /*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
			if (sem_wait(&conn_stub->sem)) {
				PRINT_ERROR("conn_stub->sem wait prob");
				exit(-1);
			}
			//if (value > conn_stub->host_window) {
			//	conn_stub->host_window -= value;
			//} else {
			//	conn_stub->host_window = 0;
			//}
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	default:
		PRINT_DEBUG("read_param_conn_stub_thread: Error unknown param_id=%d", param_id);
		//TODO implement?
		break;
	}

	pthread_exit(NULL);
}

void tcp_read_param(struct finsFrame *ff) {
	int ret = 0;

	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	struct tcp_connection *conn;
	struct tcp_connection_stub *conn_stub;
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	metadata *params = ff->ctrlFrame.metaData;
	if (metadata_read_conn(params, &state, &host_ip, &host_port, &rem_ip, &rem_port)) {
		if (state > SS_UNCONNECTED) {
			PRINT_DEBUG("tcp_read_param_host_window: searching: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_find(host_ip, host_port, rem_ip, rem_port);
			if (conn) {
				start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				if (start) {
					thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
					thread_data->id = tcp_thread_count++;
					thread_data->conn = conn;
					thread_data->ff = ff;

					if (pthread_create(&thread, NULL, read_param_conn_thread, (void *) thread_data)) {
						PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
						exit(-1);
					}
				} else {
					PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//TODO error
			}
		} else {
			PRINT_DEBUG("tcp_read_param_host_window: searching: host=%u/%u", host_ip, host_port);
			if (sem_wait(&conn_stub_list_sem)) {
				PRINT_ERROR("conn_stub_list_sem wait prob");
				exit(-1);
			}
			conn_stub = conn_stub_find(host_ip, host_port);
			if (conn_stub) {
				start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_stub_list_sem);

				if (start) {
					thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
					thread_data->id = tcp_thread_count++;
					thread_data->conn_stub = conn_stub;
					thread_data->ff = ff;

					if (pthread_create(&thread, NULL, read_param_conn_stub_thread, (void *) thread_data)) {
						PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
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
	} else {
		//TODO error
	}
}

void *set_param_conn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct finsFrame *ff = thread_data->ff;
	socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("set_param_conn_thread: Entered: ff=%d", (int)ff);

	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->ctrlFrame.metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == 0;
	switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
	case SET_PARAM_TCP_HOST_WINDOW:
		PRINT_DEBUG("set_param_conn_thread: param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("set_param_conn_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			if (conn->recv_win + value < conn->recv_win || conn->recv_max_win < conn->recv_win + value) {
				conn->recv_win = conn->recv_max_win;
			} else {
				conn->recv_win += value;
			}/*#*/
			PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	case SET_PARAM_TCP_SOCK_OPT:
		PRINT_DEBUG("set_param_conn_thread: param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("set_param_conn_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			//fill in with switch of opts? or have them separate?
			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			if (value > conn->recv_win) {
				conn->recv_win -= value;
			} else {
				conn->recv_win = 0;
			}
			/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	default:
		PRINT_DEBUG("set_param_conn_thread: Error unknown param_id=%d", param_id);
		//TODO implement?
		break;
	}

	pthread_exit(NULL);
}

void *set_param_conn_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct finsFrame *ff = thread_data->ff;
	socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("set_param_conn_stub_thread: Entered: ff=%d", (int)ff);

	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->ctrlFrame.metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == 0;
	switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
	case SET_PARAM_TCP_HOST_WINDOW:
		PRINT_DEBUG("set_param_conn_stub_thread: param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("set_param_conn_stub_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			//TODO do something? error?
			/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
			if (sem_wait(&conn_stub->sem)) {
				PRINT_ERROR("conn_stub->write_sem wait prob");
				exit(-1);
			}
			//if (value > conn_stub->host_window) {
			//conn_stub->host_window -= value;
			//} else {
			//conn_stub->host_window = 0;
			//}
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	case SET_PARAM_TCP_SOCK_OPT:
		PRINT_DEBUG("set_param_conn_thread: param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
		ret = metadata_readFromElement(params, "value", &value) == 0;
		if (ret) {
			PRINT_DEBUG("set_param_conn_thread: ret=%d", ret);
			//TODO send nack

			value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		} else {
			//fill in with switch of opts? or have them separate?
			/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
			if (sem_wait(&conn_stub->sem)) {
				PRINT_ERROR("conn_stub->sem wait prob");
				exit(-1);
			}
			//if (value > conn_stub->host_window) {
			//	conn_stub->host_window -= value;
			//} else {
			//	conn_stub->host_window = 0;
			//}
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
			sem_post(&conn_stub->sem);

			value = 1;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
		}

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
		break;
	default:
		PRINT_DEBUG("set_param_conn_thread: Error unknown param_id=%d", param_id);
		//TODO implement?
		break;
	}

	pthread_exit(NULL);
}

void tcp_set_param(struct finsFrame *ff) {
	int ret = 0;

	socket_state state = 0;
	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	metadata *params = ff->ctrlFrame.metaData;
	if (params) {
		if (metadata_read_conn(params, &state, &host_ip, &host_port, &rem_ip, &rem_port)) {
			if (state > SS_UNCONNECTED) {
				PRINT_DEBUG("tcp_read_param_host_window: searching: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
				if (sem_wait(&conn_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				struct tcp_connection *conn = conn_find(host_ip, host_port, rem_ip, rem_port);
				if (conn) {
					start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_thread_count++;
						thread_data->conn = conn;
						thread_data->ff = ff;
						thread_data->flags = state;

						if (pthread_create(&thread, NULL, set_param_conn_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
							exit(-1);
						}
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
					}
				} else {
					PRINT_DEBUG("");
					sem_post(&conn_list_sem);

					//TODO error
					PRINT_DEBUG("todo error");

					int value = 0;
					metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);

					ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
					tcp_to_switch(ff);
				}
			} else {
				PRINT_DEBUG("tcp_read_param_host_window: searching: host=%u/%u", host_ip, host_port);
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_stub_list_sem wait prob");
					exit(-1);
				}
				struct tcp_connection_stub *conn_stub = conn_stub_find(host_ip, host_port);
				if (conn_stub) {
					start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_thread_count++;
						thread_data->conn_stub = conn_stub;
						thread_data->ff = ff;
						thread_data->flags = state;

						if (pthread_create(&thread, NULL, set_param_conn_stub_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
							exit(-1);
						}
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
					}
				} else {
					PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					//TODO error
					PRINT_DEBUG("todo error");
					int value = 0;
					metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);

					ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
					tcp_to_switch(ff);
				}
			}
		} else {
			//TODO error
			PRINT_DEBUG("todo error");
			int value = 0;
			metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
		}
	} else {
		//TODO huge error
		PRINT_DEBUG("todo error huge");
	}
}
