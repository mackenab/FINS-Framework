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
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	uint8_t *called_data = thread_data->data_raw;
	uint32_t called_len = thread_data->data_len;
	uint32_t serial_num = thread_data->serial_num;
	uint32_t flags = thread_data->flags;
	free(thread_data);

	uint8_t *pt = called_data;
	int index = 0;
	int len;
	int space;
	uint8_t *buf;
	struct tcp_node *node;

	if (flags & (1)) {
		//TODO do specific flags/settings
	}

	PRINT_DEBUG("Entered: id=%u", id);
	if (sem_wait(&conn->write_sem)) { //func depends on write_sem, write op can't be interrupted
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		PRINT_DEBUG("state=%d", conn->state);
		if (conn->state == TCP_SYN_SENT || conn->state == TCP_SYN_RECV) { //equiv to non blocking
			PRINT_DEBUG("non-blocking");
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
				//conn_send_daemon(conn, EXEC_TCP_SEND, 0, 2); //TODO change msg values, "error: insufficient resources"
				conn_send_fcf(conn, serial_num, EXEC_TCP_SEND, 0, 2);
				free(called_data);
			}
		} else if (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT) { //essentially blocking
			PRINT_DEBUG("blocking");
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

					if (index == called_len) {
						break;
					}

					/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
					sem_post(&conn->sem);
				} else {
					/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
					sem_post(&conn->sem);

					/*#*/PRINT_DEBUG("");
					if (sem_wait(&conn->write_wait_sem)) {
						PRINT_ERROR("conn->send_wait_sem prob");
						exit(-1);
					}
					sem_init(&conn->write_wait_sem, 0, 0);
					PRINT_DEBUG("left conn->send_wait_sem\n");
				}

				/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
				if (sem_wait(&conn->sem)) {
					PRINT_ERROR("conn->sem prod");
					exit(-1);
				}
			}

			if (conn->running_flag) {
				/*#*/PRINT_DEBUG("");
				//send ACK to send handler
				if (index == called_len) {
					//conn_send_daemon(conn, EXEC_TCP_SEND, 1, 0);
					conn_send_fcf(conn, serial_num, EXEC_TCP_SEND, 1, called_len);
				} else {
					PRINT_DEBUG("todo error");
					//TODO error  //TODO remove - can't ever happen?
				}
			} else {
				/*#*/PRINT_DEBUG("todo error");
				//send NACK to send handler
				//conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
				conn_send_fcf(conn, serial_num, EXEC_TCP_SEND, 0, 1);
			}

			free(called_data);
		} else {
			//TODO error, send/write'ing when conn sending is closed
			PRINT_DEBUG("todo error");
			//send NACK to send handler
			//conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
			conn_send_fcf(conn, serial_num, EXEC_TCP_SEND, 0, 1);

			free(called_data);
		}
	} else {
		PRINT_DEBUG("todo error");
		//send NACK to send handler
		//conn_send_daemon(conn, EXEC_TCP_SEND, 0, 1);
		conn_send_fcf(conn, serial_num, EXEC_TCP_SEND, 0, 1);
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
	//conn->write_threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void tcp_out_fdf(struct finsFrame *ff) {
	//receiving straight data from the APP layer, process/package into segment
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_port;
	uint32_t dst_port;

	uint32_t flags;
	uint32_t serial_num;

	PRINT_DEBUG("Entered: ff=%p", ff);

	metadata* meta = ff->metaData;

	int ret = 0;
	ret += metadata_readFromElement(meta, "flags", &flags) == CONFIG_FALSE;

	ret += metadata_readFromElement(meta, "src_ip", &src_ip) == CONFIG_FALSE; //host
	ret += metadata_readFromElement(meta, "dst_ip", &dst_ip) == CONFIG_FALSE; //remote
	ret += metadata_readFromElement(meta, "src_port", &src_port) == CONFIG_FALSE;
	ret += metadata_readFromElement(meta, "dst_port", &dst_port) == CONFIG_FALSE;

	ret += metadata_readFromElement(meta, "serial_num", &serial_num) == CONFIG_FALSE;

	if (ret) {
		//TODO error
		PRINT_DEBUG("todo error");
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	struct tcp_connection *conn = conn_list_find(src_ip, (uint16_t) src_port, dst_ip, (uint16_t) dst_port); //TODO check if right
	int start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
	//if (start) {conn->write_threads++;}
	/*#*/PRINT_DEBUG("");
	sem_post(&conn_list_sem);

	if (conn) {
		if (start) {
			struct tcp_thread_data *thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_gen_thread_id();
			thread_data->conn = conn;
			thread_data->data_raw = ff->dataFrame.pdu;
			thread_data->data_len = ff->dataFrame.pduLength;
			thread_data->flags = flags;
			thread_data->serial_num = serial_num;

			//spin off thread to handle
			pthread_t thread;
			if (pthread_create(&thread, NULL, write_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create write_thread thread.");
				exit(-1);
			}
			pthread_detach(thread);
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		//TODO error
		PRINT_DEBUG("todo error");

		//TODO LISTEN: if SEND, SYN, SYN_SENT
	}

	freeFinsFrame(ff);
}

void *close_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	//uint32_t send_ack = thread_data->flags;
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}

	if (conn_stub->running_flag) {
		conn_stub_shutdown(conn_stub);

		//send ACK to close handler
		//conn_stub_send_daemon(conn_stub, EXEC_TCP_CLOSE_STUB, 1, 0);
		tcp_reply_fcf(ff, 1, 0);

		conn_stub_free(conn_stub);
	} else {
		PRINT_DEBUG("todo error");
		//send NACK to close handler
		//conn_stub_send_daemon(conn_stub, EXEC_TCP_CLOSE_STUB, 0, 0);
		tcp_reply_fcf(ff, 0, 0);
	}

	//TODO add conn_stub->threads--?

	PRINT_DEBUG("Exited: id=%u", id);

	pthread_exit(NULL);
}

void tcp_exec_close_stub(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port) {
	PRINT_DEBUG("Entered: host=%u/%u", host_ip, host_port);

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	struct tcp_connection_stub *conn_stub = conn_stub_list_find(host_ip, host_port);
	if (conn_stub) {
		conn_stub_list_remove(conn_stub);
		int start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
		/*#*/PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);

		if (start) {
			struct tcp_thread_data *thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_gen_thread_id();
			thread_data->conn_stub = conn_stub;
			thread_data->flags = 1;
			thread_data->ff = ff;

			pthread_t thread;
			if (pthread_create(&thread, NULL, close_stub_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
			pthread_detach(thread);
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
		}
	} else {
		PRINT_DEBUG("todo error");
		sem_post(&conn_stub_list_sem);
		//TODO error
	}
}

void *poll_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	//uint32_t send_ack = thread_data->flags;
	uint32_t events = thread_data->flags; //events
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	uint32_t mask = 0;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}

	if (conn->running_flag) {
		//TODO redo, for now mostly does POLLOUT

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) { //TODO remove - handled by daemon
			//mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?

			//add a check to see if conn moves to CLOSE_WAIT, post: POLLHUP
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
			sem_post(&conn->sem);

			if (sem_wait(&conn->write_sem)) {
				PRINT_ERROR("conn->write_sem wait prob");
				exit(-1);
			}

			/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			while (conn->running_flag) { //TODO optimize
				//POLLOUT, returns if writing then won't block
				//TODO decide if means no write_threads or simply there's write_queue space //returns if have >=1 space in write_queue

				if (queue_has_space(conn->write_queue, 1)) {
					mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
					break;
				} else {
					/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
					sem_post(&conn->sem);

					/*#*/PRINT_DEBUG("");
					if (sem_wait(&conn->write_wait_sem)) {
						PRINT_ERROR("conn->send_wait_sem prob");
						exit(-1);
					}
					sem_init(&conn->write_wait_sem, 0, 0);
					PRINT_DEBUG("left conn->send_wait_sem\n");

					/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
					if (sem_wait(&conn->sem)) {
						PRINT_ERROR("conn->sem wait prob");
						exit(-1);
					}
				}
			}

			if (conn->running_flag) {
				//conn_send_daemon(conn, EXEC_TCP_POLL, 1, mask);
				tcp_reply_fcf(ff, 1, mask);
			} else {
				//conn_send_daemon(conn, EXEC_TCP_POLL, 1, 0);
				tcp_reply_fcf(ff, 1, POLLHUP); //TODO check on value?
			}

			/*#*/PRINT_DEBUG("");
			sem_post(&conn->write_sem);
		}
	} else {
		PRINT_DEBUG("todo error");
		//conn_send_daemon(conn, EXEC_TCP_POLL, 1, 0);
		tcp_reply_fcf(ff, 1, POLLHUP); //TODO check on value?
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void *poll_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	//uint32_t send_ack = thread_data->flags;
	uint32_t events = thread_data->flags; //events
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	uint32_t mask = 0;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}

	//TODO finish
	if (conn_stub->running_flag) {

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			//mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			//mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
			//TODO contact TCP for
		}

		if (events & mask) {

		}

		//conn_stub_send_daemon(conn_stub, EXEC_TCP_POLL, 1, mask);
		tcp_reply_fcf(ff, 1, mask);
	} else {
		PRINT_DEBUG("todo error");
		//conn_stub_send_daemon(conn_stub, EXEC_TCP_POLL, 1, 0);
		tcp_reply_fcf(ff, 0, 0);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void tcp_exec_poll(struct finsFrame *ff, socket_state state, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, uint32_t flags) {
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("Entered: state=%u host=%u/%u rem=%u/%u", state, host_ip, host_port, rem_ip, rem_port);
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		struct tcp_connection *conn = conn_list_find(host_ip, host_port, rem_ip, rem_port);
		if (conn) {
			start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_list_sem);

			if (start) {
				thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->id = tcp_gen_thread_id();
				thread_data->conn = conn;
				thread_data->flags = flags;
				thread_data->ff = ff;

				if (pthread_create(&thread, NULL, poll_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create poll_thread thread.");
					exit(-1);
				}
				pthread_detach(thread);
			} else {
				PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
				tcp_reply_fcf(ff, 1, POLLERR); //TODO check on value?
			}
		} else {
			PRINT_DEBUG("todo error");
			sem_post(&conn_list_sem);
			//TODO error

			tcp_reply_fcf(ff, 1, POLLERR); //TODO check on value?
		}
	} else {
		PRINT_DEBUG("Entered: state=%u host=%u/%u", state, host_ip, host_port);
		if (sem_wait(&conn_stub_list_sem)) {
			PRINT_ERROR("conn_stub_list_sem wait prob");
			exit(-1);
		}
		struct tcp_connection_stub *conn_stub = conn_stub_list_find(host_ip, host_port);
		if (conn_stub) {
			start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_stub_list_sem);

			if (start) {
				thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->id = tcp_gen_thread_id();
				thread_data->conn_stub = conn_stub;
				thread_data->flags = flags;
				thread_data->ff = ff;

				if (pthread_create(&thread, NULL, poll_stub_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create poll_stub_thread thread.");
					exit(-1);
				}
				pthread_detach(thread);
			} else {
				PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
				tcp_reply_fcf(ff, 1, POLLERR); //TODO check on value?
			}
		} else {
			PRINT_DEBUG("todo error");
			sem_post(&conn_stub_list_sem);
			//TODO error

			tcp_reply_fcf(ff, 1, POLLERR); //TODO check on value?
		}
	}
}

void *connect_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	uint32_t flags = thread_data->flags;
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	struct tcp_segment *temp_seg;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == TCP_CLOSED || conn->state == TCP_LISTEN) {
			//if CONNECT, send SYN, SYN_SENT
			if (conn->state == TCP_CLOSED) {
				PRINT_DEBUG("CLOSED: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			} else {
				PRINT_DEBUG("LISTEN: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			}
			conn->state = TCP_SYN_SENT;
			conn->active_open = 1;
			conn->ff = ff;

			if (flags & (1)) {
				//TODO do specific flags/settings
			}

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
			//conn_send_daemon(conn, EXEC_TCP_CONNECT, 0, 0);
			tcp_reply_fcf(ff, 0, 0);
		}
	} else {
		PRINT_DEBUG("todo error");
		//send NACK to connect handler
		//conn_send_daemon(conn, EXEC_TCP_CONNECT, 0, 1);
		tcp_reply_fcf(ff, 0, 1);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void tcp_exec_connect(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, uint32_t flags) {
	PRINT_DEBUG("Entered: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	struct tcp_connection *conn = conn_list_find(host_ip, host_port, rem_ip, rem_port);
	if (conn == NULL) {
		if (conn_list_has_space()) {
			conn = conn_create(host_ip, host_port, rem_ip, rem_port);
			if (conn_list_insert(conn)) {
				conn->threads++;
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//if listening stub remove
				/*#*/PRINT_DEBUG("");
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				struct tcp_connection_stub *conn_stub = conn_stub_list_find(host_ip, host_port);
				if (conn_stub) {
					conn_stub_list_remove(conn_stub);
					int start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					if (start) {
						struct tcp_thread_data *stub_thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						stub_thread_data->id = tcp_gen_thread_id();
						stub_thread_data->conn_stub = conn_stub;
						stub_thread_data->flags = 0;

						pthread_t stub_thread;
						if (pthread_create(&stub_thread, NULL, close_stub_thread, (void *) stub_thread_data)) {
							PRINT_ERROR("ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
						pthread_detach(stub_thread);
					}
				} else {
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);
				}

				struct tcp_thread_data *thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->id = tcp_gen_thread_id();
				thread_data->conn = conn;
				thread_data->flags = flags;
				thread_data->ff = ff;

				pthread_t thread;
				if (pthread_create(&thread, NULL, connect_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
				pthread_detach(thread);
			} else {
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_insert fail");
				//conn->running_flag = 0;
				//sem_post(&conn->main_wait_sem);
				conn_shutdown(conn);
				//conn_free(conn);

				//TODO send NACK
			}
		} else {
			PRINT_DEBUG("todo error");
			sem_post(&conn_list_sem);

			//TODO throw minor error, list full
			//TODO send NACK
		}
	} else {
		PRINT_DEBUG("todo error");
		sem_post(&conn_list_sem);

		//TODO error, existing connection already connected there
		//TODO send NACK?
	}
}

void tcp_exec_listen(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t backlog) {
	struct tcp_connection_stub *conn_stub;

	PRINT_DEBUG("Entered: addr=%u/%u, backlog=%u", host_ip, host_port, backlog);
	if (sem_wait(&conn_stub_list_sem)) { //TODO change from conn_stub to conn in listen
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_list_find(host_ip, host_port);
	if (conn_stub == NULL) {
		if (conn_stub_list_has_space(1)) {
			conn_stub = conn_stub_create(host_ip, host_port, backlog);
			if (conn_stub_list_insert(conn_stub)) {
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
			PRINT_DEBUG("todo error");
			sem_post(&conn_stub_list_sem);
			//TODO throw minor error
		}
	} else {
		PRINT_DEBUG("todo error");
		sem_post(&conn_stub_list_sem);
		//TODO error
	}

	//TODO send ACK to listen handler - don't? have nonblocking
	freeFinsFrame(ff);
}

void *accept_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t flags = thread_data->flags;
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	//int start;
	struct tcp_segment *temp_seg;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	while (conn_stub->running_flag) {
		if (!queue_is_empty(conn_stub->syn_queue)) {
			node = queue_remove_front(conn_stub->syn_queue);
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
			sem_post(&conn_stub->sem);

			seg = (struct tcp_segment *) node->data;

			/*#*/PRINT_DEBUG("");
			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_list_find(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
			if (conn == NULL) {
				if (conn_list_has_space()) {
					conn = conn_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
					if (conn_list_insert(conn)) {
						conn->threads++;
						/*#*/PRINT_DEBUG("");
						sem_post(&conn_list_sem);

						/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
						if (sem_wait(&conn->sem)) {
							PRINT_ERROR("conn->sem wait prob");
							exit(-1);
						}
						if (conn->running_flag) { //LISTENING state
							//if SYN, send SYN ACK, SYN_RECV
							PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
							conn->state = TCP_SYN_RECV;
							conn->active_open = 0;
							conn->ff = ff;

							if (flags & (1)) {
								//TODO do specific flags/settings
							}

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
						} else {
							PRINT_DEBUG("todo error");
							//TODO error
						}

						/*#*/PRINT_DEBUG("");
						if (sem_wait(&conn_list_sem)) {
							PRINT_ERROR("conn_list_sem wait prob");
							exit(-1);
						}
						conn->threads--;
						PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
						sem_post(&conn_list_sem);

						/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
						sem_post(&conn->sem);

						seg_free(seg);
						free(node);
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
					PRINT_DEBUG("todo error");
					sem_post(&conn_list_sem);
					//TODO throw minor error
				}
			} else {
				PRINT_DEBUG("todo error");
				sem_post(&conn_list_sem);
				//TODO error
			}

			seg_free(seg);
			free(node);
		} else {
			/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
			sem_post(&conn_stub->sem);

			/*#*/PRINT_DEBUG("");
			if (sem_wait(&conn_stub->accept_wait_sem)) {
				PRINT_ERROR("conn_stub->accept_wait_sem prob");
				exit(-1);
			}
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem\n");
		}

		/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
		if (sem_wait(&conn_stub->sem)) {
			PRINT_ERROR("conn_stub->sem prod");
			exit(-1);
		}
	}

	if (!conn_stub->running_flag) {
		PRINT_DEBUG("todo error");
		//conn_stub_send_daemon(conn_stub, EXEC_TCP_ACCEPT, 0, 0);
		tcp_reply_fcf(ff, 0, 0);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("Exited: id=%u", id);

	pthread_exit(NULL);
}

void tcp_exec_accept(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t flags) {
	PRINT_DEBUG("Entered: host=%u/%u, flags=%x", host_ip, host_port, flags);

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	struct tcp_connection_stub *conn_stub = conn_stub_list_find(host_ip, host_port);
	if (conn_stub) {
		int start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
		/*#*/PRINT_DEBUG("");
		sem_post(&conn_stub_list_sem);

		if (start) {
			struct tcp_thread_data *thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_gen_thread_id();
			thread_data->conn_stub = conn_stub;
			thread_data->flags = flags;
			thread_data->ff = ff;

			pthread_t thread;
			if (pthread_create(&thread, NULL, accept_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
			pthread_detach(thread);
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
			//TODO send NACK
		}
	} else {
		PRINT_DEBUG("todo error");
		sem_post(&conn_stub_list_sem);
		//TODO error, no listening stub

		//TODO send NACK
	}
}

void *close_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	struct tcp_segment *seg;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn->write_sem)) {
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == TCP_ESTABLISHED || conn->state == TCP_SYN_RECV) {
			PRINT_DEBUG("CLOSE, send FIN, FIN_WAIT_1: state=%d conn=%p", conn->state, conn);
			conn->state = TCP_FIN_WAIT_1;
			conn->ff_close = ff;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//if CLOSE, send FIN, FIN_WAIT_1
			if (queue_is_empty(conn->write_queue) && conn->send_seq_num == conn->send_seq_end) {
				//send FIN
				if (conn->state == TCP_ESTABLISHED) {
					PRINT_DEBUG("ESTABLISHED: done, send FIN: state=%d conn=%p", conn->state, conn);
				} else {
					PRINT_DEBUG("SYN_RECV: done, send FIN: state=%d conn=%p", conn->state, conn);
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
		} else if (conn->state == TCP_CLOSE_WAIT) {
			PRINT_DEBUG("CLOSE_WAIT: CLOSE, send FIN, LAST_ACK: state=%d conn=%p", conn->state, conn);
			conn->state = TCP_LAST_ACK;
			conn->ff_close = ff;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//if CLOSE, send FIN, FIN_WAIT_1
			if (queue_is_empty(conn->write_queue) && conn->send_seq_num == conn->send_seq_end) {
				//send FIN
				PRINT_DEBUG("done, send FIN: state=%d conn=%p", conn->state, conn);
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
		} else if (conn->state == TCP_SYN_SENT) {
			//if CLOSE, send -, CLOSED
			PRINT_DEBUG("SYN_SENT: CLOSE, send -, CLOSED: state=%d conn=%p", conn->state, conn);
			conn->state = TCP_CLOSED;

			if (conn->ff) {
				tcp_reply_fcf(conn->ff, 0, 0); //send NACK about connect call
				conn->ff = NULL;
			} else {
				PRINT_DEBUG("todo error");
			}

			//conn_send_daemon(conn, EXEC_TCP_CLOSE, 1, 0); //TODO check move to end of last_ack/start of time_wait?
			tcp_reply_fcf(ff, 1, 0);

			conn_shutdown(conn);
		} else {
			//TODO figure out:
			PRINT_DEBUG("todo error");
		}
	} else {
		//TODO figure out: conn shutting down already?
		PRINT_DEBUG("todo error");
	}

	/*#*/PRINT_DEBUG("");
	sem_post(&conn->write_sem);

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);

	pthread_exit(NULL);
}

void tcp_exec_close(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	struct tcp_connection *conn = conn_list_find(host_ip, host_port, rem_ip, rem_port);
	if (conn) {
		int start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
		/*#*/PRINT_DEBUG("");
		sem_post(&conn_list_sem);

		if (start) {
			struct tcp_thread_data *thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_gen_thread_id();
			thread_data->conn = conn;
			thread_data->ff = ff;

			pthread_t thread;
			if (pthread_create(&thread, NULL, close_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
			pthread_detach(thread);
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		PRINT_DEBUG("todo error");
		sem_post(&conn_list_sem);
		//TODO error trying to close closed connection
	}
}

void *read_param_conn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct finsFrame *ff = thread_data->ff;
	//socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: ff=%p, conn=%p, id=%u", ff, conn, id);

	uint32_t ret_val;
	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == CONFIG_FALSE;

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
		case READ_PARAM_TCP_HOST_WINDOW:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
				value = conn->recv_win;
				metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		case READ_PARAM_TCP_SOCK_OPT:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				//fill in with switch of opts? or have them separate?

				//TODO read sock opts

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		default:
			PRINT_DEBUG("Error unknown param_id=%d", param_id);
			//TODO implement?

			ret_val = 0;
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		}
	} else {
		PRINT_DEBUG("todo error");

		ret_val = 0;
		metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

		ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
		tcp_to_switch(ff);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void *read_param_conn_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct finsFrame *ff = thread_data->ff;
	//socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: ff=%p, conn_stub=%p, id=%u", ff, conn_stub, id);

	uint32_t ret_val;
	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == CONFIG_FALSE;

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->write_sem wait prob");
		exit(-1);
	}
	if (conn_stub->running_flag) {
		switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
		case READ_PARAM_TCP_HOST_WINDOW:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				//TODO do something? error?

				//if (value > conn_stub->host_window) {
				//conn_stub->host_window -= value;
				//} else {
				//conn_stub->host_window = 0;
				//}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		case READ_PARAM_TCP_SOCK_OPT:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				//fill in with switch of opts? or have them separate?

				//if (value > conn_stub->host_window) {
				//	conn_stub->host_window -= value;
				//} else {
				//	conn_stub->host_window = 0;
				//}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		default:
			PRINT_DEBUG("Error unknown param_id=%d", param_id);
			//TODO implement?

			ret_val = 0;
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		}
	} else {
		PRINT_DEBUG("todo error");

		ret_val = 0;
		metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void tcp_read_param(struct finsFrame *ff) {
	//int ret = 0;

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

	metadata *params = ff->metaData;
	if (metadata_read_conn(params, &state, &host_ip, &host_port, &rem_ip, &rem_port)) {
		if (state > SS_UNCONNECTED) {
			PRINT_DEBUG("searching: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_list_find(host_ip, host_port, rem_ip, rem_port);
			if (conn) {
				start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_list_sem);

				if (start) {
					thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
					thread_data->id = tcp_gen_thread_id();
					thread_data->conn = conn;
					thread_data->ff = ff;

					if (pthread_create(&thread, NULL, read_param_conn_thread, (void *) thread_data)) {
						PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
						exit(-1);
					}
					pthread_detach(thread);
				} else {
					PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
				}
			} else {
				PRINT_DEBUG("todo error");
				sem_post(&conn_list_sem);

				//TODO error
			}
		} else {
			PRINT_DEBUG("searching: host=%u/%u", host_ip, host_port);
			if (sem_wait(&conn_stub_list_sem)) {
				PRINT_ERROR("conn_stub_list_sem wait prob");
				exit(-1);
			}
			conn_stub = conn_stub_list_find(host_ip, host_port);
			if (conn_stub) {
				start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
				/*#*/PRINT_DEBUG("");
				sem_post(&conn_stub_list_sem);

				if (start) {
					thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
					thread_data->id = tcp_gen_thread_id();
					thread_data->conn_stub = conn_stub;
					thread_data->ff = ff;

					if (pthread_create(&thread, NULL, read_param_conn_stub_thread, (void *) thread_data)) {
						PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
						exit(-1);
					}
					pthread_detach(thread);
				} else {
					PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
				}
			} else {
				PRINT_DEBUG("todo error");
				sem_post(&conn_stub_list_sem);

				//TODO error
			}
		}
	} else {
		PRINT_DEBUG("todo error");
		//TODO error
	}
}

void *set_param_conn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct finsFrame *ff = thread_data->ff;
	//socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: ff=%p, conn=%p, id=%u", ff, conn, id);

	uint32_t param_id;
	uint32_t ret_val;
	uint32_t value;

	metadata *params = ff->metaData;

	int ret = 0;
	ret = metadata_readFromElement(params, "param_id", &param_id) == CONFIG_FALSE;

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
		case SET_PARAM_TCP_HOST_WINDOW:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				if (conn->recv_win + value < conn->recv_win || conn->recv_max_win < conn->recv_win + value) {
					conn->recv_win = conn->recv_max_win;
				} else {
					conn->recv_win += value;
				}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		case SET_PARAM_TCP_SOCK_OPT:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				//fill in with switch of opts? or have them separate?

				if (value > conn->recv_win) {
					conn->recv_win -= value;
				} else {
					conn->recv_win = 0;
				}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		default:
			PRINT_DEBUG("Error unknown param_id=%d", param_id);
			//TODO implement?

			ret_val = 0;
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		}
	} else {
		PRINT_DEBUG("todo error");

		ret_val = 0;
		metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	sem_post(&conn_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void *set_param_conn_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct finsFrame *ff = thread_data->ff;
	//socket_state state = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: ff=%p, conn_stub=%p, id=%u", ff, conn_stub, id);

	uint32_t ret_val;
	uint32_t param_id;
	uint32_t value;

	int ret = 0;
	metadata *params = ff->metaData;
	ret = metadata_readFromElement(params, "param_id", &param_id) == CONFIG_FALSE;

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	if (conn_stub->running_flag) {
		switch (param_id) { //TODO optimize this code better when control format is fully fleshed out
		case SET_PARAM_TCP_HOST_WINDOW:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_HOST_WINDOW (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				ret_val = 0;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			} else {
				//TODO do something? error?

				//if (value > conn_stub->host_window) {
				//conn_stub->host_window -= value;
				//} else {
				//conn_stub->host_window = 0;
				//}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		case SET_PARAM_TCP_SOCK_OPT:
			PRINT_DEBUG("param_id=READ_PARAM_TCP_SOCK_OPT (%d)", param_id);
			ret = metadata_readFromElement(params, "value", &value) == CONFIG_FALSE;
			if (ret) {
				PRINT_DEBUG("ret=%d", ret);
				//TODO send nack

				value = 0;
				metadata_writeToElement(params, "ret_val", &value, META_TYPE_INT);
			} else {
				//fill in with switch of opts? or have them separate?

				//if (value > conn_stub->host_window) {
				//	conn_stub->host_window -= value;
				//} else {
				//	conn_stub->host_window = 0;
				//}

				ret_val = 1;
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);
			}

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		default:
			PRINT_DEBUG("Error unknown param_id=%d", param_id);
			//TODO implement?

			ret_val = 0;
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
			break;
		}
	} else {
		PRINT_DEBUG("todo error");

		ret_val = 0;
		metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		tcp_to_switch(ff);
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	sem_post(&conn_stub_list_sem);

	/*#*/PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	pthread_exit(NULL);
}

void tcp_set_param(struct finsFrame *ff) {
	//int ret = 0;

	socket_state state = 0;
	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;
	uint32_t ret_val;

	metadata *params = ff->metaData;
	if (params) {
		if (metadata_read_conn(params, &state, &host_ip, &host_port, &rem_ip, &rem_port)) {
			if (state > SS_UNCONNECTED) {
				PRINT_DEBUG("searching: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
				if (sem_wait(&conn_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				struct tcp_connection *conn = conn_list_find(host_ip, host_port, rem_ip, rem_port);
				if (conn) {
					start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_gen_thread_id();
						thread_data->conn = conn;
						thread_data->ff = ff;
						thread_data->flags = state;

						if (pthread_create(&thread, NULL, set_param_conn_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
							exit(-1);
						}
						pthread_detach(thread);
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
					}
				} else {
					PRINT_DEBUG("todo error");
					sem_post(&conn_list_sem);

					//TODO error

					ret_val = 0;
					metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

					ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
					tcp_to_switch(ff);
				}
			} else {
				PRINT_DEBUG("searching: host=%u/%u", host_ip, host_port);
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_stub_list_sem wait prob");
					exit(-1);
				}
				struct tcp_connection_stub *conn_stub = conn_stub_list_find(host_ip, host_port);
				if (conn_stub) {
					start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_gen_thread_id();
						thread_data->conn_stub = conn_stub;
						thread_data->ff = ff;
						thread_data->flags = state;

						if (pthread_create(&thread, NULL, set_param_conn_stub_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create read_param_thread thread.");
							exit(-1);
						}
						pthread_detach(thread);
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
					}
				} else {
					PRINT_DEBUG("todo error");
					sem_post(&conn_stub_list_sem);

					//TODO error

					ret_val = 0;
					metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

					ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
					tcp_to_switch(ff);
				}
			}
		} else {
			//TODO error
			PRINT_DEBUG("todo error");
			ret_val = 0;
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
			tcp_to_switch(ff);
		}
	} else {
		//TODO huge error
		PRINT_DEBUG("todo error huge");
	}
}
