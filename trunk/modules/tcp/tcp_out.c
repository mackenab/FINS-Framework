/*
 * @file tcp_out.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */
#include "tcp_internal.h"

void tcp_write(struct fins_module *module, struct tcp_conn *conn, uint32_t called_len, uint8_t *called_data, uint32_t flags, uint32_t serial_num) {
	PRINT_DEBUG("Entered: conn=%p, called_len=%u, called_data=%p, flags=0x%x, serial_num=%u", conn, called_len, called_data, flags, serial_num);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_node *node;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		PRINT_DEBUG("state=%d", conn->state);
		if (conn->state == TS_SYN_SENT || conn->state == TS_SYN_RECV) { //equiv to non blocking
			PRINT_DEBUG("pre-connected non-blocking");

			int space = conn->write_queue->max - conn->write_queue->len;
			PRINT_DEBUG("space=%d, called_len=%u", space, called_len);
			if (space >= called_len) {
				node = tcp_node_create(called_data, called_len, 0, called_len - 1);
				tcp_queue_append(conn->write_queue, node);

				space -= called_len;

				tcp_conn_send_exec_reply(conn, serial_num, TCP_EXEC_SEND, FCF_TRUE, called_len);

				if (conn->main_waiting) {
					conn->main_waiting = 0;
					PRINT_DEBUG("posting to main_wait_sem");
					sem_post(&conn->main_wait_sem);
				}
			} else {
				tcp_conn_send_exec_reply(conn, serial_num, TCP_EXEC_SEND, FCF_FALSE, EAGAIN);
				free(called_data);
			}

			if (conn->poll_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
				if (tcp_queue_is_empty(conn->request_queue)) {
					PRINT_DEBUG("conn=%p, space=%d", conn, space);
					if (space > 0) { //only possible if request_queue is empty
						tcp_conn_send_fcf(conn, CTRL_ALERT, TCP_ALERT_POLL, FCF_TRUE, POLLOUT | POLLWRNORM | POLLWRBAND);
						conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
					}
				}
			}
		} else if (conn->state == TS_ESTABLISHED || conn->state == TS_CLOSE_WAIT) {
			struct tcp_request *request = (struct tcp_request *) secure_malloc(sizeof(struct tcp_request));
			request->data = called_data;
			request->len = called_len;
			request->flags = flags;
			request->serial_num = serial_num;

			if (flags & (MSG_DONTWAIT)) {
				PRINT_DEBUG("non-blocking");

				request->to_flag = 0;

				request->to_data = secure_malloc(sizeof(struct intsem_to_timer_data));
				request->to_data->handler = intsem_to_handler;
				request->to_data->flag = &request->to_flag;
				request->to_data->interrupt = &conn->request_interrupt;
				request->to_data->sem = &conn->main_wait_sem;
				timer_create_to((struct to_timer_data *) request->to_data);

				timer_once_start(request->to_data->tid, TCP_BLOCK_DEFAULT);
			} else {
				PRINT_DEBUG("blocking");

				request->to_flag = 0;
				request->to_data = NULL;
			}

			if (tcp_queue_has_space(conn->request_queue, 1)) {
				node = tcp_node_create((uint8_t *) request, 1, 0, 0);
				tcp_queue_append(conn->request_queue, node);

				tcp_handle_requests(conn);

				if (conn->main_waiting) {
					conn->main_waiting = 0;
					PRINT_DEBUG("posting to main_wait_sem");
					sem_post(&conn->main_wait_sem);
				}
			} else {
				PRINT_ERROR("request_list full, len=%u", conn->request_queue->len);
				//send NACK to send handler
				tcp_conn_send_exec_reply(conn, serial_num, TCP_EXEC_SEND, FCF_FALSE, 0);
				free(called_data);
			}
		} else {
			//TODO error, send/write'ing when conn sending is closed
			PRINT_WARN("todo error");
			//send NACK to send handler
			tcp_conn_send_exec_reply(conn, serial_num, TCP_EXEC_SEND, FCF_FALSE, 0);

			free(called_data);
		}
	} else {
		PRINT_WARN("todo error");
		//send NACK to send handler
		tcp_conn_send_exec_reply(conn, serial_num, TCP_EXEC_SEND, FCF_FALSE, 0);
		free(called_data);
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);
}

void tcp_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct tcp_data *md = (struct tcp_data *) module->data;

	//receiving straight data from the APP layer, process/package into segment
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_port;
	uint32_t dst_port;

	uint32_t flags;
	uint32_t serial_num;

	secure_metadata_readFromElement(ff->metaData, "flags", &flags);
	secure_metadata_readFromElement(ff->metaData, "serial_num", &serial_num);

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "send_family", &family);
	//host
	secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
	secure_metadata_readFromElement(ff->metaData, "send_src_port", &src_port);
	//remote
	secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);
	secure_metadata_readFromElement(ff->metaData, "send_dst_port", &dst_port);

	//TODO if flags & MSG_DONTWAIT, read timeout

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	uint16_t test_src_port = (uint16_t) src_port;
	uint16_t test_dst_port = (uint16_t) dst_port;
	struct tcp_conn *conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &src_ip, &test_src_port, &dst_ip, &test_dst_port); //TODO check if right
	int start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	if (conn) {
		if (start) {
			tcp_write(module, conn, ff->dataFrame.pduLength, ff->dataFrame.pdu, flags, serial_num);
			ff->dataFrame.pdu = NULL;
		} else {
			PRINT_ERROR("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		//TODO error
		PRINT_WARN("todo error");

		//TODO LISTEN: if SEND, SYN, SYN_SENT
	}

	freeFinsFrame(ff);
}

void tcp_close(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p", conn, ff);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_seg *seg;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		if (conn->state == TS_ESTABLISHED || conn->state == TS_SYN_RECV) {
			//if CLOSE, send FIN, FIN_WAIT_1
			PRINT_DEBUG("CLOSE, send FIN, FIN_WAIT_1: state=%d, conn=%p", conn->state, conn);
			conn->state = TS_FIN_WAIT_1;

			module_reply_fcf(module, ff, FCF_TRUE, 0);

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			if (tcp_conn_is_finished(conn)) {
				//send FIN
				conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fsse = conn->send_seq_end + 1;
				PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
				tcp_seg_send(module, seg);
				tcp_seg_free(seg);

				//conn->send_seq_end++;

				//TODO add TO
			} //else piggy back it
		} else if (conn->state == TS_CLOSE_WAIT) {
			//if CLOSE_WAIT: CLOSE, send FIN, LAST_ACK
			PRINT_DEBUG("CLOSE_WAIT: CLOSE, send FIN, LAST_ACK: state=%d, conn=%p", conn->state, conn);
			conn->state = TS_LAST_ACK;

			module_reply_fcf(module, ff, FCF_TRUE, 0);

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			PRINT_DEBUG("request_queue->len=%u, write_queue->len=%u", conn->request_queue->len, conn->write_queue->len);
			if (tcp_conn_is_finished(conn)) {
				//send FIN
				conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fsse = conn->send_seq_end + 1;
				PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
				tcp_seg_send(module, seg);
				tcp_seg_free(seg);

				//conn->send_seq_end++;

				//TODO add TO
			} //else piggy back it
		} else if (conn->state == TS_SYN_SENT) {
			//if CLOSE, send -, CLOSED
			PRINT_DEBUG("SYN_SENT: CLOSE, send -, CLOSED: state=%d, conn=%p", conn->state, conn);
			conn->state = TS_CLOSED;

			/*
			 if (conn->ff) {
			 module_reply_fcf(conn->ff, 0, 0); //send NACK about connect call
			 conn->ff = NULL;
			 } else {
			 PRINT_WARN("todo error");
			 }
			 */

			module_reply_fcf(module, ff, FCF_TRUE, 0); //TODO check move to end of last_ack/start of time_wait?

			tcp_conn_shutdown(conn);
		} else if (conn->state == TS_CLOSED || conn->state == TS_TIME_WAIT) {
			if (conn->state == TS_CLOSED) {
				PRINT_DEBUG("CLOSED: CLOSE, -, CLOSED: state=%d, conn=%p", conn->state, conn);
			} else {
				PRINT_DEBUG("TIME_WAIT: CLOSE, -, TIME_WAIT: state=%d, conn=%p", conn->state, conn);
			}
			module_reply_fcf(module, ff, FCF_TRUE, 0);
		} else {
			PRINT_WARN("todo error");

			PRINT_DEBUG("conn=%p, state=%u", conn, conn->state);
			//TODO figure out:
		}
	} else {
		//TODO figure out: conn shutting down already?
		PRINT_WARN("todo error");
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);
}

void tcp_exec_close(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	struct tcp_conn *conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &host_ip, &host_port, &rem_ip, &rem_port);
	if (conn) {
		if (conn->threads < TCP_THREADS_MAX) {
			conn->threads++;
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);

			tcp_close(module, conn, ff);
		} else {
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);

			PRINT_ERROR("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		PRINT_WARN("todo error");
		PRINT_DEBUG("conn_list post***************");
		sem_post(&md->conn_list_sem);
		//TODO error trying to close closed connection
	}
}

void tcp_close_stub(struct fins_module *module, struct tcp_conn_stub *conn_stub, struct finsFrame *ff, uint32_t send_ack) {
	PRINT_DEBUG("Entered: conn_stub=%p, ff=%p, send_ack=%u", conn_stub, ff, send_ack);

	PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	secure_sem_wait(&conn_stub->sem);

	if (conn_stub->running_flag) {
		tcp_conn_stub_shutdown(conn_stub);

		//send ACK to close handler
		if (send_ack != 0) {
			module_reply_fcf(module, ff, FCF_TRUE, 0);
		}

		tcp_conn_stub_free(conn_stub);
	} else {
		PRINT_WARN("todo error");
		//send NACK to close handler
		if (send_ack != 0) {
			module_reply_fcf(module, ff, FCF_FALSE, 0);
		}
	}

	//TODO add conn_stub->threads--?
}

void tcp_exec_close_stub(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port) {
	PRINT_DEBUG("Entered: host=%u:%u", host_ip, host_port);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
	if (conn_stub) {
		list_remove(md->conn_stub_list, conn_stub);
		if (conn_stub->threads < TCP_THREADS_MAX) {
			conn_stub->threads++;
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);

			tcp_close_stub(module, conn_stub, ff, 1);
		} else {
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);

			PRINT_ERROR("Too many threads=%d. Dropping...", conn_stub->threads);
		}
	} else {
		PRINT_WARN("todo error");
		PRINT_DEBUG("conn_stub_list post***************");
		sem_post(&md->conn_stub_list_sem);
		//TODO error
	}
}

void tcp_exec_listen(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t backlog) {
	PRINT_DEBUG("Entered: addr=%u:%u, backlog=%u", host_ip, host_port, backlog);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	//TODO change from conn_stub to conn in listen
	struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
	if (conn_stub == NULL) {
		if (list_has_space(md->conn_stub_list)) {
			conn_stub = tcp_conn_stub_create(module, host_ip, host_port, backlog);
			list_append(md->conn_stub_list, conn_stub);

			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);
			//TODO throw minor error
		}
	} else {
		PRINT_WARN("todo error");
		PRINT_DEBUG("conn_stub_list post***************");
		sem_post(&md->conn_stub_list_sem);
		//TODO error
	}

	//TODO send ACK to listen handler - don't? have nonblocking
	freeFinsFrame(ff);
}

void *tcp_accept_thread(void *local) { //this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	uint32_t id = thread_data->id;
	struct tcp_conn_stub *conn_stub = thread_data->conn_stub;
	uint32_t flags = thread_data->flags;
	struct finsFrame *ff = thread_data->ff;
	free(thread_data);

	PRINT_DEBUG("Entered: id=%u", id);
	struct tcp_data *md = (struct tcp_data *) conn_stub->module->data;

	struct tcp_node *node;
	struct tcp_seg *seg;
	struct tcp_conn *conn;
	struct tcp_seg *temp_seg;

	PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	secure_sem_wait(&conn_stub->sem);
	while (conn_stub->running_flag) {
		if (!tcp_queue_is_empty(conn_stub->syn_queue)) {
			node = tcp_queue_remove_front(conn_stub->syn_queue);
			PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
			sem_post(&conn_stub->sem);

			seg = (struct tcp_seg *) node->data;

			PRINT_DEBUG("conn_list wait***************");
			secure_sem_wait(&md->conn_list_sem);
			conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &seg->dst_ip, &seg->dst_port, &seg->src_ip, &seg->src_port);
			if (conn == NULL) {
				if (list_has_space(md->conn_list)) {
					conn = tcp_conn_create(conn_stub->module, seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
					list_append(md->conn_list, conn);

					conn->threads++;
					PRINT_DEBUG("conn_list post***************");
					sem_post(&md->conn_list_sem);
					conn->module = conn_stub->module;

					PRINT_DEBUG("sem_wait: conn=%p", conn);
					secure_sem_wait(&conn->sem);
					if (conn->running_flag) { //LISTENING state
						//if SYN, send SYN ACK, SYN_RECV
						PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
						conn->state = TS_SYN_RECV;
						conn->active_open = 0;
						conn->ff = ff;
						conn->poll_events = conn_stub->poll_events; //TODO specify more

						if (flags & (1)) {
							//TODO do specific flags/settings
						}

						conn->issn = tcp_rand();
						conn->send_seq_num = conn->issn;
						conn->send_seq_end = conn->send_seq_num;
						conn->send_max_win = (uint32_t) seg->win_size;
						conn->send_win = conn->send_max_win;

						conn->irsn = seg->seq_num;
						conn->recv_seq_num = seg->seq_num + 1;
						conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

						PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
								conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

						//TODO process options, decide: MSS, max window size!!
						//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

						if (seg->opt_len) {
							tcp_process_options(conn, seg);
						}

						//conn_change_options(conn, tcp->options, SYN);

						//send SYN ACK
						temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
						tcp_seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
						tcp_seg_send(conn->module, temp_seg);
						tcp_seg_free(temp_seg);

						//timer_once_start(conn->to_gbn_data->tid, TCP_MSL_TO_DEFAULT);
						conn->timeout = TCP_GBN_TO_MIN;
						timer_once_start(conn->to_gbn_data->tid, TCP_GBN_TO_MIN); //TODO figure out to's
						conn->to_gbn_flag = 0;
					} else {
						PRINT_WARN("todo error");
						//TODO error
					}

					PRINT_DEBUG("conn_list wait***************");
					secure_sem_wait(&md->conn_list_sem);
					conn->threads--;
					PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
					PRINT_DEBUG("conn_list post***************");
					sem_post(&md->conn_list_sem);

					PRINT_DEBUG("sem_post: conn=%p", conn);
					sem_post(&conn->sem);

					tcp_seg_free(seg);
					free(node);
					break;
				} else {
					PRINT_WARN("todo error");
					PRINT_DEBUG("conn_list post***************");
					sem_post(&md->conn_list_sem);
					//TODO throw minor error
				}
			} else {
				PRINT_WARN("todo error");
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);
				//TODO error
			}

			tcp_seg_free(seg);
			free(node);
		} else {
			PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
			sem_post(&conn_stub->sem);

			/*#*/PRINT_DEBUG("");
			secure_sem_wait(&conn_stub->accept_wait_sem);
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem");
		}

		PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
		secure_sem_wait(&conn_stub->sem);
	}

	if (!conn_stub->running_flag) {
		PRINT_WARN("todo error");
		//conn_stub_send_daemon(conn_stub, TCP_EXEC_ACCEPT, 0, 0);
		module_reply_fcf(conn_stub->module, ff, FCF_FALSE, 0);
	}

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	PRINT_DEBUG("conn_stub_list post***************");
	sem_post(&md->conn_stub_list_sem);

	PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);

	PRINT_DEBUG("Exited: id=%u", id);
	return NULL;
}

void tcp_exec_accept(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t flags) {
	PRINT_DEBUG("Entered: host=%u:%u, flags=0x%x", host_ip, host_port, flags);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
	if (conn_stub != NULL) {
		if (conn_stub->threads < TCP_THREADS_MAX) {
			conn_stub->threads++;
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);

			struct tcp_thread_data *thread_data = (struct tcp_thread_data *) secure_malloc(sizeof(struct tcp_thread_data));
			thread_data->id = tcp_gen_thread_id(module);
			thread_data->conn_stub = conn_stub;
			thread_data->ff = ff;
			thread_data->flags = flags;

			pthread_t thread;
			secure_pthread_create(&thread, NULL, tcp_accept_thread, (void *) thread_data);
			pthread_detach(thread);
		} else {
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);

			PRINT_ERROR("Too many threads=%d. Dropping...", conn_stub->threads);
			//TODO send NACK
		}
	} else {
		PRINT_WARN("todo error");
		PRINT_DEBUG("conn_stub_list post***************");
		sem_post(&md->conn_stub_list_sem);
		//TODO error, no listening stub

		//send NACK to accept handler
		module_reply_fcf(module, ff, FCF_FALSE, 1);
	}
}

void tcp_connect(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff, uint32_t flags) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p, flags=%u", conn, ff, flags);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_seg *temp_seg;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		if (conn->state == TS_CLOSED || conn->state == TS_LISTEN) {
			//if CONNECT, send SYN, SYN_SENT
			if (conn->state == TS_CLOSED) {
				PRINT_DEBUG("CLOSED: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			} else {
				PRINT_DEBUG("LISTEN: CONNECT, send SYN, SYN_SENT: state=%d", conn->state);
			}
			conn->state = TS_SYN_SENT;
			conn->active_open = 1;
			conn->ff = ff;

			if (flags & (1)) {
				//TODO do specific flags/settings
			}

			conn->issn = tcp_rand();
			conn->send_seq_num = conn->issn;
			conn->send_seq_end = conn->send_seq_num;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//TODO add options, for: MSS, max window size!!
			//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

			//conn_change_options(conn, tcp->options, SYN);

			//send SYN
			temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
			tcp_seg_update(temp_seg, conn, FLAG_SYN);
			tcp_seg_send(module, temp_seg);
			tcp_seg_free(temp_seg);

			conn->timeout = TCP_GBN_TO_DEFAULT;
			//startTimer(conn->to_gbn_fd, conn->timeout); //TODO fix
		} else {
			//TODO error
			PRINT_WARN("todo error");
			module_reply_fcf(module, ff, FCF_FALSE, 0);
		}
	} else {
		PRINT_WARN("todo error");
		//send NACK to connect handler
		module_reply_fcf(module, ff, FCF_FALSE, 1);
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);
}

void tcp_exec_connect(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port,
		uint32_t flags) {
	PRINT_DEBUG("Entered: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	struct tcp_conn *conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &host_ip, &host_port, &rem_ip, &rem_port);
	if (conn == NULL) {
		if (list_has_space(md->conn_list)) {
			conn = tcp_conn_create(module, host_ip, host_port, rem_ip, rem_port);
			list_append(md->conn_list, conn);

			conn->threads++;
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);
			conn->module = module;

			//if listening stub remove
			PRINT_DEBUG("conn_stub_list wait***************");
			secure_sem_wait(&md->conn_stub_list_sem);
			struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
			if (conn_stub) {
				list_remove(md->conn_stub_list, conn_stub);
				if (conn_stub->threads < TCP_THREADS_MAX) {
					conn_stub->threads++;
					PRINT_DEBUG("conn_stub_list post***************");
					sem_post(&md->conn_stub_list_sem);

					tcp_close_stub(module, conn_stub, NULL, 0);
				} else {
					PRINT_DEBUG("conn_stub_list post***************");
					sem_post(&md->conn_stub_list_sem);

					PRINT_ERROR("error");
				}
			} else {
				PRINT_DEBUG("conn_stub_list post***************");
				sem_post(&md->conn_stub_list_sem);
			}

			tcp_connect(module, conn, ff, flags);
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);

			//TODO throw minor error, list full
			//TODO send NACK
		}
	} else {
		PRINT_WARN("todo error");
		PRINT_DEBUG("conn_list post***************");
		sem_post(&md->conn_list_sem);

		//TODO error, existing connection already connected there
		//TODO send NACK?
	}
}

void tcp_poll(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff, uint32_t initial, uint32_t events) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p,  initial=0x%x, events=0x%x", conn, ff, initial, events);
	struct tcp_data *md = (struct tcp_data *) module->data;

	uint32_t mask = 0;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		//TODO redo, for now mostly does POLLOUT

		if (events & (POLLERR)) {
			//TODO errors
		}

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) { //TODO remove - handled by daemon
			//mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?

			//add a check to see if conn moves to CLOSE_WAIT, post: POLLHUP
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			if (tcp_queue_is_empty(conn->request_queue)) {
				int space = conn->write_queue->max - conn->write_queue->len;
				if (space > 0) {
					mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
				} else {
					if (initial) {
						conn->poll_events |= (POLLOUT | POLLWRNORM | POLLWRBAND);
						PRINT_DEBUG("adding: poll_events=0x%x", conn->poll_events);
					} else {
						conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
						PRINT_DEBUG("removing: poll_events=0x%x", conn->poll_events);
					}
				}
			} else {
				if (initial) {
					conn->poll_events |= (POLLOUT | POLLWRNORM | POLLWRBAND);
					PRINT_DEBUG("adding: poll_events=0x%x", conn->poll_events);
				} else {
					conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
					PRINT_DEBUG("removing: poll_events=0x%x", conn->poll_events);
				}
			}
		}

		if (events & (POLLHUP)) {
			//TODO errors
		}

		module_reply_fcf(module, ff, FCF_TRUE, mask);
	} else {
		PRINT_WARN("todo error");
		module_reply_fcf(module, ff, FCF_TRUE, POLLHUP); //TODO check on value?
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);
}

void tcp_poll_stub(struct fins_module *module, struct tcp_conn_stub *conn_stub, struct finsFrame *ff, uint32_t initial, uint32_t events) {
	PRINT_DEBUG("Entered: conn_stub=%p, ff=%p,  initial=0x%x, events=0x%x", conn_stub, ff, initial, events);
	struct tcp_data *md = (struct tcp_data *) module->data;

	uint32_t mask = 0;

	PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	secure_sem_wait(&conn_stub->sem);
	if (conn_stub->running_flag) {
		//TODO redo, for now mostly does POLLOUT

		if (events & (POLLERR)) {
			//TODO errors
		}

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) { //TODO remove - handled by daemon
			//mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?

			//add a check to see if conn moves to CLOSE_WAIT, post: POLLHUP
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			int val = 0;
			//val = conn_stub->
			//sem_getvalue(&conn->write_sem, &val);
			//PRINT_DEBUG("conn_stub=%p, conn->write_sem=%d", conn_stub, val);

			if (val) {
				mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
			} else {
				if (initial) {
					conn_stub->poll_events |= (POLLOUT | POLLWRNORM | POLLWRBAND);
				} else {
					conn_stub->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
				}
			}
		}

		if (events & (POLLHUP)) {
			//TODO errors
		}

		module_reply_fcf(module, ff, FCF_TRUE, mask);
	} else {
		PRINT_WARN("todo error");
		module_reply_fcf(module, ff, FCF_TRUE, POLLHUP); //TODO check on value?
	}

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	PRINT_DEBUG("conn_stub_list post***************");
	sem_post(&md->conn_stub_list_sem);

	PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);
}

void tcp_exec_poll(struct fins_module *module, struct finsFrame *ff, socket_state state, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip,
		uint16_t rem_port, uint32_t initial, uint32_t flags) {
	PRINT_DEBUG("Entered: host=%u:%u, rem=%u:%u, initial=%u, flags=%u", host_ip, host_port, rem_ip, rem_port, initial, flags);
	struct tcp_data *md = (struct tcp_data *) module->data;

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("Entered: state=%u, host=%u:%u, rem=%u:%u, initial=%u, events=0x%x", state, host_ip, host_port, rem_ip, rem_port, initial, flags);
		PRINT_DEBUG("conn_list wait***************");
		secure_sem_wait(&md->conn_list_sem);
		struct tcp_conn *conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &host_ip, &host_port, &rem_ip, &rem_port);
		if (conn) {
			if (conn->threads < TCP_THREADS_MAX) {
				conn->threads++;
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);

				tcp_poll(module, conn, ff, initial, flags);
			} else {
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);

				PRINT_ERROR("Too many threads=%d. Dropping...", conn->threads);
				module_reply_fcf(module, ff, FCF_TRUE, POLLERR); //TODO check on value?
			}
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);
			//TODO error

			module_reply_fcf(module, ff, FCF_TRUE, POLLERR); //TODO check on value?
		}
	} else {
		PRINT_DEBUG("Entered: state=%u, host=%u:%u, initial=%u, flags=%u", state, host_ip, host_port, initial, flags);
		PRINT_DEBUG("conn_stub_list wait***************");
		secure_sem_wait(&md->conn_stub_list_sem);
		struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
		if (conn_stub) {
			if (conn_stub->threads < TCP_THREADS_MAX) {
				conn_stub->threads++;
				PRINT_DEBUG("conn_stub_list post***************");
				sem_post(&md->conn_stub_list_sem);

				tcp_poll_stub(module, conn_stub, ff, initial, flags);
			} else {
				PRINT_DEBUG("conn_stub_list post***************");
				sem_post(&md->conn_stub_list_sem);

				PRINT_ERROR("Too many threads=%d. Dropping...", conn_stub->threads);
				module_reply_fcf(module, ff, FCF_TRUE, POLLERR); //TODO check on value?
			}
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);
			//TODO error

			module_reply_fcf(module, ff, FCF_TRUE, POLLERR); //TODO check on value?
		}
	}
}

void tcp_conn_alert(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p", conn, ff);

	uint32_t value = 0;

	switch (ff->ctrlFrame.param_id) { //TODO optimize this code better when control format is fully fleshed out
	case TCP_ALERT_SHUTDOWN:
		PRINT_DEBUG("param_id=TCP_ALERT_SHUTDOWN (%d)", ff->ctrlFrame.param_id);
		secure_metadata_readFromElement(ff->metaData, "value", &value);
		PRINT_DEBUG("value=%u", value);

		if (value == TCP_STATUS_RD) {
			//TODO RD, handled at daemon
			conn->status &= ~value;
		} else if (value == TCP_STATUS_WR || value == TCP_STATUS_RDWR) {
			//TODO if WR, send FIN
			conn->status &= ~value;
			struct tcp_seg *seg;

			if (conn->state == TS_ESTABLISHED || conn->state == TS_SYN_RECV) {
				//if SHUT_WR, send FIN, FIN_WAIT_1
				PRINT_DEBUG("SHUT_WR, send FIN, FIN_WAIT_1: state=%d, conn=%p", conn->state, conn);
				conn->state = TS_FIN_WAIT_1;

				module_reply_fcf(module, ff, FCF_TRUE, 0);

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				if (tcp_conn_is_finished(conn)) {
					//send FIN
					conn->fin_sent = 1;
					conn->fin_sep = 1;
					conn->fsse = conn->send_seq_end + 1;
					PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

					seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
					tcp_seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
					tcp_seg_send(module, seg);
					tcp_seg_free(seg);

					//conn->send_seq_end++;

					//TODO add TO
				} //else piggy back it
			} else if (conn->state == TS_CLOSE_WAIT) {
				//if CLOSE_WAIT: SHUT_WR, send FIN, LAST_ACK
				PRINT_DEBUG("CLOSE_WAIT: SHUT_WR, send FIN, LAST_ACK: state=%d, conn=%p", conn->state, conn);
				conn->state = TS_LAST_ACK;

				module_reply_fcf(module, ff, FCF_TRUE, 0);

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				PRINT_DEBUG("request_queue->len=%u, write_queue->len=%u", conn->request_queue->len, conn->write_queue->len);
				if (tcp_conn_is_finished(conn)) {
					//send FIN
					conn->fin_sent = 1;
					conn->fin_sep = 1;
					conn->fsse = conn->send_seq_end + 1;
					PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

					seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
					tcp_seg_update(seg, conn, FLAG_FIN | FLAG_ACK);
					tcp_seg_send(module, seg);
					tcp_seg_free(seg);

					//conn->send_seq_end++;

					//TODO add TO
				} //else piggy back it
			} else if (conn->state == TS_SYN_SENT) {
				//if SHUT_WR, send -, CLOSED
				PRINT_DEBUG("SYN_SENT: SHUT_WR, send -, CLOSED: state=%d, conn=%p", conn->state, conn);
				conn->state = TS_CLOSED;

				/*
				 if (conn->ff) {
				 module_reply_fcf(conn->ff, 0, 0); //send NACK about connect call
				 conn->ff = NULL;
				 } else {
				 PRINT_WARN("todo error");
				 }
				 */

				module_reply_fcf(module, ff, FCF_TRUE, 0); //TODO check move to end of last_ack/start of time_wait?

				tcp_conn_shutdown(conn);
			} else if (conn->state == TS_CLOSED || conn->state == TS_TIME_WAIT) {
				if (conn->state == TS_CLOSED) {
					PRINT_DEBUG("CLOSED: SHUT_WR, -, CLOSED: state=%d, conn=%p", conn->state, conn);
				} else {
					PRINT_DEBUG("TIME_WAIT: SHUT_WR, -, TIME_WAIT: state=%d, conn=%p", conn->state, conn);
				}
				module_reply_fcf(module, ff, FCF_TRUE, 0);
			} else {
				PRINT_WARN("todo error");

				PRINT_DEBUG("conn=%p, state=%u", conn, conn->state);
				//TODO figure out:
			}
		} else {
			PRINT_WARN("todo error");
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_conn_read_param(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p", conn, ff);

	switch (ff->ctrlFrame.param_id) { //TODO optimize this code better when control format is fully fleshed out
	case TCP_GET_HOST_WINDOW:
		PRINT_DEBUG("param_id=TCP_GET_HOST_WINDOW (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_TRUE, conn->recv_win);
		break;
	case TCP_GET_SOCK_OPT:
		PRINT_DEBUG("param_id=TCP_GET_SOCK_OPT (%d)", ff->ctrlFrame.param_id);
		//fill in with switch of opts? or have them separate?

		//TODO read sock opts
		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_conn_set_param(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p", conn, ff);

	uint32_t value = 0;

	switch (ff->ctrlFrame.param_id) { //TODO optimize this code better when control format is fully fleshed out
	case TCP_SET_HOST_WINDOW:
		PRINT_DEBUG("param_id=TCP_SET_HOST_WINDOW (%d)", ff->ctrlFrame.param_id);
		secure_metadata_readFromElement(ff->metaData, "value", &value);
		PRINT_DEBUG("value=%u", value);
		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u), before",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
		uint32_increase(&conn->recv_win, value, conn->recv_max_win);
		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u), after",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		if (conn->flow_stopped == 1) {
			conn->flow_stopped = 0;
			//Send keep-alive ACK to other side of

			struct tcp_seg *seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
			tcp_seg_update(seg, conn, FLAG_ACK);
			tcp_seg_send(module, seg);
			tcp_seg_free(seg);
		}

		if (0) {
			module_reply_fcf(module, ff, FCF_TRUE, value);
		} else {
			freeFinsFrame(ff);
		}
		break;
	case TCP_SET_SOCK_OPT:
		PRINT_DEBUG("param_id=TCP_SET_SOCK_OPT (%d)", ff->ctrlFrame.param_id);
		//fill in with switch of opts? or have them separate?

		PRINT_WARN("todo");

		if (0) {
			module_reply_fcf(module, ff, FCF_TRUE, value);
		} else {
			freeFinsFrame(ff);
		}
		break;
	case TCP_SET_PARAM_STATUS:
		//TODO shutdown RD / WR
		//TODO if WR, send FIN
		//TODO RD, handled at daemon
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_conn_fcf(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p", conn, ff);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		switch (ff->ctrlFrame.opcode) {
		case CTRL_ALERT:
			PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
			tcp_conn_alert(module, conn, ff);
			break;
		case CTRL_ALERT_REPLY:
			PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_READ_PARAM:
			PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
			tcp_conn_read_param(module, conn, ff);
			break;
		case CTRL_READ_PARAM_REPLY:
			PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_SET_PARAM:
			PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
			tcp_conn_set_param(module, conn, ff);
			break;
		case CTRL_SET_PARAM_REPLY:
			PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_EXEC:
			PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
			PRINT_WARN("todo");
			module_reply_fcf(module, ff, FCF_FALSE, 0);
			break;
		case CTRL_EXEC_REPLY:
			PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_ERROR:
			PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
			tcp_error(module, ff);
			break;
		default:
			PRINT_ERROR("opcode=default (%d)", ff->ctrlFrame.opcode);
			exit(-1);
			break;
		}
	} else {
		PRINT_WARN("todo error");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	conn->threads--;
	PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn, conn->threads);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_DEBUG("sem_post: conn=%p", conn);
	sem_post(&conn->sem);
}

void tcp_conn_stub_read_param(struct fins_module *module, struct tcp_conn_stub *conn_stub, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn_stub=%p, ff=%p", conn_stub, ff);

	uint32_t value = 0;

	switch (ff->ctrlFrame.param_id) { //TODO optimize this code better when control format is fully fleshed out
	case TCP_GET_HOST_WINDOW:
		PRINT_DEBUG("param_id=TCP_GET_HOST_WINDOW (%d)", ff->ctrlFrame.param_id);
		//TODO do something? error?

		//if (value > conn_stub->host_window) {
		//conn_stub->host_window -= value;
		//} else {
		//conn_stub->host_window = 0;
		//}

		module_reply_fcf(module, ff, FCF_TRUE, value);
		break;
	case TCP_GET_SOCK_OPT:
		PRINT_DEBUG("param_id=TCP_GET_SOCK_OPT (%d)", ff->ctrlFrame.param_id);
		//fill in with switch of opts? or have them separate?

		//if (value > conn_stub->host_window) {
		//	conn_stub->host_window -= value;
		//} else {
		//	conn_stub->host_window = 0;
		//}

		module_reply_fcf(module, ff, FCF_TRUE, value);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_conn_stub_set_param(struct fins_module *module, struct tcp_conn_stub *conn_stub, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn_stub=%p, ff=%p", conn_stub, ff);

	uint32_t value = 0;

	switch (ff->ctrlFrame.param_id) { //TODO optimize this code better when control format is fully fleshed out
	case TCP_SET_HOST_WINDOW:
		PRINT_DEBUG("param_id=TCP_SET_HOST_WINDOW (%d)", ff->ctrlFrame.param_id);
		//TODO do something? error?

		//if (value > conn_stub->host_window) {
		//conn_stub->host_window -= value;
		//} else {
		//conn_stub->host_window = 0;
		//}

		module_reply_fcf(module, ff, FCF_TRUE, value);
		break;
	case TCP_SET_SOCK_OPT:
		PRINT_DEBUG("param_id=TCP_SET_SOCK_OPT (%d)", ff->ctrlFrame.param_id);
		//fill in with switch of opts? or have them separate?

		//if (value > conn_stub->host_window) {
		//	conn_stub->host_window -= value;
		//} else {
		//	conn_stub->host_window = 0;
		//}

		module_reply_fcf(module, ff, FCF_TRUE, value);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_conn_stub_fcf(struct fins_module *module, struct tcp_conn_stub *conn_stub, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: conn_stub=%p, ff=%p", conn_stub, ff);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	secure_sem_wait(&conn_stub->sem);
	if (conn_stub->running_flag) {
		switch (ff->ctrlFrame.opcode) {
		case CTRL_ALERT:
			PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
			PRINT_WARN("todo");
			module_reply_fcf(module, ff, FCF_FALSE, 0);
			break;
		case CTRL_ALERT_REPLY:
			PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_READ_PARAM:
			PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
			tcp_conn_stub_read_param(module, conn_stub, ff);
			break;
		case CTRL_READ_PARAM_REPLY:
			PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_SET_PARAM:
			PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
			tcp_conn_stub_set_param(module, conn_stub, ff);
			break;
		case CTRL_SET_PARAM_REPLY:
			PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_EXEC:
			PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
			PRINT_WARN("todo");
			module_reply_fcf(module, ff, FCF_FALSE, 0);
			break;
		case CTRL_EXEC_REPLY:
			PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
			PRINT_WARN("todo");
			freeFinsFrame(ff);
			break;
		case CTRL_ERROR:
			PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
			tcp_error(module, ff);
			break;
		default:
			PRINT_ERROR("opcode=default (%d)", ff->ctrlFrame.opcode);
			exit(-1);
			break;
		}
	} else {
		PRINT_WARN("todo error");
		module_reply_fcf(module, ff, FCF_FALSE, 0);
	}

	PRINT_DEBUG("conn_stub_list wait***************");
	secure_sem_wait(&md->conn_stub_list_sem);
	conn_stub->threads--;
	PRINT_DEBUG("leaving thread: conn_stub=%p, threads=%d", conn_stub, conn_stub->threads);
	PRINT_DEBUG("conn_stub_list post***************");
	sem_post(&md->conn_stub_list_sem);

	PRINT_DEBUG("sem_post: conn_stub=%p", conn_stub);
	sem_post(&conn_stub->sem);
}

void tcp_fcf_match(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct tcp_data *md = (struct tcp_data *) module->data;

	socket_state state = 0;
	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	tcp_metadata_read_conn(ff->metaData, &state, &host_ip, &host_port, &rem_ip, &rem_port);
	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("searching: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
		PRINT_DEBUG("conn_list wait***************");
		secure_sem_wait(&md->conn_list_sem);
		struct tcp_conn *conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &host_ip, &host_port, &rem_ip, &rem_port);
		if (conn) {
			if (conn->threads < TCP_THREADS_MAX) {
				conn->threads++;
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);

				tcp_conn_fcf(module, conn, ff);
			} else {
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);

				PRINT_ERROR("Too many threads=%d. Dropping...", conn->threads);
			}
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);

			//TODO error
			module_reply_fcf(module, ff, FCF_FALSE, 0);
		}
	} else { //unconnected
		PRINT_DEBUG("searching: host=%u:%u", host_ip, host_port);
		PRINT_DEBUG("conn_stub_list wait***************");
		secure_sem_wait(&md->conn_stub_list_sem);
		struct tcp_conn_stub *conn_stub = (struct tcp_conn_stub *) list_find2(md->conn_stub_list, tcp_conn_stub_addr_test, &host_ip, &host_port);
		if (conn_stub) {
			if (conn_stub->threads < TCP_THREADS_MAX) {
				conn_stub->threads++;
				PRINT_DEBUG("conn_stub_list post***************");
				sem_post(&md->conn_stub_list_sem);

				tcp_conn_stub_fcf(module, conn_stub, ff);
			} else {
				PRINT_DEBUG("conn_stub_list post***************");
				sem_post(&md->conn_stub_list_sem);

				PRINT_ERROR("Too many threads=%d. Dropping...", conn_stub->threads);
			}
		} else {
			PRINT_WARN("todo error");
			PRINT_DEBUG("conn_stub_list post***************");
			sem_post(&md->conn_stub_list_sem);

			//TODO error
			module_reply_fcf(module, ff, FCF_FALSE, 0);
		}
	}
}

void tcp_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct tcp_data *md = (struct tcp_data *) module->data;

	int32_t val_int32;
	//int64_t val_int64;
	//float val_float;

	switch (ff->ctrlFrame.param_id) {
	case TCP_GET_PARAM_FLOWS:
		PRINT_DEBUG("TCP_GET_PARAM_FLOWS");
		module_get_param_flows(module, ff);
		break;
	case TCP_GET_PARAM_LINKS:
		PRINT_DEBUG("TCP_GET_PARAM_LINKS");
		module_get_param_links(module, ff);
		break;
	case TCP_GET_PARAM_DUAL:
		PRINT_DEBUG("TCP_GET_PARAM_DUAL");
		module_get_param_dual(module, ff);
		break;
	case TCP_GET_HOST_WINDOW: //conn/conn_stub specific READ_PARAMS
	case TCP_GET_SOCK_OPT:
		PRINT_DEBUG("host_window or sock opt");
		tcp_fcf_match(module, ff);
		break;
	case TCP_GET_FAST_ENABLED__id:
		PRINT_DEBUG("TCP_GET_FAST_ENABLED");

		val_int32 = (uint32_t) md->fast_enabled;
		secure_metadata_writeToElement(ff->metaData, "value", &val_int32, META_TYPE_INT32);

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_GET_FAST_DUPLICATES__id:
		PRINT_DEBUG("TCP_GET_FAST_DUPLICATES");

		val_int32 = (uint32_t) md->fast_duplicates;
		secure_metadata_writeToElement(ff->metaData, "value", &val_int32, META_TYPE_INT32);

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_GET_FAST_RETRANSMITS__id:
		PRINT_DEBUG("TCP_GET_FAST_RETRANSMITS");

		//fast_retransmits
		val_int32 = (uint32_t) md->total_conn_stats.fast;
		secure_metadata_writeToElement(ff->metaData, "value", &val_int32, META_TYPE_INT32);

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_GET_MSS__id:
		PRINT_DEBUG("TCP_GET_MSS");

		val_int32 = (uint32_t) md->mss;
		secure_metadata_writeToElement(ff->metaData, "value", &val_int32, META_TYPE_INT32);

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	default:
		break;
	}
}

void tcp_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct tcp_data *md = (struct tcp_data *) module->data;

	int32_t val_int32;
	//int64_t val_int64;
	//float val_float;

	switch (ff->ctrlFrame.param_id) {
	case TCP_SET_PARAM_FLOWS:
		PRINT_DEBUG("TCP_SET_PARAM_FLOWS");
		module_set_param_flows(module, ff);
		break;
	case TCP_SET_PARAM_LINKS:
		PRINT_DEBUG("TCP_SET_PARAM_LINKS");
		module_set_param_links(module, ff);
		break;
	case TCP_SET_PARAM_DUAL:
		PRINT_DEBUG("TCP_SET_PARAM_DUAL");
		module_set_param_dual(module, ff);
		break;
	case TCP_SET_HOST_WINDOW: //conn/conn_stub specific SET_PARAMS
	case TCP_SET_SOCK_OPT:
	case TCP_SET_PARAM_STATUS:
		PRINT_DEBUG("conn/conn_stub SET_PARAM");
		tcp_fcf_match(module, ff);
		break;
	case TCP_SET_FAST_ENABLED__id:
		PRINT_DEBUG("TCP_SET_FAST_ENABLED");

		secure_metadata_readFromElement(ff->metaData, "value", &val_int32);
		md->fast_enabled = (uint8_t) val_int32;

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_SET_FAST_DUPLICATES__id:
		PRINT_DEBUG("TCP_SET_FAST_DUPLICATES");

		secure_metadata_readFromElement(ff->metaData, "value", &val_int32);
		md->fast_duplicates = (uint32_t) val_int32;

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_SET_FAST_RETRANSMITS__id:
		PRINT_DEBUG("TCP_SET_FAST_RETRANSMITS");

		secure_metadata_readFromElement(ff->metaData, "value", &val_int32);
		md->total_conn_stats.fast = (uint32_t) val_int32;

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	case TCP_SET_MSS__id:
		PRINT_DEBUG("TCP_SET_MSS");

		secure_metadata_readFromElement(ff->metaData, "value", &val_int32);
		md->mss = (uint32_t) val_int32;

		module_reply_fcf(module, ff, FCF_TRUE, 0);
		break;
	default:
		break;
	}
}
