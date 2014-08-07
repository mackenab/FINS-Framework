/*
 * @file tcp.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */
#include "tcp_internal.h"

//#include <arpa/inet.h>

struct tcp_node *tcp_node_create(uint8_t *data, uint32_t len, uint32_t seq_num, uint32_t seq_end) {
	PRINT_DEBUG("Entered: data=%p, len=%d, seq_num=%u, seq_end=%u", data, len, seq_num, seq_end);

	struct tcp_node *node = (struct tcp_node *) secure_malloc(sizeof(struct tcp_node));
	node->data = data;
	node->len = len;
	node->seq_num = seq_num;
	node->seq_end = seq_end;
	node->next = NULL;

	PRINT_DEBUG("Exited: data=%p, len=%d, seq_num=%u, seq_end=%u, node=%p", data, len, seq_num, seq_end, node);
	return node;
}

// assumes nodes are in window, -1=less than, 0=problem/equal, 1=greater
//edges touching/connecting between nodes are accepted
int tcp_node_compare(struct tcp_node *node, struct tcp_node *cmp, uint32_t win_seq_num, uint32_t win_seq_end) {
	// []=window, |=wrap around , ()=node, {}=cmp, ,=is in that region

	//TODO add time stamps to comparison
	PRINT_DEBUG("Entered: node: node=%p, seqs=(%u, %u); cmp: node=%p, seqs=(%u, %u); win: seqs=(%u, %u)",
			node, node->seq_num, node->seq_end, cmp, cmp->seq_num, cmp->seq_end, win_seq_num, win_seq_end);

	if (win_seq_num <= node->seq_num) { // [ ( |
		if (win_seq_num <= node->seq_end) { // [ () |
			if (win_seq_num <= cmp->seq_num) { // [ (),{ |
				if (win_seq_num <= cmp->seq_end) { // [ (),{} |
					if (node->seq_num < cmp->seq_num) { // [ ( { |
						if (node->seq_end <= cmp->seq_num) { // [ () { |
							PRINT_DEBUG("Exited: node=%p, -1", node);
							return -1;
						} else { // [ ( { ) |
							PRINT_DEBUG("Exited: node=%p, 0", node);
							return 0;
						}
					} else if (node->seq_num == cmp->seq_num) {
						PRINT_DEBUG("Exited: node=%p, 0", node);
						return 0;
					} else { // [ { ( |
						if (cmp->seq_end <= node->seq_num) { // [ {} ( |
							PRINT_DEBUG("Exited: node=%p, 1", node);
							return 1;
						} else { // [ { ( } |
							PRINT_DEBUG("Exited: node=%p, 0", node);
							return 0;
						}
					}
				} else { // [ (),{ | } ]
					if (node->seq_num < cmp->seq_num) { // [ ( { | } ]
						if (node->seq_end <= cmp->seq_num) { // [ () { | } ]
							PRINT_DEBUG("Exited: node=%p, -1", node);
							return -1;
						} else { // [ ( { ) | } ]
							PRINT_DEBUG("Exited: node=%p, 0", node);
							return 0;
						}
					} else { // [ { () | } ]
						PRINT_DEBUG("Exited: node=%p, 0", node);
						return 0;
					}
				}
			} else { // [ () | {} ]
				PRINT_DEBUG("Exited: node=%p, -1", node);
				return -1;
			}
		} else { // [ ( | ) ]
			if (win_seq_num <= cmp->seq_num) { // [ (,{ | ) ]
				if (node->seq_num <= cmp->seq_num) { // [ ( { | ) ]
					PRINT_DEBUG("Exited: node=%p, 0", node);
					return 0;
				} else { // [ { ( | ) ]
					if (cmp->seq_end <= node->seq_num) { // [ {} ( | ) ]
						PRINT_DEBUG("Exited: node=%p, 1", node);
						return 1;
					} else { // [ { ( } | ) ]
						PRINT_DEBUG("Exited: node=%p, 0", node);
						return 0;
					}
				}
			} else { // [ ( | {},) ]
				if (node->seq_end <= cmp->seq_num) { // [ ( | ) {} ]
					PRINT_DEBUG("Exited: node=%p, -1", node);
					return -1;
				} else { // [ ( | { ) ]
					PRINT_DEBUG("Exited: node=%p, 0", node);
					return 0;
				}
			}
		}
	} else { // [ | () ]
		if (win_seq_num <= cmp->seq_num) { // [ { | () ]
			if (win_seq_num <= cmp->seq_end) { // [ {} | () ]
				PRINT_DEBUG("Exited: node=%p, 1", node);
				return 1;
			} else { // [ { | },() ]
				if (cmp->seq_end <= node->seq_num) { // [ { | } () ]
					PRINT_DEBUG("Exited: node=%p, 1", node);
					return 1;
				} else { // [ { | ( } ]
					PRINT_DEBUG("Exited: node=%p, 0", node);
					return 0;
				}
			}
		} else { // [ | {},() ]
			if (node->seq_num < cmp->seq_num) { // [ | ( {} ]
				if (node->seq_end <= cmp->seq_num) { // [ | () {} ]
					PRINT_DEBUG("Exited: node=%p, -1", node);
					return -1;
				} else { // [ | ( { ) ]
					PRINT_DEBUG("Exited: node=%p, 0", node);
					return 0;
				}
			} else if (node->seq_num == cmp->seq_num) {
				PRINT_DEBUG("Exited: node=%p, 0", node);
				return 0;
			} else { // [ | { () ]
				if (cmp->seq_end <= node->seq_num) { // [ | {} () ]
					PRINT_DEBUG("Exited: node=%p, 1", node);
					return 1;
				} else { // [ | { ( } ]
					PRINT_DEBUG("Exited: node=%p, 0", node);
					return 0;
				}
			}
		}
	}
}

void tcp_node_free(struct tcp_node *node) {
	PRINT_DEBUG("Entered: node=%p", node);

	if (node->data) {
		free(node->data);
	}
	free(node);
}

struct tcp_queue *tcp_queue_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct tcp_queue *queue = (struct tcp_queue *) secure_malloc(sizeof(struct tcp_queue));
	queue->max = max;
	queue->len = 0;

	queue->front = NULL;
	queue->end = NULL;

	PRINT_DEBUG("Exited: max=%u, queue=%p", max, queue);
	return queue;
}

void tcp_queue_append(struct tcp_queue *queue, struct tcp_node *node) {
	PRINT_DEBUG("Entered: queue=%p, node=%p", queue, node);

	node->next = NULL;
	if (tcp_queue_is_empty(queue)) {
		//queue empty
		queue->front = node;
	} else {
		//node after end
		queue->end->next = node;
	}
	queue->end = node;
	queue->len += node->len;

	//queue_check(queue);
}

void tcp_queue_prepend(struct tcp_queue *queue, struct tcp_node *node) {
	PRINT_DEBUG("Entered: queue=%p, node=%p", queue, node);

	node->next = queue->front;
	if (tcp_queue_is_empty(queue)) {
		queue->end = node;
	}
	queue->front = node;
	queue->len += node->len;
}

void tcp_queue_add(struct tcp_queue *queue, struct tcp_node *node, struct tcp_node *prev) {
	PRINT_DEBUG("Entered: queue=%p, node=%p", queue, node);

	node->next = prev->next;
	prev->next = node;
	queue->len += node->len;
}

//assumes the node being inserted is in the window
int tcp_queue_insert(struct tcp_queue *queue, struct tcp_node *node, uint32_t win_seq_num, uint32_t win_seq_end) {
	PRINT_DEBUG("Entered: queue=%p, len=%u, node=%p, win_seq_num=%u, win_seq_end=%u", queue, queue->len, node, win_seq_num, win_seq_end);

	int ret;
	//queue_check(queue);

	//empty
	if (tcp_queue_is_empty(queue)) {
		tcp_queue_prepend(queue, node);

		//queue_check(queue);
		return 1;
	}

	//before front
	ret = tcp_node_compare(node, queue->front, win_seq_num, win_seq_end);
	if (ret == -1) { // [ <> () ] |
		tcp_queue_prepend(queue, node);

		//queue_check(queue);
		return 1;
	} else if (ret == 0) {

		//queue_check(queue);
		return 0;
	}

	//after end
	ret = tcp_node_compare(node, queue->end, win_seq_num, win_seq_end);
	if (ret == 1) { // [ {} <> ] |
		tcp_queue_append(queue, node);

		//queue_check(queue);
		return 1;
	} else if (ret == 0) {

		//queue_check(queue);
		return 0;
	}

	//iterate through queue
	struct tcp_node *temp_node = queue->front;
	while (temp_node->next) {
		ret = tcp_node_compare(node, temp_node->next, win_seq_num, win_seq_end);
		if (ret == -1) {
			tcp_queue_add(queue, node, temp_node);

			//queue_check(queue);
			return 1;
		} else if (ret == 0) {

			//queue_check(queue);
			return 0;
		}

		temp_node = temp_node->next;
	}

	//unable to insert, but didn't trip any overlaps - big error/not possible?
	PRINT_DEBUG("unreachable insert location: (%u, %u) [%u, %u]", node->seq_num, node->seq_end, win_seq_num, win_seq_end);
	return 0;
}

struct tcp_node *tcp_queue_find(struct tcp_queue *queue, uint32_t seq_num) {
	PRINT_DEBUG("Entered: queue=%p, seq_num=%u", queue, seq_num);

	struct tcp_node *comp = queue->front;
	while (comp) {
		if (comp->seq_num == seq_num) {
			return comp;
		} else {
			comp = comp->next;
		}
	}

	return NULL;
}

struct tcp_node *tcp_queue_remove_front(struct tcp_queue *queue) {
	PRINT_DEBUG("Entered: queue=%p", queue);

	struct tcp_node *node = queue->front;
	if (node) {
		queue->front = node->next;
		queue->len -= node->len;
	} else {
		PRINT_ERROR("resetting len");
		queue->len = 0;
	}

	//queue_check(queue);

	PRINT_DEBUG("Exited: queue=%p, len=%u, node=%p", queue, queue->len, node);
	return node;
}

void tcp_queue_remove(struct tcp_queue *queue, struct tcp_node *node) {
	PRINT_DEBUG("Entered: queue=%p, node=%p", queue, node);

	if (tcp_queue_is_empty(queue)) {
		//queue_check(queue);

		PRINT_DEBUG("Exited: queue=%p, len=%u", queue, queue->len);
		return;
	}

	if (queue->front == node) {
		queue->front = queue->front->next;
		queue->len -= node->len;

		//queue_check(queue);

		PRINT_DEBUG("Exited: queue=%p, len=%u", queue, queue->len);
		return;
	}

	struct tcp_node *temp = queue->front;
	while (temp->next != NULL) {
		if (temp->next == node) {
			if (queue->end == node) {
				queue->end = temp;
				temp->next = NULL;
			} else {
				temp->next = node->next;
			}

			queue->len -= node->len;

			//queue_check(queue);

			PRINT_DEBUG("Exited: queue=%p, len=%u", queue, queue->len);
			return;
		}
		temp = temp->next;
	}

	PRINT_DEBUG("Exited: queue=%p, len=%u", queue, queue->len);
}

int tcp_queue_check(struct tcp_queue *queue) { //TODO remove all references
	PRINT_DEBUG("Entered: queue=%p, len=%u", queue, queue->len);

	int count = 0;

	PRINT_DEBUG("front=%p, end=%p", queue->front, queue->end);

	struct tcp_node *temp = queue->front;
	while (temp && count <= queue->max) {
		count += temp->len;
		temp = temp->next;
	}

	if (count == queue->len) {
	} else {
		PRINT_ERROR("todo error: queue=%p, max=%u, len=%u, count=%u, check=%u", queue, queue->max, queue->len, count, count == queue->len);
		temp = queue->front;
		while (temp && count <= queue->max) {
			PRINT_DEBUG("count=%d, node=%p", count, temp);
			count += temp->len;
			temp = temp->next;
		}
	}

	PRINT_DEBUG("Exited: queue=%p, count=%u, check=%u", queue, count, count == queue->len);
	return count == queue->len;
}

int tcp_queue_is_empty(struct tcp_queue *queue) {
	return queue->front == NULL; //Use so can add 0 len nodes, signals/flags?
	//return queue->len == 0;
}

int tcp_queue_is_full(struct tcp_queue *queue) {
	return queue->len == queue->max;
}

int tcp_queue_has_space(struct tcp_queue *queue, uint32_t len) {
	return queue->len + len <= queue->max;
}

void tcp_queue_free(struct tcp_queue *queue) {
	PRINT_DEBUG("Entered: queue=%p", queue);

	struct tcp_node *next;

	struct tcp_node *node = queue->front;
	while (node) {
		next = node->next;
		tcp_node_free(node);
		node = next;
	}
	free(queue);
}

void handle_interrupt(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	if (tcp_queue_is_empty(conn->request_queue)) {
		PRINT_ERROR("todo error - minor");
	} else {
		struct tcp_node *temp_node;
		struct tcp_request *request;

		struct tcp_node *front = conn->request_queue->front;
		struct tcp_node *node = front;
		while (node) {
			request = (struct tcp_request *) node->data;
			if (request->to_flag) {
				temp_node = node;
				node = node->next;

				tcp_queue_remove(conn->request_queue, temp_node);

				if (temp_node == front && conn->request_index) {
					PRINT_DEBUG("TO'd, removing: request=%p, front, index=%d", request, conn->request_index);
					tcp_conn_send_exec_reply(module, conn, request->serial_num, TCP_EXEC_SEND, FCF_TRUE, conn->request_index);
					conn->request_index = 0;
				} else {
					PRINT_DEBUG("TO'd, removing: request=%p", request);
					tcp_conn_send_exec_reply(module, conn, request->serial_num, TCP_EXEC_SEND, FCF_FALSE, EAGAIN);
				}

				if (request->to_data) {
					timer_delete(request->to_data->tid);
					free(request->to_data);
				}

				free(request->data);
				free(request);
				free(temp_node);
			} else {
				node = node->next;
			}
		}
	}
}

void tcp_handle_requests(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	struct tcp_node *node;
	struct tcp_node *temp_node;
	struct tcp_request *request;
	int avail;
	uint8_t *buf;

	int space = conn->write_queue->max - (conn->write_queue->len - conn->write_index);
	while (space && !tcp_queue_is_empty(conn->request_queue)) {
		temp_node = conn->request_queue->front;
		request = (struct tcp_request *) temp_node->data;

		avail = request->len - conn->request_index;
		PRINT_DEBUG("space=%d, index=%d, len=%u, avail=%d", space, conn->request_index, request->len, avail);
		if (space < avail) {
			buf = (uint8_t *) secure_malloc(space);
			memcpy(buf, request->data + conn->request_index, space);
			conn->request_index += space;

			node = tcp_node_create(buf, space, conn->request_index - space, conn->request_index - 1);
			tcp_queue_append(conn->write_queue, node);

			space = 0;
			break;
		} else {
			buf = (uint8_t *) secure_malloc(avail);
			memcpy(buf, request->data + conn->request_index, avail);
			conn->request_index = 0;

			node = tcp_node_create(buf, avail, request->len - avail, request->len - 1);
			tcp_queue_append(conn->write_queue, node);

			space -= avail;

			tcp_queue_remove_front(conn->request_queue); // == to temp_node

			tcp_conn_send_exec_reply(module, conn, request->serial_num, TCP_EXEC_SEND, FCF_TRUE, request->len);

			if (request->to_data) {
				timer_delete(request->to_data->tid);
				free(request->to_data);
			}

			free(request->data);
			free(request);
			free(temp_node);
		}
	}

	if (conn->poll_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
		PRINT_DEBUG("conn=%p, space=%d", conn, space);
		if (space > 0) { //only possible if request_queue is empty
			tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_POLL, FCF_TRUE, POLLOUT | POLLWRNORM | POLLWRBAND);
			conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
			PRINT_DEBUG("poll: removing=0x%x, poll_events=0x%x", (POLLOUT | POLLWRNORM | POLLWRBAND), conn->poll_events);
		}
	}
}

void tcp_main_closed(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;
	}

	//wait
	conn->main_wait_flag = 1;
	PRINT_DEBUG("flagging waitFlag");

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_listen(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	//shouldn't happen? leave if combine stub/conn

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;
	}

	//wait
	conn->main_wait_flag = 1;
	PRINT_DEBUG("flagging waitFlag");

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_syn_sent(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;

		if (conn->timeout == TCP_GBN_TO_MAX) {
			//sent FF back saying failed to connect
			//send ACK to handler, prob accept
			if (conn->ff) {
				tcp_conn_reply_fcf(module, conn, conn->ff, FCF_FALSE, ETIMEDOUT); //accept needs rem ip/port
				conn->ff = NULL;
				tcp_conn_shutdown(conn);
				return;
			} else {
				PRINT_WARN("todo error");
			}
		}

		//TO, resend SYN, -
		conn->issn = tcp_rand();
		conn->send_seq_num = conn->issn;
		conn->send_seq_end = conn->send_seq_num;

		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		//TODO add options, for: MSS, max window size!!
		//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

		//conn_change_options(conn, tcp->options, SYN);

		//send SYN
		struct tcp_seg *temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
		tcp_seg_update(temp_seg, conn, FLAG_SYN);
		tcp_seg_send(module, temp_seg);
		tcp_seg_free(temp_seg);

		conn->main_wait_flag = 0; //handle cases where TO after set waitFlag

		conn->timeout = fmin(2.0 * conn->timeout, TCP_GBN_TO_MAX);
		timer_once_start(conn->to_gbn_data->tid, conn->timeout);
	} else {
		conn->main_wait_flag = 1;
		PRINT_DEBUG("flagging waitFlag");
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;
	}

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_syn_recv(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	//wait
	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;

		//TO, close connection, -
		if (conn->active_open) { //from connect
			//TO, resend SYN, SYN_SENT (?) //TODO check if correct

			conn->state = TS_SYN_SENT;
			conn->issn = tcp_rand();
			conn->send_seq_num = conn->issn;
			conn->send_seq_end = conn->send_seq_num;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//send SYN
			struct tcp_seg *temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
			tcp_seg_update(temp_seg, conn, FLAG_SYN);
			tcp_seg_send(module, temp_seg);
			tcp_seg_free(temp_seg);

			conn->main_wait_flag = 0; //handle cases where TO after set waitFlag

			conn->timeout = fmin(2.0 * conn->timeout, TCP_GBN_TO_MAX);
			timer_once_start(conn->to_gbn_data->tid, conn->timeout);
		} else { //from accept
			if (conn->timeout == TCP_MSL_TO_DEFAULT) {
				//sent FF back saying failed to connect
				//send ACK to handler, prob accept
				if (conn->ff) {
					//TODO change this to simply put self back into accept queue?
					tcp_conn_reply_fcf(module, conn, conn->ff, FCF_FALSE, ETIMEDOUT); //accept needs rem ip/port
					conn->ff = NULL;
					tcp_conn_shutdown(conn);
				} else {
					PRINT_WARN("todo error");
				}
			} else {
				//if TO, send SYN ACK, SYN_RECV
				PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
				//conn->issn = tcp_rand();
				//conn->send_seq_num = conn->issn;
				//conn->send_seq_end = conn->send_seq_num;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//TODO process options, decide: MSS, max window size!!
				//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

				//conn_change_options(conn, tcp->options, SYN);

				//send SYN ACK
				struct tcp_seg *temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
				tcp_seg_send(module, temp_seg);
				tcp_seg_free(temp_seg);

				conn->timeout = fmin(2.0 * conn->timeout, TCP_MSL_TO_DEFAULT);
				timer_once_start(conn->to_gbn_data->tid, conn->timeout); //TODO figure out to's
				conn->to_gbn_flag = 0;
			}
		}
	} else {
		conn->main_wait_flag = 1;
		PRINT_DEBUG("flagging waitFlag");
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;
	}

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_established(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	struct tcp_data *md = (struct tcp_data *) module->data;
	//can receive, send ACKs, send/resend data, & get ACKs

	struct tcp_seg *seg;
	uint32_t write_space;
	uint32_t flight_size;
	double recv_space;
	double cong_space;
	uint32_t data_len;
	struct tcp_node *temp_node;

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;

		handle_interrupt(module, conn);
	} else if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
		conn->stats.gbn++;
		__sync_add_and_fetch(&md->total_conn_stats.gbn, 1);

		//gbn timeout
		conn->first_flag = 0;
		conn->fast_flag = 0;

		if (tcp_queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
		} else {
			conn->gbn_flag = 1;

			//rtt
			conn->rtt_flag = 0;

			//cong control
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
			switch (conn->cong_state) {
			case RENO_SLOWSTART:
				conn->cong_state = RENO_AVOIDANCE;
				flight_size = conn->send_seq_end - conn->send_seq_num;
				conn->threshhold = fmax(flight_size / 2.0, 2.0 * conn->MSS);
				conn->cong_window = conn->threshhold + 3.0 * conn->MSS;
				break;
			case RENO_AVOIDANCE:
			case RENO_RECOVERY:
				conn->cong_state = RENO_SLOWSTART;
				conn->threshhold = (double) conn->send_max_win; //TODO fix?
				conn->cong_window = (double) conn->MSS;
				break;
			}
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);

			//resend first seg
			conn->gbn_node = conn->send_queue->front;

			seg = (struct tcp_seg *) conn->gbn_node->data;
			tcp_seg_update(seg, conn, FLAG_ACK);
			tcp_seg_send(module, seg);

			if (conn->recv_win == 0) {
				conn->flow_stopped = 1;
			}

			uint32_decrease(&conn->send_win, seg->data_len);
			//conn->timeout *= 2; //TODO uncomment, should have?
			timer_once_start(conn->to_gbn_data->tid, conn->timeout);
			conn->main_wait_flag = 0;

			conn->stats.timeout_total += conn->timeout;
			conn->stats.timeout_count++;
		}
	} else if (conn->fast_flag && md->fast_enabled) {
		conn->fast_flag = 0;
		conn->stats.fast++;
		__sync_add_and_fetch(&md->total_conn_stats.fast, 1);
		//fast retransmit

		if (!tcp_queue_is_empty(conn->send_queue)) {
			seg = (struct tcp_seg *) conn->send_queue->front->data;
			tcp_seg_update(seg, conn, FLAG_ACK);
			tcp_seg_send(module, seg);

			if (conn->recv_win == 0) {
				conn->flow_stopped = 1;
			}

			uint32_decrease(&conn->send_win, seg->data_len);
		}
	} else if (conn->gbn_flag) {
		//normal GBN
		if (tcp_queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
			conn->stats.gbn++;
			__sync_add_and_fetch(&md->total_conn_stats.gbn, 1);
		} else {
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//if (conn->send_win && cong_space > 0) { //TODO check if right
			//if (recv_space >= (double) conn->MSS && cong_space >= (double) conn->MSS) {
			if (recv_space > 1 && cong_space > 1) {
				//if (recv_space > 1) { //TODO remove, ignores cc
				if (conn->first_flag) {
					conn->gbn_node = conn->send_queue->front;
				} else {
					conn->gbn_node = conn->gbn_node->next;
				}

				if (conn->gbn_node) {
					seg = (struct tcp_seg *) conn->gbn_node->data;
					tcp_seg_update(seg, conn, FLAG_ACK);
					tcp_seg_send(module, seg);

					if (conn->recv_win == 0) {
						conn->flow_stopped = 1;
					}

					uint32_decrease(&conn->send_win, seg->data_len);
				} else {
					conn->gbn_flag = 0;
				}
			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("GBN: flagging waitFlag");
			}
		}
	} else {
		//normal
		PRINT_DEBUG("Normal");

		if (tcp_queue_is_empty(conn->request_queue) && tcp_queue_is_empty(conn->write_queue)) {
			conn->main_wait_flag = 1;
			PRINT_DEBUG("Normal: flagging waitFlag");
		} else {
			//handle_requests(conn);

			write_space = conn->write_queue->len - conn->write_index;
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//((struct tcp_request *) conn->request_queue->front->data)->len - conn->request_index;
			//PRINT_IMPORTANT("write=%u, flight=%u, recv=%f, cong=%f", write_space, flight_size, recv_space, cong_space);

			//if (conn->send_win && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			//if (conn->send_win_ack + conn->send_win > conn->send_seq_end && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			PRINT_DEBUG("write_space=%u, recv_space=%f, cong_space=%f", write_space, recv_space, cong_space);
			if (write_space > 0 && recv_space > 1 && cong_space > 1) { //TODO make sure is right!
			//if (write_space > 0 && recv_space > 1) { //TODO remove, ignores cc
				PRINT_DEBUG("sending packet");

				if (write_space > (uint32_t) conn->MSS) {
					data_len = (uint32_t) conn->MSS;
				} else {
					data_len = write_space;
				}
				if (data_len > (uint32_t) conn->send_win) { //leave for now, move to outside if for Nagle
					data_len = (uint32_t) conn->send_win;
				}
				if ((double) data_len > cong_space) { //TODO unneeded if (cong_space >= MSS) kept, keep if change to (cong_space > 0)
					data_len = (uint32_t) cong_space; //TODO check if converts fine //TODO uncomment, ignores cc
				}

				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				conn->write_index = tcp_seg_add_data(seg, conn->write_queue, conn->write_index, data_len);

				conn->stats.sent_data += data_len;
				PRINT_DEBUG("len=%u, sent_data=%llu", data_len, conn->stats.sent_data);

				tcp_handle_requests(module, conn);

				tcp_seg_update(seg, conn, FLAG_ACK);
				if (conn->temp_count++ == 4 && conn->temp_tries < 40 && 0) {
					conn->temp_tries++;
					conn->temp_count = 0;
				} else {
					tcp_seg_send(module, seg);
				}

				if (conn->recv_win == 0) {
					conn->flow_stopped = 1;
				}

				temp_node = tcp_node_create((uint8_t *) seg, data_len, seg->seq_num, seg->seq_num + data_len - 1);
				tcp_queue_append(conn->send_queue, temp_node);

				conn->send_seq_end += (uint32_t) data_len;
				uint32_decrease(&conn->send_win, data_len);

				if (conn->rtt_flag == 0) {
					gettimeofday(&conn->rtt_stamp, 0);
					conn->rtt_flag = 1;
					conn->rtt_seq_num = seg->seq_num;
					conn->rtt_seq_end = conn->send_seq_end;
					PRINT_DEBUG("setting seqEndRTT=%u, stampRTT=(%d, %d)", conn->rtt_seq_end, (int)conn->rtt_stamp.tv_sec, (int)conn->rtt_stamp.tv_usec);
				}

				if (conn->first_flag) {
					conn->first_flag = 0;
					timer_once_start(conn->to_gbn_data->tid, conn->timeout);
					conn->to_gbn_flag = 0;
				}

				if (conn->poll_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) { //TODO remove?
					if (tcp_queue_is_empty(conn->request_queue)) {
						int space = conn->write_queue->max - (conn->write_queue->len - conn->write_index);
						PRINT_DEBUG("conn=%p, space=%d", conn, space);
						if (space > 0) {
							tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_POLL, FCF_TRUE, POLLOUT | POLLWRNORM | POLLWRBAND);
							conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
							PRINT_DEBUG("poll: removing=0x%x, poll_events=0x%x", (POLLOUT | POLLWRNORM | POLLWRBAND), conn->poll_events);
						}
					}
				}
			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("Normal: flagging waitFlag");
			}
		}
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;

		//delayed ACK timeout, send ACK
		conn->delayed_flag = 0;

		//send ack
		//seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
		//tcp_seg_update(seg, conn, conn->delayed_ack_flags);
		//tcp_seg_send(module, seg);
		//tcp_seg_free(seg);

		conn->ack_seg->seq_num = conn->send_seq_end;
		conn->ack_seg->seq_end = conn->send_seq_end;
		tcp_seg_update(conn->ack_seg, conn, conn->delayed_ack_flags);
		tcp_seg_send(module, conn->ack_seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	}

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_fin_wait_1(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	struct tcp_data *md = (struct tcp_data *) module->data;
	//merge with established, can still get ACKs, receive, send ACKs, & send/resend data (don't accept new data)

	struct tcp_seg *seg;
	uint32_t write_space;
	uint32_t flight_size;
	double recv_space;
	double cong_space;
	uint32_t data_len;
	struct tcp_node *temp_node;

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;

		handle_interrupt(module, conn);
	} else if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
		conn->stats.gbn++;
		__sync_add_and_fetch(&md->total_conn_stats.gbn, 1);

		//gbn timeout
		conn->first_flag = 0;
		conn->fast_flag = 0;

		if (tcp_queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
			if (conn->fin_sent && tcp_conn_is_finished(conn)) {
				//conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fsse = conn->send_seq_end + 1;
				PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

				//send fin
				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				tcp_seg_send(module, seg);
				tcp_seg_free(seg);
			}
		} else {
			conn->gbn_flag = 1;

			//rtt
			conn->rtt_flag = 0;

			//cong control
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
			switch (conn->cong_state) {
			case RENO_SLOWSTART:
				conn->cong_state = RENO_AVOIDANCE;
				flight_size = conn->send_seq_end - conn->send_seq_num;
				conn->threshhold = fmax(flight_size / 2.0, 2.0 * conn->MSS);
				conn->cong_window = conn->threshhold + 3.0 * conn->MSS;
				break;
			case RENO_AVOIDANCE:
			case RENO_RECOVERY:
				conn->cong_state = RENO_SLOWSTART;
				conn->threshhold = (double) conn->send_max_win; //TODO fix?
				conn->cong_window = (double) conn->MSS;
				break;
			}
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);

			//resend first seg
			conn->gbn_node = conn->send_queue->front;
			seg = (struct tcp_seg *) conn->gbn_node->data;
			tcp_seg_update(seg, conn, FLAG_ACK);
			tcp_seg_send(module, seg);

			uint32_decrease(&conn->send_win, seg->data_len);
			//conn->timeout *= 2; //TODO uncomment, should have?
			timer_once_start(conn->to_gbn_data->tid, conn->timeout);
			conn->main_wait_flag = 0;

			conn->stats.timeout_total += conn->timeout;
			conn->stats.timeout_count++;
		}
	} else if (conn->fast_flag && md->fast_enabled) {
		conn->fast_flag = 0;
		conn->stats.fast++;
		__sync_add_and_fetch(&md->total_conn_stats.fast, 1);
		//fast retransmit

		if (!tcp_queue_is_empty(conn->send_queue)) {
			seg = (struct tcp_seg *) conn->send_queue->front->data;
			tcp_seg_update(seg, conn, FLAG_ACK);
			tcp_seg_send(module, seg);

			uint32_decrease(&conn->send_win, seg->data_len);
		}
	} else if (conn->gbn_flag) {
		//normal GBN
		if (tcp_queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
		} else {
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//if (conn->send_win && cong_space > 0) { //TODO check if right
			//if (recv_space >= (double) conn->MSS && cong_space >= (double) conn->MSS) {
			if (recv_space > 1 && cong_space > 1) {
				//if (recv_space > 1) { //TODO remove, ignores cc
				if (conn->first_flag) {
					conn->gbn_node = conn->send_queue->front;
				} else {
					conn->gbn_node = conn->gbn_node->next;
				}

				if (conn->gbn_node) {
					seg = (struct tcp_seg *) conn->gbn_node->data;
					tcp_seg_update(seg, conn, FLAG_ACK);
					tcp_seg_send(module, seg);

					uint32_decrease(&conn->send_win, seg->data_len);
				} else {
					conn->gbn_flag = 0;
				}
			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("GBN: flagging waitFlag");
			}
		}
	} else {
		//normal
		PRINT_DEBUG("Normal");

		if (tcp_queue_is_empty(conn->request_queue) && tcp_queue_is_empty(conn->write_queue)) {
			if (conn->fin_sent) {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("Normal: flagging waitFlag");
			} else {
				conn->fin_sent = 1;
				conn->fin_sep = 1;
				conn->fsse = conn->send_seq_end + 1;
				PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

				//send fin
				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				tcp_seg_send(module, seg);
				tcp_seg_free(seg);
			}
		} else {
			write_space = conn->write_queue->len - conn->write_index;
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//if (conn->send_win && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			//if (conn->send_win_ack + conn->send_win > conn->send_seq_end && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			PRINT_DEBUG("write_space=%u, recv_space=%f, cong_space=%f", write_space, recv_space, cong_space);
			if (write_space > 0 && recv_space > 1 && cong_space > 1) { //TODO make sure is right!
			//if (write_space > 0 && recv_space > 1) { //TODO remove, ignores cc
				PRINT_DEBUG("sending packet");

				if (write_space > (uint32_t) conn->MSS) {
					data_len = (uint32_t) conn->MSS;
				} else {
					data_len = write_space;
				}
				if (data_len > (uint32_t) conn->send_win) { //leave for now, move to outside if for Nagle
					data_len = (uint32_t) conn->send_win;
				}
				if ((double) data_len > cong_space) { //TODO unneeded if (cong_space >= MSS) kept, keep if change to (cong_space > 0)
					data_len = (uint32_t) cong_space; //TODO check if converts fine //TODO uncomment, ignores cc
				}

				seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				conn->write_index = tcp_seg_add_data(seg, conn->write_queue, conn->write_index, data_len);

				conn->stats.sent_data += data_len;
				PRINT_DEBUG("len=%u, sent_data=%llu", data_len, conn->stats.sent_data);

				tcp_handle_requests(module, conn);

				if (tcp_queue_is_empty(conn->request_queue) && tcp_queue_is_empty(conn->write_queue)) {
					conn->fin_sent = 1;
					conn->fin_sep = 0;
					conn->fsse = seg->seq_end + 1;
					PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

					tcp_seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				} else {
					tcp_seg_update(seg, conn, FLAG_ACK);
				}
				tcp_seg_send(module, seg);

				temp_node = tcp_node_create((uint8_t *) seg, data_len, seg->seq_num, seg->seq_num + data_len - 1);
				tcp_queue_append(conn->send_queue, temp_node);

				conn->send_seq_end += (uint32_t) data_len;
				uint32_decrease(&conn->send_win, data_len);

				if (conn->rtt_flag == 0) {
					gettimeofday(&conn->rtt_stamp, 0);
					conn->rtt_flag = 1;
					conn->rtt_seq_num = seg->seq_num;
					conn->rtt_seq_end = conn->send_seq_end;
					PRINT_DEBUG("setting seqEndRTT=%u, stampRTT=(%d, %d)", conn->rtt_seq_end, (int)conn->rtt_stamp.tv_sec, (int)conn->rtt_stamp.tv_usec);
				}

				if (conn->first_flag) {
					conn->first_flag = 0;
					timer_once_start(conn->to_gbn_data->tid, conn->timeout);
					conn->to_gbn_flag = 0;
				}

				if (conn->poll_events & (POLLOUT | POLLWRNORM | POLLWRBAND)) { //TODO remove?
					if (tcp_queue_is_empty(conn->request_queue)) {
						int space = conn->write_queue->max - (conn->write_queue->len - conn->write_index);
						PRINT_DEBUG("conn=%p, space=%d", conn, space);
						if (space > 0) {
							tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_POLL, FCF_TRUE, POLLOUT | POLLWRNORM | POLLWRBAND);
							conn->poll_events &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);
							PRINT_DEBUG("poll: removing=0x%x, poll_events=0x%x", (POLLOUT | POLLWRNORM | POLLWRBAND), conn->poll_events);
						}
					}
				}
			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("Normal: flagging waitFlag");
			}
		}
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;

		//delayed ACK timeout, send ACK
		conn->delayed_flag = 0;

		//send ack
		conn->ack_seg->seq_num = conn->send_seq_end;
		conn->ack_seg->seq_end = conn->send_seq_end;
		tcp_seg_update(conn->ack_seg, conn, conn->delayed_ack_flags);
		tcp_seg_send(module, conn->ack_seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	}

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_fin_wait_2(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	//can still receive, send ACKs

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
	}

	if (conn->to_delayed_flag) {
		conn->to_delayed_flag = 0;

		//delayed ACK timeout, send ACK
		conn->delayed_flag = 0;

		//send ack
		conn->ack_seg->seq_num = conn->send_seq_end;
		conn->ack_seg->seq_end = conn->send_seq_end;
		tcp_seg_update(conn->ack_seg, conn, conn->delayed_ack_flags);
		tcp_seg_send(module, conn->ack_seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	}

	conn->main_wait_flag = 1;
	PRINT_DEBUG("flagging waitFlag");

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_closing(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	//self, can still get ACKs & send/resend data (don't accept new data)

	tcp_main_fin_wait_1(module, conn);

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_time_wait(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	if (conn->request_interrupt) {
		conn->request_interrupt = 0;
	}

	if (conn->to_gbn_flag) {
		conn->to_gbn_flag = 0;
		//TO, CLOSE

		if (conn->delayed_flag) {
			//send remaining ACK
			timer_stop(conn->to_delayed_data->tid);
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;

			//send ack
			conn->ack_seg->seq_num = conn->send_seq_end;
			conn->ack_seg->seq_end = conn->send_seq_end;
			tcp_seg_update(conn->ack_seg, conn, conn->delayed_ack_flags);
			tcp_seg_send(module, conn->ack_seg);

			if (conn->recv_win == 0) {
				conn->flow_stopped = 1;
			}
		}

		PRINT_DEBUG("TO, CLOSE: state=%d, conn=%p", conn->state, conn);
		conn->state = TS_CLOSED;

		conn->main_wait_flag = 0;
		tcp_conn_shutdown(conn);
	} else {
		conn->main_wait_flag = 1;
		PRINT_DEBUG("flagging waitFlag");

		if (conn->to_delayed_flag) {
			conn->to_delayed_flag = 0;

			//delayed ACK timeout, send ACK
			conn->delayed_flag = 0;

			//send ack
			conn->ack_seg->seq_num = conn->send_seq_end;
			conn->ack_seg->seq_end = conn->send_seq_end;
			tcp_seg_update(conn->ack_seg, conn, conn->delayed_ack_flags);
			tcp_seg_send(module, conn->ack_seg);

			if (conn->recv_win == 0) {
				conn->flow_stopped = 1;
			}
		}
	}

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_close_wait(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	//can still send & get ACKs
	tcp_main_established(module, conn);

	PRINT_DEBUG("Exited: conn=%p", conn);
}

void tcp_main_last_ack(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	//can still get ACKs & send/resend data (don't accept new data)

	tcp_main_fin_wait_1(module, conn);

	//TODO augment so that on final ack, call conn_shutdown(conn);
	PRINT_DEBUG("Exited: conn=%p", conn);
}

void *tcp_main_thread(void *local) {
	struct tcp_conn *conn = (struct tcp_conn *) local;
	struct fins_module *module = conn->module;
	struct tcp_data *md = (struct tcp_data *) module->data;
	PRINT_DEBUG("Entered: conn=%p", conn);

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	while (conn->running_flag) {
		PRINT_DEBUG( "before: host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		PRINT_DEBUG("before: flags: state=%u, interrupt=%u, to_gbn=%u, fast=%u, gbn=%u, delayed=%u, to_delay=%u, first=%u, wait=%u",
				conn->state, conn->request_interrupt, conn->to_gbn_flag, conn->fast_flag, conn->gbn_flag, conn->delayed_flag, conn->to_delayed_flag, conn->first_flag, conn->main_wait_flag);

		switch (conn->state) {
		case TS_CLOSED:
			tcp_main_closed(module, conn);
			break;
		case TS_LISTEN:
			tcp_main_listen(module, conn);
			break;
		case TS_SYN_SENT:
			tcp_main_syn_sent(module, conn);
			break;
		case TS_SYN_RECV:
			tcp_main_syn_recv(module, conn);
			break;
		case TS_ESTABLISHED:
			tcp_main_established(module, conn);
			break;
		case TS_FIN_WAIT_1:
			tcp_main_fin_wait_1(module, conn);
			break;
		case TS_FIN_WAIT_2:
			tcp_main_fin_wait_2(module, conn);
			break;
		case TS_CLOSING:
			tcp_main_closing(module, conn);
			break;
		case TS_TIME_WAIT:
			tcp_main_time_wait(module, conn);
			break;
		case TS_CLOSE_WAIT:
			tcp_main_close_wait(module, conn);
			break;
		case TS_LAST_ACK:
			tcp_main_last_ack(module, conn);
			break;
		}

		PRINT_DEBUG( "after: host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		PRINT_DEBUG("after: flags: state=%u, interrupt=%u, to_gbn=%u, fast=%u, gbn=%u, delayed=%u, to_delay=%u, first=%u, wait=%u",
				conn->state, conn->request_interrupt, conn->to_gbn_flag, conn->fast_flag, conn->gbn_flag, conn->delayed_flag, conn->to_delayed_flag, conn->first_flag, conn->main_wait_flag);

		if (conn->main_wait_flag && !conn->request_interrupt && !conn->to_gbn_flag && !conn->to_delayed_flag
		/*&& !(!queue_is_empty(conn->request_queue) && queue_has_space(conn->write_queue, 1))*/) {
			conn->main_wait_flag = 0;
			conn->main_waiting = 1;
			PRINT_DEBUG("sem_post: conn=%p", conn);
			sem_post(&conn->sem);

			PRINT_DEBUG("");
			secure_sem_wait(&conn->main_wait_sem);

			PRINT_DEBUG("sem_wait: conn=%p", conn);
			secure_sem_wait(&conn->sem);
			//sem_init(&conn->main_wait_sem, 0, 0);
		} else {
			PRINT_DEBUG("sem_post: conn=%p", conn);
			sem_post(&conn->sem);

			PRINT_DEBUG("sem_wait: conn=%p", conn);
			secure_sem_wait(&conn->sem);
		}
	}

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);
	if (conn->stub_list) {
		list_remove(md->conn_stub_list, conn);
	} else {
		list_remove(md->conn_list, conn);
	}
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	//close & free connection
	tcp_conn_stop(module, conn);
	tcp_conn_free(conn);

	PRINT_DEBUG("Exited: conn=%p", conn);
	return NULL;
}

struct tcp_conn *tcp_conn_create(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: module=%p, host=%u:%u, rem=%u:%u", module, host_ip, host_port, rem_ip, rem_port);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_conn *conn = (struct tcp_conn *) secure_malloc(sizeof(struct tcp_conn));
	conn->module = module;
	sem_init(&conn->sem, 0, 1);
	conn->running_flag = 1;
	conn->threads = 1;
	conn->state = TS_CLOSED;
	PRINT_DEBUG("state=%d, conn=%p", conn->state, conn);

	conn->host_ip = host_ip;
	conn->host_port = host_port;
	conn->rem_ip = rem_ip;
	conn->rem_port = rem_port;

	//conn->store_list = list_create(TCP_STORE_LIST_MAX);
	conn->backlog_list = list_create(TCP_BACKLOG_LIST_MAX);

	conn->request_queue = tcp_queue_create(TCP_REQUEST_LIST_MAX);
	conn->write_queue = tcp_queue_create(TCP_MAX_QUEUE_DEFAULT);
	conn->send_queue = tcp_queue_create(TCP_MAX_QUEUE_DEFAULT);
	conn->recv_queue = tcp_queue_create(TCP_MAX_QUEUE_DEFAULT);
	//conn->read_queue = queue_create(TCP_MAX_QUEUE_DEFAULT); //commented, since buffer in Daemon

	//conn->main_wait_flag = 0;
	sem_init(&conn->main_wait_sem, 0, 0);

	conn->first_flag = 1;

	conn->to_gbn_data = secure_malloc(sizeof(struct sem_to_timer_data));
	conn->to_gbn_data->handler = sem_to_handler;
	conn->to_gbn_data->flag = &conn->to_gbn_flag;
	conn->to_gbn_data->waiting = &conn->main_waiting;
	conn->to_gbn_data->sem = &conn->main_wait_sem;
	timer_create_to((struct to_timer_data *) conn->to_gbn_data);

	conn->to_delayed_data = secure_malloc(sizeof(struct sem_to_timer_data));
	conn->to_delayed_data->handler = sem_to_handler;
	conn->to_delayed_data->flag = &conn->to_delayed_flag;
	conn->to_delayed_data->waiting = &conn->main_waiting;
	conn->to_delayed_data->sem = &conn->main_wait_sem;
	timer_create_to((struct to_timer_data *) conn->to_delayed_data);
	conn->ack_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);

	conn->send_max_win = TCP_MAX_WINDOW_DEFAULT;
	conn->send_win = conn->send_max_win;

	conn->recv_max_win = TCP_MAX_WINDOW_DEFAULT;
	conn->recv_win = conn->recv_max_win;
	conn->recv_seq_num = 0;
	conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

	conn->MSS = md->mss;
	conn->cong_state = RENO_SLOWSTART;
	conn->cong_window = conn->MSS;

	conn->rtt_first = 1;
	conn->timeout = TCP_GBN_TO_DEFAULT;

	conn->tsopt_attempt = 0; //1; //TODO change to 0, trial values atm
	conn->sack_attempt = 0; //1;

	conn->wsopt_attempt = 0; //1;
	conn->ws_send = TCP_OPT_WS_DEFAULT;
	conn->ws_recv = TCP_OPT_WS_DEFAULT;

	//################################################################## alternate implementation, uses 1
	conn->send_buf = NULL;
	conn->send_len = 0;
	conn->send_start = 0;
	conn->send_next = 0;
	conn->send_end = 0;
	conn->send_pkt = (struct tcp_packet *) secure_malloc(sizeof(struct tcp_packet));
	conn->send_pkt->ip_hdr.src_ip = conn->host_ip;
	conn->send_pkt->ip_hdr.dst_ip = conn->rem_ip;
	conn->send_pkt->ip_hdr.zeros = 0;
	conn->send_pkt->ip_hdr.protocol = IPPROTO_TCP;
	conn->send_pkt->tcp_hdr.src_port = conn->host_port;
	conn->send_pkt->tcp_hdr.dst_port = conn->rem_port;
	free(conn->send_pkt); //TODO remove if do re-implementation
	//##################################################################

	//TODO add keepalive timer - implement through gbn timer
	//TODO add silly window timer
	//TODO add nagel timer

	//start main thread
	secure_pthread_create(&conn->main_thread, NULL, tcp_main_thread, (void *) conn);
	pthread_detach(conn->main_thread);

	PRINT_DEBUG("Exited: host=%u:%u, rem=%u:%u, conn=%p", host_ip, host_port, rem_ip, rem_port, conn);
	return conn;
}

//find a TCP connection with given host addr/port
int tcp_conn_host_test(struct tcp_conn *conn, uint32_t *host_ip, uint16_t *host_port) {
	return conn->host_ip == *host_ip && conn->host_port == *host_port;
}

//find a TCP connection with given host addr/port and remote addr/port
//NOTE: this means for incoming IP FF call with (dst_ip, src_ip, dst_p, src_p)
int tcp_conn_addr_test(struct tcp_conn *conn, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port) {
	return conn->host_ip == *host_ip && conn->host_port == *host_port && conn->rem_ip == *rem_ip && conn->rem_port == *rem_port;
}

int tcp_conn_established_test(struct tcp_conn *conn) {
	return conn->state == TS_ESTABLISHED && !conn->signaled;
}

int tcp_conn_send_fcf(struct fins_module *module, struct tcp_conn *conn, uint16_t opcode, uint32_t param_id, uint32_t ret_val, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: conn=%p, param_id=%d, ret_val=%d, ret_msg=%u", conn, param_id, ret_val, ret_msg);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(meta, "protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "ret_msg", &ret_msg, META_TYPE_INT32);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = SS_CONNECTED;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

	secure_metadata_writeToElement(meta, "host_ip", &conn->host_ip, META_TYPE_INT32);
	uint32_t host_port = conn->host_port;
	secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "rem_ip", &conn->rem_ip, META_TYPE_INT32);
	uint32_t rem_port = conn->rem_port;
	secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = gen_control_serial_num();
	ff->ctrlFrame.opcode = opcode;
	ff->ctrlFrame.param_id = param_id;
	ff->ctrlFrame.ret_val = ret_val;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
	if (module_send_flow(module, ff, TCP_FLOW_DAEMON)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

int tcp_conn_send_exec_reply(struct fins_module *module, struct tcp_conn *conn, uint32_t serial_num, uint32_t param_id, uint32_t ret_val, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: conn=%p, param_id=%d, ret_val=%d, ret_msg=%u", conn, param_id, ret_val, ret_msg);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(meta, "protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "ret_msg", &ret_msg, META_TYPE_INT32);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = SS_CONNECTED;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

	secure_metadata_writeToElement(meta, "host_ip", &conn->host_ip, META_TYPE_INT32);
	uint32_t host_port = conn->host_port;
	secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "rem_ip", &conn->rem_ip, META_TYPE_INT32);
	uint32_t rem_port = conn->rem_port;
	secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = serial_num;
	ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
	ff->ctrlFrame.param_id = param_id;
	ff->ctrlFrame.ret_val = ret_val;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
	if (module_send_flow(module, ff, TCP_FLOW_DAEMON)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

int tcp_conn_reply_fcf(struct fins_module *module, struct tcp_conn *conn, struct finsFrame *ff, uint32_t ret_val, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: conn=%p, ff=%p, ret_val=%u, ret_msg=%u", conn, ff, ret_val, ret_msg);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(ff->metaData, "protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(ff->metaData, "ret_msg", &ret_msg, META_TYPE_INT32);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(ff->metaData, "family", &family, META_TYPE_INT32);
	uint32_t state = conn->state;
	secure_metadata_writeToElement(ff->metaData, "state", &state, META_TYPE_INT32);

	secure_metadata_writeToElement(ff->metaData, "host_ip", &conn->host_ip, META_TYPE_INT32);
	uint32_t host_port = conn->host_port;
	secure_metadata_writeToElement(ff->metaData, "host_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(ff->metaData, "rem_ip", &conn->rem_ip, META_TYPE_INT32);
	uint32_t rem_port = conn->rem_port;
	secure_metadata_writeToElement(ff->metaData, "rem_port", &rem_port, META_TYPE_INT32);

	ff->destinationID = ff->ctrlFrame.sender_id;

	ff->ctrlFrame.sender_id = module->index;

	switch (ff->ctrlFrame.opcode) {
	case CTRL_READ_PARAM:
		ff->ctrlFrame.opcode = CTRL_READ_PARAM_REPLY;
		break;
	case CTRL_SET_PARAM:
		ff->ctrlFrame.opcode = CTRL_SET_PARAM_REPLY;
		break;
	case CTRL_EXEC:
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		break;
	default:
		PRINT_ERROR("Unhandled msg case: opcode=%u", ff->ctrlFrame.opcode);
		return 0;
	}

	ff->ctrlFrame.ret_val = ret_val;

	module_to_switch(module, ff);

	return 1;
}

int tcp_conn_is_finished(struct tcp_conn *conn) {
	return tcp_queue_is_empty(conn->request_queue) && tcp_queue_is_empty(conn->write_queue) && conn->send_seq_num == conn->send_seq_end;
}

void tcp_conn_shutdown(struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);

	conn->running_flag = 0;
	PRINT_DEBUG("posting to main_wait_sem");
	sem_post(&conn->main_wait_sem);
}

void tcp_conn_stop(struct fins_module *module, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p", conn);
	struct tcp_data *md = (struct tcp_data *) module->data;

	conn->running_flag = 0;

	//stop threads
	timer_stop(conn->to_gbn_data->tid);
	timer_stop(conn->to_delayed_data->tid);

	list_for_each(conn->backlog_list, tcp_conn_shutdown);

	//TODO stop keepalive timer
	//TODO stop silly window timer
	//TODO stop nagel timer
	//sem_post(&conn->main_wait_sem);
	//sem_post(&conn->write_wait_sem);
	//sem_post(&conn->write_sem);

	while (1) {
		PRINT_DEBUG("conn_list wait***************");
		secure_sem_wait(&md->conn_list_sem);
		if (conn->threads <= 1) {
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);
			break;
		} else {
			PRINT_DEBUG("conn=%p, threads=%d", conn, conn->threads);
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);
		}

		PRINT_DEBUG("sem_post: conn=%p", conn);
		sem_post(&conn->sem);
		PRINT_DEBUG("sem_wait: conn=%p", conn);
		secure_sem_wait(&conn->sem);
	}
}

void tcp_conn_free(struct tcp_conn *conn) {
	PRINT_DEBUG("conn=%p", conn);

	if (conn->backlog_list) {
		list_free(conn->backlog_list, nop_func);
	}

	if (conn->request_queue) {
		tcp_queue_free(conn->request_queue);
	}
	if (conn->write_queue) {
		tcp_queue_free(conn->write_queue);
	}
	if (conn->send_queue) {
		tcp_queue_free(conn->send_queue);
	}
	if (conn->recv_queue) {
		tcp_queue_free(conn->recv_queue);
	}
	//if (conn->read_queue) {
	//	queue_free(conn->read_queue); }

	tcp_seg_free(conn->ack_seg);

	sem_destroy(&conn->sem);
	sem_destroy(&conn->main_wait_sem);

	timer_delete(conn->to_gbn_data->tid);
	free(conn->to_gbn_data);

	timer_delete(conn->to_delayed_data->tid);
	free(conn->to_delayed_data);

	free(conn);
}

//Get a random number to use as a starting sequence number
int tcp_rand(void) {
	return rand(); //Just use the standard C random number generator for now
}

struct finsFrame *tcp_to_fdf(struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: seg=%p", seg);

	PRINT_DEBUG( "info: src=%u:%u, dst=%u:%u, seq=%u, len=%d, opts=%d, ack=%u, flags=0x%x, win=%u, checksum=0x%x, F=%u, S=%u, R=%u, A=%u",
			seg->src_ip, seg->src_port, seg->dst_ip, seg->dst_port, seg->seq_num, seg->data_len, seg->opt_len, seg->ack_num, seg->flags, seg->win_size, seg->checksum, seg->flags&FLAG_FIN, (seg->flags&FLAG_SYN)>>1, (seg->flags&FLAG_RST)>>2, (seg->flags&FLAG_ACK)>>4);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(meta, "send_protocol", &protocol, META_TYPE_INT32);
	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "send_family", &family, META_TYPE_INT32);

	secure_metadata_writeToElement(meta, "send_src_ipv4", &seg->src_ip, META_TYPE_INT32);
	uint32_t src_port = seg->src_port;
	secure_metadata_writeToElement(meta, "send_src_port", &src_port, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "send_dst_ipv4", &seg->dst_ip, META_TYPE_INT32);
	uint32_t dst_port = seg->dst_port;
	secure_metadata_writeToElement(meta, "send_dst_port", &dst_port, META_TYPE_INT32);

	struct finsFrame *ff = (struct finsFrame*) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_DATA; //leave unset?
	ff->metaData = meta;

	ff->dataFrame.directionFlag = DIR_DOWN; // ingress or egress network data; see above
	ff->dataFrame.pduLength = seg->data_len + TCP_HEADER_BYTES(seg->flags); //Add in the header size for this, too
	ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
	PRINT_DEBUG("seg=%p, ff=%p, meta=%p, data_len=%d, hdr=%d, pduLength=%d",
			seg, ff, ff->metaData, seg->data_len, TCP_HEADER_BYTES(seg->flags), ff->dataFrame.pduLength);

	struct tcpv4_header *hdr = (struct tcpv4_header *) ff->dataFrame.pdu;
	hdr->src_port = htons(seg->src_port);
	hdr->dst_port = htons(seg->dst_port);
	hdr->seq_num = htonl(seg->seq_num);
	hdr->ack_num = htonl(seg->ack_num);
	hdr->flags = htons(seg->flags);
	hdr->win_size = htons(seg->win_size);
	//hdr->checksum = htons(seg->checksum)
	hdr->checksum = 0;
	hdr->urg_pointer = htons(seg->urg_pointer);

	if (seg->opt_len > 0) {
		memcpy(hdr->options, seg->options, seg->opt_len);

		if (seg->data_len > 0) {
			memcpy(hdr->options + seg->opt_len, seg->data, seg->data_len);
		}
	} else if (seg->data_len > 0) {
		memcpy(hdr->options, seg->data, seg->data_len);
	}

	uint32_t sum = 0;
	uint8_t *pt;
	uint32_t i;

	struct ipv4_header ip_hdr;
	ip_hdr.src_ip = htonl(seg->src_ip);
	ip_hdr.dst_ip = htonl(seg->dst_ip);
	ip_hdr.zeros = 0;
	ip_hdr.protocol = IPPROTO_TCP;
	ip_hdr.tcp_len = htons((uint16_t) ff->dataFrame.pduLength);

	pt = (uint8_t *) &ip_hdr;
	for (i = 0; i < IP_HEADER_BYTES; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i, *(pt+1), *(pt+1), i+1, *(pt+2), *(pt+2));
		sum += (*pt << 8) + *(pt + 1);
	}

	pt = (uint8_t *) ff->dataFrame.pdu;
	for (i = 1; i < ff->dataFrame.pduLength; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i, *(pt+1), *(pt+1), i+1, *(pt+2), *(pt+2));
		sum += (*pt << 8) + *(pt + 1);
	}
	if (ff->dataFrame.pduLength & 0x1) {
		//PRINT_DEBUG("%u=%2x (%u), uneven", ff->dataFrame.pduLength-1, *(pt+1), *(pt+1));
		sum += *pt << 8;
	}

	while ((sum >> 16)) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;

	PRINT_DEBUG("checksum=0x%x", (uint16_t) sum);

	hdr->checksum = htons((uint16_t) sum);

	PRINT_DEBUG("Exited: seg=%p, ff=%p, meta=%p", seg, ff, ff->metaData);
	return ff;
}

struct tcp_seg *fdf_to_tcp(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	if (ff->dataFrame.pduLength < MIN_TCP_HEADER_BYTES) {
		PRINT_ERROR("pduLength too small: ff=%p, pdu_len=%u, min=%u", ff, ff->dataFrame.pduLength, MIN_TCP_HEADER_BYTES);
		return NULL;
	}

	struct tcp_seg *seg = (struct tcp_seg *) secure_malloc(sizeof(struct tcp_seg));

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "recv_protocol", &protocol);
	if (protocol != IPPROTO_TCP) {
		PRINT_ERROR("error: protocol=%u", protocol);
		free(seg);
		return NULL;
	}

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "recv_family", &family);

	secure_metadata_readFromElement(ff->metaData, "recv_src_ipv4", &seg->src_ip);
	secure_metadata_readFromElement(ff->metaData, "recv_dst_ipv4", &seg->dst_ip);

	struct tcpv4_header *hdr = (struct tcpv4_header *) ff->dataFrame.pdu;
	seg->src_port = ntohs(hdr->src_port);
	seg->dst_port = ntohs(hdr->dst_port);
	seg->seq_num = ntohl(hdr->seq_num);
	seg->ack_num = ntohl(hdr->ack_num);
	seg->flags = ntohs(hdr->flags);
	seg->win_size = ntohs(hdr->win_size);
	seg->checksum = ntohs(hdr->checksum);
	seg->urg_pointer = ntohs(hdr->urg_pointer);

	seg->opt_len = TCP_OPTIONS_BYTES(seg->flags);
	if (seg->opt_len > 0) {
		memcpy(seg->options, hdr->options, seg->opt_len);
	}

	//And fill in the data length and the data, also
	seg->data_len = ff->dataFrame.pduLength - TCP_HEADER_BYTES(seg->flags);
	if (seg->data_len > 0) {
		seg->data = (uint8_t *) secure_malloc(seg->data_len);
		//uint8_t *ptr = hdr->options + seg->opt_len;
		memcpy(seg->data, hdr->options + seg->opt_len, seg->data_len);
		//ptr += seg->data_len;
	}

	seg->seq_end = seg->seq_num + seg->data_len;

	PRINT_DEBUG("info: src=%u:%u, dst=%u:%u, seq=%u, len=%d, opts=%d, ack=%u, flags=0x%x, win=%u, checksum=0x%x, F=%u, S=%u, R=%u, A=%u",
			seg->src_ip, seg->src_port, seg->dst_ip, seg->dst_port, seg->seq_num, seg->data_len, seg->opt_len, seg->ack_num, seg->flags, seg->win_size, seg->checksum, seg->flags&FLAG_FIN, (seg->flags&FLAG_SYN)>>1, (seg->flags&FLAG_RST)>>2, (seg->flags&FLAG_ACK)>>4);

	PRINT_DEBUG("Exited: ff=%p, meta=%p, seg=%p", ff, ff->metaData, seg);
	return seg;
}

struct tcp_seg *tcp_seg_create(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint32_t seq_num, uint32_t seq_end) {
	PRINT_DEBUG("Entered: src=%u:%u, dst=%u:%u, seq_num=%u, seq_end=%u", src_ip, src_port, dst_ip, dst_port, seq_num, seq_end);
	struct tcp_seg *seg = (struct tcp_seg *) secure_malloc(sizeof(struct tcp_seg));
	seg->src_ip = src_ip;
	seg->src_port = src_port;
	seg->dst_ip = dst_ip;
	seg->dst_port = dst_port;

	seg->seq_num = seq_num;
	seg->seq_end = seq_end;

	//All commented are memset to 0 by secure_malloc
	//seg->ack_num = 0;
	//seg->flags = 0;
	//seg->win_size = 0;
	//seg->checksum = 0;
	//seg->urg_pointer = 0;

	//seg->opt_len = 0;
	////seg->options = NULL;
	////seg->options = fins_malloc(MAX_TCP_OPTIONS_BYTES);

	//seg->data_len = 0;
	//seg->data = NULL;

	PRINT_DEBUG("Exited: src=%u:%u, dst=%u:%u, seq_num=%u, seq_end=%u, seg=%p", src_ip, src_port, dst_ip, dst_port, seq_num, seq_end, seg);
	return seg;
}

uint32_t tcp_seg_add_data(struct tcp_seg *seg, struct tcp_queue *queue, uint32_t index, int data_len) {
	PRINT_DEBUG("Entered: seg=%p, queue=%p, index=%u, data_len=%d", seg, queue, index, data_len);

	if (data_len > queue->len) {
		PRINT_ERROR("len=%u, data_len=%u", queue->len, data_len);
	}

	uint32_t avail;
	struct tcp_node *temp_node;

	seg->data_len = data_len;
	seg->seq_end = seg->seq_num + seg->data_len;
	seg->data = (uint8_t *) secure_malloc(data_len);
	uint8_t *ptr = seg->data;

	while (data_len && !tcp_queue_is_empty(queue)) {
		avail = queue->front->len - index;
		PRINT_DEBUG("data_len=%d, index=%u, len=%u, avail=%u", data_len, index, queue->front->len, avail);
		if (data_len < avail) {
			memcpy(ptr, queue->front->data + index, data_len);
			ptr += data_len;
			index += data_len;
			data_len = 0;
			break;
		} else {
			memcpy(ptr, queue->front->data + index, avail);
			ptr += avail;
			index = 0;
			data_len -= avail;

			temp_node = tcp_queue_remove_front(queue);
			tcp_node_free(temp_node);
		}
	}

	PRINT_DEBUG("Exited: seg=%p, queue=%p, index=%u, data_len=%d", seg, queue, index, data_len);
	return index;
}

void tcp_seg_add_options(struct tcp_seg *seg, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p", conn, seg);

	//uint32_t i;
	//uint32_t len;
	uint8_t *pt;
	struct tcp_node *node;
	uint32_t left;
	uint32_t right;

	//add options //TODO implement options system
	switch (conn->state) {
	case TS_SYN_SENT:
		PRINT_DEBUG("");
		//add MSS to seg
		//seg->opt_len = TCP_MSS_BYTES + TCP_SACK_PERM_BYTES * conn->sack_attempt + TCP_TS_BYTES * conn->tsopt_attempt + TCP_WS_BYTES * conn->wsopt_attempt;
		//if (seg->opt_len % 4) {
		//	seg->opt_len += 4 - (seg->opt_len % 4); //round options up?
		//}
		//if (seg->opt_len > MAX_TCP_OPTIONS_BYTES) {
		//	PRINT_ERROR("ERROR");
		//}
		seg->opt_len = 0;
		pt = seg->options;

		//MSS typically 1460
		seg->opt_len += TCP_OPT_MSS_BYTES;
		*pt++ = TCP_OPT_MSS;
		*pt++ = TCP_OPT_MSS_BYTES;
		*(uint16_t *) pt = htons(conn->MSS);
		pt += sizeof(uint16_t);

		if (conn->sack_attempt) {
			if (!conn->tsopt_attempt) {
				seg->opt_len += 2;
				*pt++ = TCP_OPT_NOP; //NOP
				*pt++ = TCP_OPT_NOP; //NOP
			}

			seg->opt_len += TCP_OPT_SACK_PERM_BYTES;
			*pt++ = TCP_OPT_SACK_PERM;
			*pt++ = TCP_OPT_SACK_PERM_BYTES;
		}

		if (conn->tsopt_attempt) {
			if (!conn->sack_attempt) {
				seg->opt_len += 2;
				*pt++ = TCP_OPT_NOP; //NOP
				*pt++ = TCP_OPT_NOP; //NOP
			}
			seg->opt_len += TCP_OPT_TS_BYTES;
			*pt++ = TCP_OPT_TS;
			*pt++ = TCP_OPT_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL)));
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = 0;
			pt += sizeof(uint32_t);
		}

		if (conn->wsopt_attempt) {
			seg->opt_len++;
			*pt++ = TCP_OPT_NOP; //NOP

			seg->opt_len += TCP_OPT_WS_BYTES;
			*pt++ = TCP_OPT_WS; //WS opt
			*pt++ = TCP_OPT_WS_BYTES;
			*pt++ = conn->ws_recv; //believe default is 6
		}
		break;
	case TS_SYN_RECV:
		PRINT_DEBUG("");
		//seg->opt_len = TCP_MSS_BYTES + TCP_SACK_PERM_BYTES * conn->sack_enabled + TCP_TS_BYTES * conn->tsopt_enabled + TCP_WS_BYTES * conn->wsopt_enabled;
		//if (seg->opt_len % 4) {
		//	seg->opt_len += 4 - (seg->opt_len % 4); //round options up?
		//}
		//if (seg->opt_len > MAX_TCP_OPTIONS_BYTES) {
		//	PRINT_ERROR("ERROR");
		//}
		seg->opt_len = 0;
		pt = seg->options;

		//MSS typically 1460
		seg->opt_len += TCP_OPT_MSS_BYTES;
		*pt++ = TCP_OPT_MSS;
		*pt++ = TCP_OPT_MSS_BYTES;
		*(uint16_t *) pt = htons(conn->MSS);
		pt += sizeof(uint16_t);

		if (conn->sack_enabled) {
			if (!conn->tsopt_enabled) {
				seg->opt_len += 2;
				*pt++ = TCP_OPT_NOP; //NOP
				*pt++ = TCP_OPT_NOP; //NOP
			}

			seg->opt_len += TCP_OPT_SACK_PERM_BYTES;
			*pt++ = TCP_OPT_SACK_PERM;
			*pt++ = TCP_OPT_SACK_PERM_BYTES;
		}

		if (conn->tsopt_enabled) {
			if (!conn->sack_enabled) {
				seg->opt_len += 2;
				*pt++ = TCP_OPT_NOP; //NOP
				*pt++ = TCP_OPT_NOP; //NOP
			}

			seg->opt_len += TCP_OPT_TS_BYTES;
			*pt++ = TCP_OPT_TS;
			*pt++ = TCP_OPT_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL))); //TODO complete
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = 0;
			pt += sizeof(uint32_t);
		}

		if (conn->wsopt_enabled) {
			seg->opt_len++;
			*pt++ = TCP_OPT_NOP; //NOP

			seg->opt_len += TCP_OPT_WS_BYTES;
			*pt++ = TCP_OPT_WS; //WS opt
			*pt++ = TCP_OPT_WS_BYTES;
			*pt++ = conn->ws_recv; //believe default is 6
		}
		break;
	case TS_ESTABLISHED:
		seg->opt_len = 0;
		pt = seg->options;

		if (conn->tsopt_enabled) {
			seg->opt_len += 2;
			*pt++ = TCP_OPT_NOP; //NOP
			*pt++ = TCP_OPT_NOP; //NOP

			seg->opt_len += TCP_OPT_TS_BYTES;
			*pt++ = TCP_OPT_TS;
			*pt++ = TCP_OPT_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL))); //TODO complete
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = htonl(0); //conn->ts_latest ?
			pt += sizeof(uint32_t);
		}

		if (conn->sack_enabled) {
			seg->opt_len += 2;
			*pt++ = TCP_OPT_NOP; //NOP
			*pt++ = TCP_OPT_NOP; //NOP

			seg->opt_len += 2;
			*pt++ = TCP_OPT_SACK;
			uint8_t *len_pt = pt++;
			*len_pt = 2;

			node = conn->recv_queue->front;
			while (node) {
				left = node->seq_num;
				right = node->seq_end;

				while (node->next) {
					if (left <= right) {
						if (node->next->seq_num <= right) {
							right = node->next->seq_end;
						} else {
							break;
						}
					} else {
						if (node->next->seq_num <= right) {
							right = node->next->seq_end;
						} else if (left < node->next->seq_num) {
							right = node->next->seq_end;
						} else {
							//save
							break;
						}
					}

					node = node->next;
				}

				//save left & right
				*(uint32_t *) pt = htonl(left);
				pt += sizeof(uint32_t);
				*(uint32_t *) pt = htonl(right);
				pt += sizeof(uint32_t);

				*len_pt += 2 * sizeof(uint32_t);
				seg->opt_len += 2 * sizeof(uint32_t);
				if (seg->opt_len > 32) {
					break;
				}
				node = node->next;
			}

			if (*len_pt == 2) {
				seg->opt_len -= 4;
			}
		}

		break;
	default:
		PRINT_DEBUG("");
		seg->opt_len = 0;
		//seg->options = NULL;
		break;
	}
}

void tcp_seg_update_options(struct tcp_seg *seg, struct tcp_conn *conn) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p", conn, seg);

	//update options, since options are always 40 bytes long, so can just rewrite it
}

void tcp_seg_update(struct tcp_seg *seg, struct tcp_conn *conn, uint16_t flags) { //updates ack/win/opts/timestamps
//clear flags
//memset(&seg->flags, 0, sizeof(uint16_t));
	seg->flags = 0;
	//seg->flags &= ~FLAG_PSH;
	seg->flags |= (flags & (FLAG_CONTROL | FLAG_ECN)); //TODO this is where FLAG_FIN, etc should be added

	switch (conn->state) {
	case TS_CLOSED:
		break;
	case TS_LISTEN:
		break;
	case TS_SYN_SENT:
		break;
	case TS_SYN_RECV:
		break;
	case TS_ESTABLISHED:
		tcp_seg_delayed_ack(seg, conn);
		break;
	case TS_FIN_WAIT_1:
		tcp_seg_delayed_ack(seg, conn);
		if (conn->fin_sent && !conn->fin_sep && seg->seq_num + seg->data_len == conn->send_seq_end) { //TODO remove?
		//send fin
			PRINT_DEBUG("add FIN");
			seg->flags |= FLAG_FIN;
		}
		break;
	case TS_FIN_WAIT_2:
		break;
	case TS_CLOSING:
		tcp_seg_delayed_ack(seg, conn);
		break;
	case TS_CLOSE_WAIT:
		tcp_seg_delayed_ack(seg, conn);
		break;
	case TS_LAST_ACK:
		tcp_seg_delayed_ack(seg, conn); //TODO move outside of switch? get rid of switch
		if (conn->fin_sent && !conn->fin_sep && seg->seq_num + seg->data_len == conn->send_seq_end) {
			//send fin
			PRINT_DEBUG("add FIN");
			seg->flags |= FLAG_FIN;
		}
		break;
	case TS_TIME_WAIT:
		break;
	}

	if (seg->flags & FLAG_ACK) {
		seg->ack_num = conn->recv_seq_num;
	} else {
		seg->ack_num = 0;
	}

	if (conn->wsopt_enabled) {
		seg->win_size = conn->recv_win >> conn->ws_recv; //recv sem?
	} else {
		seg->win_size = conn->recv_win;
	}

	if (seg->opt_len) {
		//seg_update_options(seg, conn);
		tcp_seg_add_options(seg, conn);
	} else {
		tcp_seg_add_options(seg, conn);
	}
	//seg->opt_len = 0;

	//TODO PAWS

	int offset = seg->opt_len / 4; //TODO improve logic, use ceil? round up
	seg->flags |= ((MIN_TCP_HEADER_WORDS + offset) << 12) & FLAG_DATAOFFSET;
	PRINT_DEBUG("offset=%d, header_len=%d, pkt_len=%d", offset, TCP_HEADER_BYTES(seg->flags), TCP_HEADER_BYTES(seg->flags)+seg->data_len);

	//TODO alt checksum
	//seg->checksum = seg_checksum(seg);
}

uint16_t tcp_seg_checksum(struct tcp_seg *seg) { //TODO check if checksum works, check rollover
	int i;
	//TODO add TCP alternate checksum w/data in options (15)

	uint32_t sum = 0;

	struct tcp_packet2 pkt;
	pkt.src_ip = htonl(seg->src_ip);
	pkt.dst_ip = htonl(seg->dst_ip);
	pkt.zeros = 0;
	pkt.protocol = IPPROTO_TCP;
	pkt.tcp_len = htons(TCP_HEADER_BYTES(seg->flags) + seg->data_len);
	pkt.src_port = htons(seg->src_port);
	pkt.dst_port = htons(seg->dst_port);
	pkt.seq_num = htonl(seg->seq_num);
	pkt.ack_num = htonl(seg->ack_num);
	pkt.flags = htons(seg->flags);
	pkt.win_size = htons(seg->win_size);
	pkt.checksum = htons(seg->checksum);
	pkt.urg_pointer = htons(seg->urg_pointer);

	uint8_t *pt = (uint8_t *) &pkt;
	for (i = 0; i < IP_HEADER_BYTES + MIN_TCP_HEADER_BYTES; i += 2, pt += 2) {
		sum += (*pt << 8) + *(pt + 1);
	}

	/*
	 //fake IP header
	 sum += ((uint16_t)(seg->src_ip >> 16)) + ((uint16_t)(seg->src_ip & 0xFFFF)); //TODO fix
	 sum += ((uint16_t)(seg->dst_ip >> 16)) + ((uint16_t)(seg->dst_ip & 0xFFFF));
	 sum += (uint16_t) TCP_PROTOCOL;
	 sum += (uint16_t)(IP_HEADER_BYTES + TCP_HEADER_BYTES(seg->flags) + seg->data_len);

	 //fake TCP header
	 sum += seg->src_port;
	 sum += seg->dst_port;
	 sum += ((uint16_t)(seg->seq_num >> 16)) + ((uint16_t)(seg->seq_num & 0xFFFF));
	 sum += ((uint16_t)(seg->ack_num >> 16)) + ((uint16_t)(seg->ack_num & 0xFFFF));
	 sum += seg->flags;
	 sum += seg->win_size;
	 //sum += seg->checksum; //dummy checksum=0
	 sum += seg->urg_pointer;
	 */

	//options, opt_len always has to be a factor of 2
	pt = (uint8_t *) seg->options;
	for (i = 0; i < seg->opt_len; i += 2, pt += 2) {
		sum += (*pt << 8) + *(pt + 1);
	}

	//data
	pt = (uint8_t *) seg->data;
	for (i = 1; i < seg->data_len; i += 2, pt += 2) {
		sum += (*pt << 8) + *(pt + 1);
	}

	if (seg->data_len & 0x1) {
		sum += *pt << 8;
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;
	return htons((uint16_t) sum);
}

int tcp_seg_send(struct fins_module *module, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: seg=%p", seg);

	struct finsFrame *ff = tcp_to_fdf(seg);

	/*//###############################
	 struct tcp_segment *seg_test = fdf_to_seg(ff);
	 if (seg_test) {
	 if (seg->src_ip != seg_test->src_ip)
	 PRINT_DEBUG("diff: src_ip: seg=%u, test=%u", seg->src_ip, seg_test->src_ip);
	 if (seg->dst_ip != seg_test->dst_ip)
	 PRINT_DEBUG("diff: dst_ip: seg=%u, test=%u", seg->dst_ip, seg_test->dst_ip);
	 if (seg->src_port != seg_test->src_port)
	 PRINT_DEBUG("diff: src_port: seg=%u, test=%u", seg->src_port, seg_test->src_port);
	 if (seg->dst_port != seg_test->dst_port)
	 PRINT_DEBUG("diff: dst_port: seg=%u, test=%u", seg->dst_port, seg_test->dst_port);
	 if (seg->seq_num != seg_test->seq_num)
	 PRINT_DEBUG("diff: seq_num: seg=%u, test=%u", seg->seq_num, seg_test->seq_num);
	 if (seg->ack_num != seg_test->ack_num)
	 PRINT_DEBUG("diff: ack_num: seg=%u, test=%u", seg->ack_num, seg_test->ack_num);
	 if (seg->flags != seg_test->flags)
	 PRINT_DEBUG("diff: flags: seg=0x%x, test=0x%x", seg->flags, seg_test->flags);
	 if (seg->win_size != seg_test->win_size)
	 PRINT_DEBUG("diff: win_size: seg=%u, test=%u", seg->win_size, seg_test->win_size);
	 if (seg->checksum != seg_test->checksum)
	 PRINT_DEBUG("diff: checksum: seg=0x%x, test=0x%x", seg->checksum, seg_test->checksum);
	 if (seg->urg_pointer != seg_test->urg_pointer)
	 PRINT_DEBUG("diff: urg_pointer: seg=0x%x, test=%d", seg->urg_pointer, seg_test->urg_pointer);
	 if (seg->opt_len != seg_test->opt_len)
	 PRINT_DEBUG("diff: opt_len: seg=0x%x, test=%d", seg->opt_len, seg_test->opt_len);
	 if (seg->data_len != seg_test->data_len)
	 PRINT_DEBUG("diff: data_len: seg=0x%x, test=%d", seg->data_len, seg_test->data_len);
	 //check options/data?
	 }
	 //###############################*/

	if (ff) {
		PRINT_DEBUG("seg=%p, ff=%p, meta=%p", seg, ff, ff->metaData);
		if (module_send_flow(module, ff, TCP_FLOW_IPV4)) {
			return 1;
		} else {
			PRINT_ERROR("Exited, failed: seg=%p, ff=%p, meta=%p", seg, ff, ff->metaData);
			freeFinsFrame(ff);
			return 0;
		}
	} else {
		PRINT_ERROR("Exited, failed: seg=%p, ff=%p, meta=%p", seg, NULL, NULL);
		return 0;
	}
}

void tcp_seg_free(struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: seg=%p", seg);

	if (seg->data_len && seg->data) {
		free(seg->data); //keep data ptr
	}

	if (seg->opt_len && seg->options) {
		//free(seg->options); //TODO change when have options object
		//PRINT_WARN("todo error");
	}
	free(seg);
}

void tcp_seg_delayed_ack(struct tcp_seg *seg, struct tcp_conn *conn) {
	if (conn->delayed_flag) {
		timer_stop(conn->to_delayed_data->tid);
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		seg->flags |= conn->delayed_ack_flags;
	}
}

// 0=out of window, 1=in window
int tcp_in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end) {
	//check if tcp_seg is in connection window
	//Notation: [=win_seq_num, ]=win_seq_end, <=seq_num, >=seq_end, |=rollover,
	if (win_seq_num <= win_seq_end) { // [] |
		if (seq_num <= seq_end) { // <> |
			if (win_seq_num <= seq_num && seq_end <= win_seq_end) { // [ <> ] |
				return 1;
			} else {
				return 0;
			}
		} else { // [],< | >
			return 0;
		}
	} else { // [ | ]
		if (seq_num <= seq_end) { // <> |
			if (win_seq_num <= seq_num) { // [ <> | ]
				return 1;
			} else if (seq_end <= win_seq_end) { // [ | <> ]
				return 1;
			} else { //drop
				return 0;
			}
		} else { // < | >
			if (win_seq_num <= seq_num && seq_end <= win_seq_end) { // [ < | > ]
				return 1;
			} else { //drop
				return 0;
			}
		}
	}
}

int tcp_in_window_overlaps(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end) {
	//check if tcp_seg is in connection window
	//Notation: [=rem_seq_num, ]=rem_seq_end, <=node->seq_num, >=node->seq_end, |=rollover
	if (seq_num == seq_end) {
		if (win_seq_num == win_seq_end) {
			if (win_seq_num == seq_num) {
				return 1;
			} else {
				return 0;
			}
		} else {
			if (win_seq_num <= win_seq_end) { // [] |
				if (win_seq_num <= seq_num && seq_num <= win_seq_end) { // [ < ] |
					return 1;
				} else {
					return 0;
				}
			} else { // [ | ]
				if (win_seq_num <= seq_num) { // [ < | ]
					return 1;
				} else if (seq_num <= win_seq_end) { // [ | < ]
					return 1;
				} else { //drop
					return 0;
				}
			}
		}
	} else {
		if (win_seq_num == win_seq_end) {
			return 0;
		} else {
			if (win_seq_num <= win_seq_end) { // [] |
				if (seq_num <= seq_end) { // <> |
					if (win_seq_num <= seq_num && seq_num <= win_seq_end) { // [ < ] |
						return 1;
					} else if (win_seq_num <= seq_end && seq_end <= win_seq_end) { //[ > ] |
						return 1;
					} else {
						return 0;
					}
				} else { // [],< | >
					if (win_seq_num <= seq_num && seq_num <= win_seq_end) { // [ < ] | >
						return 1;
					} else if (win_seq_num <= seq_end && seq_end <= win_seq_end) { // < | [ > ]
						return 1;
					} else {
						return 0;
					}
				}
			} else { // [ | ]
				if (seq_num <= seq_end) { // <> |
					if (win_seq_num <= seq_num) { // [ < | ]
						return 1;
					} else if (win_seq_num <= seq_end) { // [ > | ]
						return 1;
					} else if (seq_end <= win_seq_end) { // [ | <> ]
						return 1;
					} else { //drop
						return 0;
					}
				} else { // < | >
					if (win_seq_num <= seq_num) { // [ < | ]
						return 1;
					} else if (seq_end <= win_seq_end) { //[ | > ]
						return 1;
					} else { //drop
						return 0;
					}
				}
			}
		}
	}
}

void tcp_metadata_read_conn(metadata *meta, socket_state *state, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port) {
	uint32_t state_buf;
	uint32_t host_port_buf;
	uint32_t rem_port_buf;

	secure_metadata_readFromElement(meta, "state", &state_buf);
	*state = (socket_state) state_buf;

	secure_metadata_readFromElement(meta, "host_ip", host_ip);
	secure_metadata_readFromElement(meta, "host_port", &host_port_buf);
	*host_port = (uint16_t) host_port_buf;

	if (*state > SS_UNCONNECTED) {
		secure_metadata_readFromElement(meta, "rem_ip", rem_ip);
		secure_metadata_readFromElement(meta, "rem_port", &rem_port_buf);
		*rem_port = (uint16_t) rem_port_buf;
	}
}

void tcp_metadata_write_conn(metadata *meta, socket_state *state, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port) {
	uint32_t state_buf;
	uint32_t host_port_buf;
	uint32_t rem_port_buf;

	state_buf = *state;
	secure_metadata_writeToElement(meta, "state", &state_buf, META_TYPE_INT32);

	secure_metadata_writeToElement(meta, "host_ip", host_ip, META_TYPE_INT32);
	host_port_buf = *host_port;
	secure_metadata_writeToElement(meta, "host_port", &host_port_buf, META_TYPE_INT32);

	if (*state > SS_UNCONNECTED) {
		secure_metadata_writeToElement(meta, "rem_ip", rem_ip, META_TYPE_INT32);
		rem_port_buf = *rem_port;
		secure_metadata_writeToElement(meta, "rem_port", &rem_port_buf, META_TYPE_INT32);
	}
}

int tcp_fcf_to_daemon(struct fins_module *module, socket_state state, uint32_t param_id, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip,
		uint16_t rem_port, uint32_t ret_val) {
	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(meta, "protocol", &protocol, META_TYPE_INT32);

	uint32_t state_buf = state;
	secure_metadata_writeToElement(meta, "state", &state_buf, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
	uint32_t host_port_buf = host_port;
	secure_metadata_writeToElement(meta, "host_port", &host_port_buf, META_TYPE_INT32);
	if (state > SS_UNCONNECTED) {
		secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
		uint32_t rem_port_buf = rem_port;
		secure_metadata_writeToElement(meta, "rem_port", &rem_port_buf, META_TYPE_INT32);
	}

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_CONTROL;
	ff->metaData = meta;

	ff->ctrlFrame.sender_id = module->index;
	ff->ctrlFrame.serial_num = gen_control_serial_num();
	ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
	ff->ctrlFrame.param_id = param_id;
	ff->ctrlFrame.ret_val = ret_val;

	ff->ctrlFrame.data_len = 0;
	ff->ctrlFrame.data = NULL;

	PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
	if (module_send_flow(module, ff, TCP_FLOW_DAEMON)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

int tcp_fdf_to_daemon(struct fins_module *module, int data_len, uint8_t *data, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: host=%u:%u, rem=%u:%u, len=%d", host_ip, host_port, rem_ip, rem_port, data_len);

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t protocol = IPPROTO_TCP;
	secure_metadata_writeToElement(meta, "recv_protocol", &protocol, META_TYPE_INT32);
	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "recv_family", &family, META_TYPE_INT32);

	secure_metadata_writeToElement(meta, "recv_src_ipv4", &host_ip, META_TYPE_INT32);
	uint32_t host_port_buf = host_port;
	secure_metadata_writeToElement(meta, "recv_src_port", &host_port_buf, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "recv_dst_ipv4", &rem_ip, META_TYPE_INT32);
	uint32_t rem_port_buf = rem_port;
	secure_metadata_writeToElement(meta, "recv_dst_port", &rem_port_buf, META_TYPE_INT32);

	struct finsFrame *ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = FF_DATA;
	ff->metaData = meta;

	ff->dataFrame.directionFlag = DIR_UP;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	PRINT_DEBUG("src=%u:%u, dst=%u:%u, ff=%p", host_ip, host_port, rem_ip, rem_port, ff);

	/**TODO insert the frame into daemon_to_switch queue
	 * check if insertion succeeded or not then
	 * return 1 on success, or -1 on failure
	 * */
	PRINT_DEBUG("ff=%p, meta=%p", ff, meta);
	if (module_send_flow(module, ff, TCP_FLOW_DAEMON)) {
		return 1;
	} else {
		ff->dataFrame.pdu = NULL;
		freeFinsFrame(ff);
		return 0;
	}
}

//----------------------------------------------------------------------
void *switch_to_tcp(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_DEBUG("Entered: module=%p", module);
	PRINT_IMPORTANT("Thread started: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);

	while (module->state == FMS_RUNNING) {
		tcp_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Thread exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	PRINT_DEBUG("Exited: module=%p", module);
	return NULL;
}

void tcp_get_ff_single(struct fins_module *module) {
	/*
	 *ff = pull();
	 *if (ff) {
	 *	if (fdf) {
	 *		etc...
	 *	} else {
	 *		//fcf
	 *	}
	 *} else if (interrupt) {
	 *	for (each conn) {
	 *		if (conn interrupt) {
	 *
	 *		}
	 *	}
	 *	for (each conn_stub) {
	 *		if (conn_stub interrupt) {
	 *
	 *		}
	 *	}
	 *} else {
	 *	//normal
	 *	if (conn[index] !waiting) {
	 *		send normal
	 *	}
	 *	index++;
	 *}
	 *
	 *events:
	 *ff
	 *	fdf
	 *		find conn
	 *	fcf
	 *		find conn
	 *interrupt
	 *	conn_stub interrupt
	 *		gbn - send seg
	 *		write TO - send FCF
	 *	conn interrupt
	 *		gbn - send seg
	 *		delayed ack - send ack
	 *		write TO - send FCF
	 *normal
	 *	send seg
	 *
	 *Turn accept to single thread & conn_stub to have thread.
	 *When listen / create conn_stub create main thread.
	 *Events:
	 *	listen
	 */
}

void tcp_get_ff(struct fins_module *module) {
	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL); //TODO change logic here, combine with switch_to_interface?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	if (ff->dataOrCtrl == FF_CONTROL) {
		tcp_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			tcp_in_fdf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			tcp_out_fdf(module, ff);
			PRINT_DEBUG("");
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}
}

void tcp_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		tcp_alert(module, ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		tcp_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		tcp_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		tcp_exec(module, ff);
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
}

void tcp_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	uint32_t state = 0;
	uint32_t host_ip = 0;
	uint32_t host_port = 0;
	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;

	uint32_t flags = 0;

	switch (ff->ctrlFrame.param_id) {
	case TCP_EXEC_LISTEN:
		PRINT_DEBUG("param_id=TCP_EXEC_LISTEN (%d)", ff->ctrlFrame.param_id);

		uint32_t backlog = 0;
		secure_metadata_readFromElement(ff->metaData, "backlog", &backlog);
		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);

		tcp_exec_listen(module, ff, host_ip, (uint16_t) host_port, backlog);
		break;
	case TCP_EXEC_ACCEPT: //TODO change this to be part of tcp_fcf_match //???
		PRINT_DEBUG("param_id=TCP_EXEC_ACCEPT (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);
		secure_metadata_readFromElement(ff->metaData, "flags", &flags);

		tcp_exec_accept(module, ff, host_ip, (uint16_t) host_port, flags);
		break;
	case TCP_EXEC_CONNECT:
		PRINT_DEBUG("param_id=TCP_EXEC_CONNECT (%d)", ff->ctrlFrame.param_id);
		secure_metadata_readFromElement(ff->metaData, "flags", &flags);

		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);
		secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);

		tcp_exec_connect(module, ff, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, flags);
		break;
	case TCP_EXEC_CLOSE: //TODO change this to be part of tcp_fcf_match
		PRINT_DEBUG("param_id=TCP_EXEC_CLOSE (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);
		secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);

		tcp_exec_close(module, ff, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
		break;
	case TCP_EXEC_CLOSE_STUB: //TODO change this to be part of tcp_fcf_match
		PRINT_DEBUG("param_id=TCP_EXEC_CLOSE_STUB (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);

		tcp_exec_close_stub(module, ff, host_ip, (uint16_t) host_port);
		break;
	case TCP_EXEC_POLL: //TODO change this to be part of tcp_fcf_match
		PRINT_DEBUG("param_id=TCP_EXEC_POLL (%d)", ff->ctrlFrame.param_id);

		uint32_t initial;
		secure_metadata_readFromElement(ff->metaData, "initial", &initial);
		secure_metadata_readFromElement(ff->metaData, "flags", &flags);

		secure_metadata_readFromElement(ff->metaData, "state", &state);
		secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
		secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);
		if (state > SS_UNCONNECTED) {
			secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
			secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);
		}

		tcp_exec_poll(module, ff, (socket_state) state, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, initial, flags);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void tcp_error(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case TCP_ERROR_TTL:
		PRINT_DEBUG("param_id=TCP_ERROR_TTL (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");

		//TODO finish for
		//if (ff->ctrlFrame.para)
		freeFinsFrame(ff);
		break;
	case TCP_ERROR_DEST_UNREACH:
		PRINT_DEBUG("param_id=TCP_ERROR_DEST_UNREACH (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");

		//TODO finish
		freeFinsFrame(ff);
		break;
	case TCP_ERROR_GET_ADDR:
		PRINT_DEBUG("param_id=TCP_ERROR_GET_ADDR (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");

		//TODO finish
		freeFinsFrame(ff);
		break;
	default:
		PRINT_ERROR("Error unknown param_id: ff=%p, param_id=%d", ff, ff->ctrlFrame.param_id);
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void tcp_init_knobs(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->knobs);

	//metadata_element *exec_elem = secure_config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);

	metadata_element *get_elem = secure_config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);
	elem_add_param(get_elem, TCP_GET_FAST_ENABLED__str, TCP_GET_FAST_ENABLED__id, TCP_GET_FAST_ENABLED__type);
	elem_add_param(get_elem, TCP_GET_FAST_DUPLICATES__str, TCP_GET_FAST_DUPLICATES__id, TCP_GET_FAST_DUPLICATES__type);
	elem_add_param(get_elem, TCP_GET_FAST_RETRANSMITS__str, TCP_GET_FAST_RETRANSMITS__id, TCP_GET_FAST_RETRANSMITS__type);
	elem_add_param(get_elem, TCP_GET_MSS__str, TCP_GET_MSS__id, TCP_GET_MSS__type);

	metadata_element *set_elem = secure_config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	elem_add_param(set_elem, TCP_SET_FAST_ENABLED__str, TCP_SET_FAST_ENABLED__id, TCP_SET_FAST_ENABLED__type);
	elem_add_param(set_elem, TCP_SET_FAST_DUPLICATES__str, TCP_SET_FAST_DUPLICATES__id, TCP_SET_FAST_DUPLICATES__type);
	elem_add_param(set_elem, TCP_SET_FAST_RETRANSMITS__str, TCP_SET_FAST_RETRANSMITS__id, TCP_SET_FAST_RETRANSMITS__type);
	elem_add_param(set_elem, TCP_SET_MSS__str, TCP_SET_MSS__id, TCP_SET_MSS__type);
}

int tcp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_DEBUG("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	tcp_init_knobs(module);

	module->data = secure_malloc(sizeof(struct tcp_data));
	struct tcp_data *md = (struct tcp_data *) module->data;

	sem_init(&md->conn_list_sem, 0, 1);
	md->conn_list = list_create(TCP_CONN_MAX);
	md->conn_stub_list = list_create(TCP_CONN_MAX);

	md->fast_enabled = TCP_FAST_ENABLED_DEFAULT;
	md->fast_duplicates = TCP_FAST_DUPLICATES_DEFAULT;
	md->mss = TCP_MSS_DEFAULT_LARGE;

	return 1;
}

int tcp_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_DEBUG("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	tcp_get_ff(module);

	struct tcp_data *md = (struct tcp_data *) module->data;
	secure_pthread_create(&md->switch_to_tcp_thread, attr, switch_to_tcp, module);

	return 1;
}

int tcp_pause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int tcp_unpause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int tcp_shutdown(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct tcp_data *md = (struct tcp_data *) module->data;

	//TODO expand this
	//shutdown every conn/conn_stub

	PRINT_DEBUG("conn_list wait***************");
	secure_sem_wait(&md->conn_list_sem);

	//list_for_each(md->conn_list, tcp_conn_shutdown);
	/*
	 struct tcp_conn *conn = md->conn_list;
	 struct tcp_conn *old_conn;
	 while (conn) { //change to conn_list_is_empty()
	 old_conn = conn;
	 conn = conn->next;

	 //TODO add conn->sem's
	 tcp_conn_shutdown(old_conn);
	 }
	 */

	//list_for_each(md->conn_stub_list, tcp_conn_shutdown);
	PRINT_DEBUG("conn_list post***************");
	sem_post(&md->conn_list_sem);

	PRINT_IMPORTANT("Joining switch_to_tcp_thread");
	pthread_join(md->switch_to_tcp_thread, NULL);

	return 1;
}

int tcp_release(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct tcp_data *md = (struct tcp_data *) module->data;
	//list_free(md->conn_list, tcp_conn_free); //TODO uncomment/fix
	list_free(md->conn_list, nop_func);
	//list_free(md->conn_stub_list, tcp_conn_free); //TODO uncomment/fix
	list_free(md->conn_stub_list, nop_func);
	sem_destroy(&md->conn_list_sem);

	//free common module data
	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void tcp_dummy(void) {

}

static struct fins_module_ops tcp_ops = { .init = tcp_init, .run = tcp_run, .pause = tcp_pause, .unpause = tcp_unpause, .shutdown = tcp_shutdown, .release =
		tcp_release, };

struct fins_module *tcp_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_DEBUG("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, TCP_LIB);
	module->flows_max = TCP_MAX_FLOWS;
	module->ops = &tcp_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_DEBUG("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
