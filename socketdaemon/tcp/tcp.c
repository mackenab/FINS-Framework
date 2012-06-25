/*
 * @file tcp.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */

//#include <arpa/inet.h>
#include <queueModule.h>
#include "tcp.h"

extern sem_t TCP_to_Switch_Qsem;
extern finsQueue TCP_to_Switch_Queue;

extern sem_t Switch_to_TCP_Qsem;
extern finsQueue Switch_to_TCP_Queue;

struct tcp_connection_stub *conn_stub_list; //The list of current connections we have
uint32_t conn_stub_num;

struct tcp_connection *conn_list; //The list of current connections we have
uint32_t conn_num;

int tcp_serial_num = 0;
int tcp_thread_count = 0;

struct tcp_node *node_create(uint8_t *data, uint32_t len, uint32_t seq_num, uint32_t seq_end) {
	PRINT_DEBUG("node_create: Entered: data=%d, len=%d, seq_num=%d, seq_end=%d", (int)data, len, seq_num, seq_end);

	struct tcp_node *node = (struct tcp_node *) malloc(sizeof(struct tcp_node));
	if (node == NULL) {
		PRINT_ERROR("node_create: Error, unable to create node");
		exit(-1);
	}

	node->data = data;
	node->len = len;
	node->seq_num = seq_num;
	node->seq_end = seq_end;
	node->next = NULL;

	return node;
}

// assumes nodes are in window, -1=less than, 0=problem/equal, 1=greater
int node_compare(struct tcp_node *node, struct tcp_node *cmp, uint32_t win_seq_num, uint32_t win_seq_end) {
	// []=window, |=wrap around , ()=node, {}=cmp, ,=is in that region

	//TODO add time stamps to comparison

	if (win_seq_num <= node->seq_num) { // [ ( | ]
		if (win_seq_num <= node->seq_end) { // [ () | ]
			if (win_seq_num <= cmp->seq_num) { // [ (),{ | ]
				if (win_seq_num <= cmp->seq_end) { // [ (),{} | ]
					if (node->seq_num < cmp->seq_num) { // [ ( { | ]
						if (node->seq_end < cmp->seq_num) { // [ () { | ]
							return -1;
						} else { // [ ( { ) | ]
							return 0;
						}
					} else if (node->seq_num == cmp->seq_num) {
						return 0;
					} else { // [ { ( | ]
						if (cmp->seq_end < node->seq_num) { // [ {} ( | ]
							return 1;
						} else { // [ { ( } | ]
							return 0;
						}
					}
				} else { // [ (),{ | } ]
					if (node->seq_num < cmp->seq_num) { // [ ( { | } ]
						if (node->seq_end < cmp->seq_num) { // [ () { | } ]
							return -1;
						} else { // [ ( { ) | } ]
							return 0;
						}
					} else { // [ { () | } ]
						return 0;
					}
				}
			} else { // [ () | {} ]
				return -1;
			}
		} else { // [ ( | ) ]
			if (win_seq_num <= cmp->seq_num) { // [ (,{ | ) ]
				if (node->seq_num < cmp->seq_num) { // [ ( { | ) ]
					return 0;
				} else { // [ { ( | ) ]
					if (cmp->seq_end < node->seq_num) { // [ {} ( | ) ]
						return 1;
					} else { // [ { ( } | ) ]
						return 0;
					}
				}
			} else { // [ ( | {},) ]
				if (node->seq_end < cmp->seq_num) { // [ ( | ) {} ]
					return -1;
				} else { // [ ( | { ) ]
					return 0;
				}
			}
		}
	} else { // [ | () ]
		if (win_seq_num <= cmp->seq_num) { // [ { | () ]
			if (win_seq_num <= cmp->seq_end) { // [ {} | () ]
				return 1;
			} else { // [ { | },() ]
				if (cmp->seq_end < node->seq_num) { // [ { | } () ]
					return 1;
				} else { // [ { | ( } ]
					return 0;
				}
			}
		} else { // [ | {},() ]
			if (node->seq_num < cmp->seq_num) { // [ | ( {} ]
				if (node->seq_end < cmp->seq_num) { // [ | () {} ]
					return -1;
				} else { // [ | ( { ) ]
					return 0;
				}
			} else if (node->seq_num == cmp->seq_num) {
				return 0;
			} else { // [ | { () ]
				if (cmp->seq_end < node->seq_num) { // [ | {} () ]
					return 1;
				} else { // [ | { ( } ]
					return 0;
				}
			}
		}
	}
}

void node_free(struct tcp_node *node) {
	PRINT_DEBUG("node_free: Entered: node=%d", (int)node);

	if (node->data) {
		free(node->data);
	}
	free(node);
}

struct tcp_queue *queue_create(uint32_t max) {
	PRINT_DEBUG("queue_create: Entered: max=%d", max);

	struct tcp_queue *queue = (struct tcp_queue *) malloc(sizeof(struct tcp_queue));
	if (queue == NULL) {
		PRINT_ERROR("Unable to create queue: max=%d", max);
		exit(-1);
	}

	queue->front = NULL;
	queue->end = NULL;

	queue->max = max;
	queue->len = 0;

	sem_init(&queue->sem, 0, 1);

	return queue;
}

void queue_append(struct tcp_queue *queue, struct tcp_node *node) {
	node->next = NULL;
	if (queue_is_empty(queue)) {
		//queue empty
		queue->front = node;
	} else {
		//node after end
		queue->end->next = node;
	}
	queue->end = node;
	queue->len += node->len;
}

void queue_prepend(struct tcp_queue *queue, struct tcp_node *node) {
	node->next = queue->front;
	queue->front = node;
	queue->len += node->len;
}

void queue_add(struct tcp_queue *queue, struct tcp_node *node, struct tcp_node *prev) {
	node->next = prev->next;
	prev->next = node;
	queue->len += node->len;
}

//assumes the node being inserted is in the window
int queue_insert(struct tcp_queue *queue, struct tcp_node *node, uint32_t win_seq_num, uint32_t win_seq_end) {
	int ret;

	//empty
	if (queue_is_empty(queue)) {
		queue_prepend(queue, node);
		return 1;
	}

	//before front
	ret = node_compare(node, queue->front, win_seq_num, win_seq_end);
	if (ret == -1) { // [ <> () ] |
		queue_prepend(queue, node);
		return 1;
	} else if (ret == 0) {
		return 0;
	}

	//after end
	ret = node_compare(node, queue->end, win_seq_num, win_seq_end);
	if (ret == 1) { // [ {} <> ] |
		queue_append(queue, node);
		return 1;
	} else if (ret == 0) {
		return 0;
	}

	//iterate through queue
	struct tcp_node *temp_node = queue->front;
	while (temp_node->next) {
		ret = node_compare(node, temp_node->next, win_seq_num, win_seq_end);
		if (ret == -1) {
			queue_add(queue, node, temp_node);
			return 1;
		} else if (ret == 0) {
			return 0;
		}

		temp_node = temp_node->next;
	}

	//TODO unable to insert, but didn't trip any overlaps - big error/not possible?
	PRINT_DEBUG("unreachable insert location: (%d, %d) [%d, %d]", node->seq_num, node->seq_end, win_seq_num, win_seq_end);
	return 0;
}

struct tcp_node *queue_find(struct tcp_queue *queue, uint32_t seq_num) {
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

struct tcp_node *queue_remove_front(struct tcp_queue *queue) {
	struct tcp_node *old = queue->front;
	if (old) {
		queue->front = old->next;
		queue->len -= old->len;
	}

	return old;
}

int queue_is_empty(struct tcp_queue *queue) {
	return queue->front == NULL;
}

int queue_has_space(struct tcp_queue *queue, uint32_t len) {
	return queue->len + len <= queue->max;
}

void queue_free(struct tcp_queue *queue) {
	PRINT_DEBUG("queue_free: Entered: queue=%d", (int)queue);

	struct tcp_node *next;

	struct tcp_node *node = queue->front;
	while (node) {
		next = node->next;
		node_free(node);
		node = next;
	}
	free(queue);
}

struct tcp_connection_stub *conn_stub_create(uint32_t host_ip, uint16_t host_port, uint32_t backlog) {
	PRINT_DEBUG("conn_stub_create: Entered: host=%u/%d, backlog=%d", host_ip, host_port, backlog);

	struct tcp_connection_stub *conn_stub = (struct tcp_connection_stub *) malloc(sizeof(struct tcp_connection_stub));
	if (conn_stub == NULL) {
		PRINT_ERROR("Unable to create conn_stub: host=%u/%d, backlog=%d", host_ip, host_port, backlog);
		exit(-1);
	}

	conn_stub->next = NULL;
	sem_init(&conn_stub->sem, 0, 1);
	conn_stub->threads = 0;
	//state?

	conn_stub->host_ip = host_ip;
	conn_stub->host_port = host_port;

	conn_stub->syn_queue = queue_create(backlog);

	//conn_stub->syn_threads = 0;

	//conn_stub->accept_threads = 0;
	sem_init(&conn_stub->accept_wait_sem, 0, 0);

	conn_stub->running_flag = 1;

	return conn_stub;
}

int conn_stub_insert(struct tcp_connection_stub *conn_stub) { //TODO change from append to insertion to ordered LL, return -1 if already inserted
	struct tcp_connection_stub *temp = NULL;

	if (conn_stub_list == NULL) {
		conn_stub_list = conn_stub;
	} else {
		temp = conn_stub_list;
		while (temp->next != NULL) {
			temp = temp->next;
		}

		temp->next = conn_stub;
		conn_stub->next = NULL;
	}

	conn_stub_num++;
	return 1;
}

struct tcp_connection_stub *conn_stub_find(uint32_t host_ip, uint16_t host_port) {
	PRINT_DEBUG("conn_stub_find: Entered: host=%u/%d", host_ip, host_port);

	struct tcp_connection_stub *temp = conn_stub_list;
	while (temp != NULL) { //TODO change to return NULL once conn_list is ordered LL
		if (temp->host_ip == host_ip && temp->host_port == host_port) {
			PRINT_DEBUG("conn_stub_find: Exited: host=%u/%d, conn_stub=%d", host_ip, host_port, (int)temp);
			return temp;
		}
		temp = temp->next;
	}

	PRINT_DEBUG("conn_stub_find: Exited: host=%u/%d, conn_stub=%d", host_ip, host_port, (int)NULL);
	return NULL;
}

void conn_stub_remove(struct tcp_connection_stub *conn_stub) {
	struct tcp_connection_stub *temp = conn_stub_list;
	if (temp == NULL) {
		return;
	}

	if (temp == conn_stub) {
		conn_stub_list = conn_stub_list->next;
		conn_stub_num--;
		return;
	}

	while (temp->next != NULL) {
		if (temp->next == conn_stub) {
			temp->next = conn_stub->next;
			conn_stub_num--;
			break;
		}
		temp = temp->next;
	}
}

int conn_stub_is_empty(void) {
	return conn_stub_num == 0;
}

int conn_stub_has_space(uint32_t len) {
	return conn_stub_num + len <= TCP_CONN_MAX;
}

int conn_stub_send_jinni(struct tcp_connection_stub *conn_stub, uint32_t exec_call, uint32_t ret_val) {
	PRINT_DEBUG("conn_stub_send_jinni: Entered: conn_stub=%d, exec_call=%d, ret_val=%d", (int)conn_stub, exec_call, ret_val);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		return 0;
	}
	metadata_create(params);

	int status = 0;
	metadata_writeToElement(params, "status", &status, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

	metadata_writeToElement(params, "host_ip", &conn_stub->host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &conn_stub->host_port, META_TYPE_INT);

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("ff creation failed, freeing meta=%d", (int) params);
		metadata_destroy(params);
		return 0;
	}

	ff->dataOrCtrl = CONTROL;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = JINNIID;
	ff->destinationID.next = NULL;
	ff->ctrlFrame.senderID = TCPID;
	ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
	ff->ctrlFrame.serialNum = tcp_serial_num++;
	ff->ctrlFrame.metaData = params;

	/*#*/PRINT_DEBUG("");
	if (tcp_to_switch(ff)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

//must have conn_stub->sem before calling & conn_stub_list_sem not be taken
void conn_stub_shutdown(struct tcp_connection_stub *conn_stub) {
	PRINT_DEBUG("conn_stub_shutdown: Entered: conn_stub=%d", (int) conn_stub);

	conn_stub->running_flag = 0;

	//clear all threads using this conn_stub
	while (1) {
		/*#*/PRINT_DEBUG("");
		if (sem_wait(&conn_stub_list_sem)) {
			PRINT_ERROR("conn_stub_list_sem wait prob");
			exit(-1);
		}
		if (conn_stub->threads <= 1) {
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_stub_list_sem);
			break;
		} else {
			//PRINT_DEBUG("conn_stub_shutdown: conn_stub=%d threads=%d", (int)conn_stub, conn_stub->threads);
			sem_post(&conn_stub_list_sem);
		}
		/*#*/PRINT_DEBUG("");
		sem_post(&conn_stub->accept_wait_sem);

		/*#*/PRINT_DEBUG("sem_post: conn_stub=%d", (int) conn_stub);
		sem_post(&conn_stub->sem);
		/*#*/PRINT_DEBUG("sem_wait: conn_stub=%d", (int) conn_stub);
		if (sem_wait(&conn_stub->sem)) {
			PRINT_ERROR("conn_stub->sem wait prob");
			exit(-1);
		}
	}
}

void conn_stub_free(struct tcp_connection_stub *conn_stub) {
	PRINT_DEBUG("conn_stub_free: Entered: conn_stub=%d", (int) conn_stub);

	if (conn_stub->syn_queue)
		queue_free(conn_stub->syn_queue);
	free(conn_stub);
}

void *to_thread(void *local) {
	struct tcp_to_thread_data *to_data = (struct tcp_to_thread_data *) local;
	int id = to_data->id;
	int fd = to_data->fd;
	uint8_t *running = to_data->running;
	uint8_t *flag = to_data->flag;
	uint8_t *waiting = to_data->waiting;
	sem_t *sem = to_data->sem;
	free(to_data);

	int ret;
	uint64_t exp;

	PRINT_DEBUG("to_thread: Entered: id=%d, fd=%d", id, fd);
	while (*running) {
		/*#*/PRINT_DEBUG("");
		ret = read(fd, &exp, sizeof(uint64_t)); //blocking read
		if (!(*running)) {
			break;
		}
		if (ret != sizeof(uint64_t)) {
			//read error
			PRINT_DEBUG("to_thread: Read error: id=%d fd=%d", id, fd);
			continue;
		}

		PRINT_DEBUG("to_thread: throwing flag: id=%d fd=%d", id, fd);
		*flag = 1;
		if (*waiting) {
			PRINT_DEBUG("posting to wait_sem");
			sem_post(sem);
		}
	}

	PRINT_DEBUG("to_thread: Exited: id=%d, fd=%d", id, fd);
	pthread_exit(NULL);
}

void main_closed(struct tcp_connection *conn) {
	PRINT_DEBUG("main_closed: Entered: conn=%d", (int)conn);

	//wait
	conn->main_wait_flag = 1;
}

void main_listen(struct tcp_connection *conn) {
	PRINT_DEBUG("main_listen: Entered: conn=%d", (int)conn);

	//shouldn't happen? leave if combine stub/conn
	//wait
	conn->main_wait_flag = 1;
}

void main_syn_sent(struct tcp_connection *conn) {
	PRINT_DEBUG("main_syn_sent: Entered: conn=%d", (int)conn);
	struct tcp_segment *temp_seg;

	if (conn->to_gbn_flag) {
		//TO, resend SYN, -
		conn->to_gbn_flag = 0;

		conn->issn = 0; //tcp_rand(); //TODO uncomment
		conn->send_seq_num = conn->issn;
		conn->send_seq_end = conn->send_seq_num;

		PRINT_DEBUG( "host: seqs=(%d, %d) win=(%d/%d), rem: seqs=(%d, %d) win=(%d/%d)",
				conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		//TODO add options, for: MSS, max window size!!
		//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

		//conn_change_options(conn, tcp->options, SYN);

		//send SYN
		temp_seg = seg_create(conn);
		seg_update(temp_seg, conn, FLAG_SYN);
		seg_send(temp_seg);
		seg_free(temp_seg);

		conn->main_wait_flag = 0; //handle cases where TO after set waitFlag
		//sem_init(&conn->main_wait_sem, 0, 0);

		conn->timeout *= 2;
		if (conn->timeout > TCP_GBN_TO_MAX) {
			conn->timeout = TCP_GBN_TO_MAX;
		}
		//startTimer(conn->to_gbn_fd, conn->timeout); //TODO uncomment this

	} else {
		conn->main_wait_flag = 1;
	}

	PRINT_DEBUG("main_syn_sent: Exited: conn=%d", (int)conn);
}

void main_syn_recv(struct tcp_connection *conn) {
	PRINT_DEBUG("main_syn_recv: Entered: conn=%d", (int)conn);

	//wait
	conn->main_wait_flag = 1;
}

void main_established(struct tcp_connection *conn) {
	PRINT_DEBUG("main_established: Entered: conn=%d", (int)conn);
	struct tcp_segment *seg;
	uint32_t flight_size;
	double recv_space;
	double cong_space;
	int data_len;
	struct tcp_node *temp_node;

	//can receive, send ACKs, send/resend data, & get ACKs
	if (conn->to_gbn_flag) {
		//gbn timeout
		conn->to_gbn_flag = 0;
		conn->first_flag = 0;
		conn->fast_flag = 0;

		if (queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
			if ((conn->state == FIN_WAIT_1 || conn->state == LAST_ACK) && queue_is_empty(conn->write_queue) && conn->fin_sent
					&& conn->send_seq_num == conn->send_seq_end) {
				conn->fin_sent = 1;
				conn->fin_sep = 1;

				//send fin
				seg = seg_create(conn);
				seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				seg_send(seg);
				seg_free(seg);
			}
		} else {
			conn->gbn_flag = 1;

			//rtt
			conn->rtt_flag = 0;

			//cong control
			switch (conn->cong_state) {
			case SLOWSTART:
				conn->cong_state = AVOIDANCE;
				conn->threshhold = conn->cong_window / 2.0;
				if (conn->threshhold < (double) conn->MSS) {
					conn->threshhold = (double) conn->MSS;
				}
				conn->cong_window = conn->threshhold + 3.0 * conn->MSS;
				break;
			case AVOIDANCE:
			case RECOVERY:
				conn->cong_state = SLOWSTART;
				conn->threshhold = (double) conn->send_max_win; //TODO fix?
				conn->cong_window = (double) conn->MSS;
				break;
			}

			//resend first seg
			conn->gbn_node = conn->send_queue->front;
			seg = (struct tcp_segment *) conn->gbn_node->data;
			if (conn->send_win > (uint32_t) seg->data_len) {
				conn->send_win -= (uint32_t) seg->data_len;
			} else {
				conn->send_win = 0;
			}

			seg_update(seg, conn, FLAG_ACK);
			seg_send(seg);

			//conn->timeout *= 2; //TODO uncomment, should have?
			startTimer(conn->to_gbn_fd, conn->timeout);
			conn->main_wait_flag = 0;
		}
	} else if (conn->fast_flag) {
		//fast retransmit
		conn->fast_flag = 0;

		if (!queue_is_empty(conn->send_queue)) {
			seg = (struct tcp_segment *) conn->send_queue->front->data;
			if (conn->send_win > (uint32_t) seg->data_len) {
				conn->send_win -= (uint32_t) seg->data_len;
			} else {
				conn->send_win = 0;
			}

			seg_update(seg, conn, FLAG_ACK);
			seg_send(seg);
		}
	} else if (conn->gbn_flag) {
		//normal GBN
		if (queue_is_empty(conn->send_queue)) {
			conn->gbn_flag = 0;
		} else {
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//if (conn->send_win && cong_space > 0) { //TODO check if right
			//if (recv_space >= (double) conn->MSS && cong_space >= (double) conn->MSS) {
			if (recv_space > 0 && cong_space > 0) {
				conn->gbn_node = conn->gbn_node->next;
				if (conn->gbn_node) {
					seg = (struct tcp_segment *) conn->gbn_node->data;
					if (conn->send_win > (uint32_t) seg->data_len) {
						conn->send_win -= (uint32_t) seg->data_len;
					} else {
						conn->send_win = 0;
					}

					seg_update(seg, conn, FLAG_ACK);
					seg_send(seg);
				} else {
					conn->gbn_flag = 0;
				}
			} else {
				conn->main_wait_flag = 1;
				//sem_init(&conn->main_wait_flag, 0, 0);
				PRINT_DEBUG("GBN: flagging waitFlag");
			}
		}
	} else {
		//normal
		PRINT_DEBUG("Normal");

		if (queue_is_empty(conn->write_queue)) {
			if (!conn->fin_sent && (conn->state == FIN_WAIT_1 || conn->state == LAST_ACK)) {
				conn->fin_sent = 1;
				conn->fin_sep = 1;

				//send fin
				seg = seg_create(conn);
				seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				seg_send(seg);
				seg_free(seg);
			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("Normal: flagging waitFlag");
			}
		} else {
			flight_size = conn->send_seq_end - conn->send_seq_num;
			recv_space = (double) conn->send_win - (double) flight_size;
			cong_space = conn->cong_window - (double) flight_size;

			//if (conn->send_win && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			//if (conn->send_win_ack + conn->send_win > conn->send_seq_end && flight_size < (uint32_t) conn->send_max_win && cong_space >= (double) conn->MSS) {
			if (recv_space > 0 && cong_space > 0) { //TODO make sure is right!
				PRINT_DEBUG("sending packet");

				if (conn->write_queue->len > (uint32_t) conn->MSS) {
					data_len = (int) conn->MSS;
				} else {
					data_len = (int) conn->write_queue->len;
				}
				if (data_len > (int) conn->send_win) { //leave for now, move to outside if for Nagle
					data_len = (int) conn->send_win;
				}
				if ((double) data_len > cong_space) { //TODO unneeded if (cong_space >= MSS) kept, keep if change to (cong_space > 0)
					data_len = (int) cong_space; //TODO check if converts fine
				}

				seg = seg_create(conn);
				seg_add_data(seg, conn, data_len);

				temp_node = node_create((uint8_t *) seg, data_len, seg->seq_num, seg->seq_num + data_len - 1);
				queue_append(conn->send_queue, temp_node);

				conn->send_seq_end += (uint32_t) data_len;
				if ((int) conn->send_win > data_len) {
					conn->send_win -= (uint32_t) data_len;
				} else {
					conn->send_win = 0;
				}

				if ((conn->state == FIN_WAIT_1 || conn->state == LAST_ACK) && queue_is_empty(conn->write_queue)) {
					conn->fin_sent = 1;
					conn->fin_sep = 0;
					seg_update(seg, conn, FLAG_ACK | FLAG_FIN);
				} else {
					seg_update(seg, conn, FLAG_ACK);
				}
				seg_send(seg);

				if (conn->rtt_flag == 0) {
					gettimeofday(&conn->rtt_stamp, 0);
					conn->rtt_flag = 1;
					conn->rtt_seq_end = conn->send_seq_end;
					PRINT_DEBUG("setting seqEndRTT=%d stampRTT=(%d, %d)\n", conn->rtt_seq_end, (int)conn->rtt_stamp.tv_sec, (int)conn->rtt_stamp.tv_usec);
				}

				if (conn->first_flag) {
					conn->first_flag = 0;
					startTimer(conn->to_gbn_fd, conn->timeout);
				}

				/*#*/PRINT_DEBUG("");
				sem_post(&conn->write_wait_sem); //unstop write_thread if waiting

			} else {
				conn->main_wait_flag = 1;
				PRINT_DEBUG("Normal: flagging waitFlag");
			}
		}

	}

	if (conn->to_delayed_flag) {
		//delayed ACK timeout, send ACK
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		//send ack
		seg = seg_create(conn);
		seg_update(seg, conn, conn->delayed_ack_flags);
		seg_send(seg);

		seg_free(seg);
	}

	PRINT_DEBUG("main_established: Exited: conn=%d", (int)conn);
}

void main_fin_wait_1(struct tcp_connection *conn) {
	PRINT_DEBUG("main_fin_wait_1: Entered: conn=%d", (int)conn);

//merge with established, can still get ACKs, receive, send ACKs, & send/resend data (don't accept new data)
	main_established(conn);
}

void main_fin_wait_2(struct tcp_connection *conn) {
	PRINT_DEBUG("main_fin_wait_2: Entered: conn=%d", (int)conn);

//can still receive, send ACKs
	conn->main_wait_flag = 1;
}

void main_closing(struct tcp_connection *conn) {
	PRINT_DEBUG("main_closing: Entered: conn=%d", (int)conn);

//self, can still get ACKs & send/resend data (don't accept new data)
	main_established(conn);
}

void main_time_wait(struct tcp_connection *conn) {
	PRINT_DEBUG("main_time_wait: Entered: conn=%d", (int)conn);
	struct tcp_segment *seg;

	if (conn->to_gbn_flag) {
		//TO, CLOSE

		if (conn->delayed_flag) {
			//send remaining ACK
			stopTimer(conn->to_delayed_fd);
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;

			//send ack
			seg = seg_create(conn);
			seg_update(seg, conn, conn->delayed_ack_flags);
			seg_send(seg);
			seg_free(seg);
		}

		conn->to_gbn_flag = 0;
		PRINT_DEBUG("main_time_wait: TO, CLOSE: state=%d conn=%d", conn->state, (int)conn);
		conn->state = CLOSED;

		//send ACK to close handler
		conn_send_jinni(conn, EXEC_TCP_CLOSE, 1); //TODO check move to end of last_ack/start of time_wait?

		//conn->main_wait_flag = 0;
		conn_shutdown(conn);
	} else {
		conn->main_wait_flag = 1;

		if (conn->to_delayed_flag) {
			//delayed ACK timeout, send ACK
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;

			//send ack
			seg = seg_create(conn);
			seg_update(seg, conn, conn->delayed_ack_flags);
			seg_send(seg);

			seg_free(seg);
		}
	}

	PRINT_DEBUG("main_time_wait: Exited: conn=%d", (int)conn);
}

void main_close_wait(struct tcp_connection *conn) {
	PRINT_DEBUG("main_close_wait: Entered: conn=%d", (int)conn);

//can still send & get ACKs
	main_established(conn);
}

void main_last_ack(struct tcp_connection *conn) {
	PRINT_DEBUG("main_last_ack: Entered: conn=%d", (int)conn);

//can still get ACKs & send/resend data (don't accept new data)
	main_established(conn);

//TODO augment so that on final ack, call conn_shutdown(conn);
}

void *main_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;

	PRINT_DEBUG("main_thread: Entered: conn=%d", (int)conn);

	/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	while (conn->running_flag) {
		PRINT_DEBUG( "host: seqs=(%d, %d) win=(%d/%d), rem: seqs=(%d, %d) win=(%d/%d)",
				conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
		PRINT_DEBUG("flags: to_gbn=%d fast=%d gbn=%d delayed=%d to_delay=%d first=%d wait=%d ",
				conn->to_gbn_flag, conn->fast_flag, conn->gbn_flag, conn->delayed_flag, conn->to_delayed_flag, conn->first_flag, conn->main_wait_flag);

		switch (conn->state) {
		case CLOSED:
			main_closed(conn);
			break;
		case LISTEN:
			main_listen(conn);
			break;
		case SYN_SENT:
			main_syn_sent(conn);
			break;
		case SYN_RECV:
			main_syn_recv(conn);
			break;
		case ESTABLISHED:
			main_established(conn);
			break;
		case FIN_WAIT_1:
			main_fin_wait_1(conn);
			break;
		case FIN_WAIT_2:
			main_fin_wait_2(conn);
			break;
		case CLOSING:
			main_closing(conn);
			break;
		case TIME_WAIT:
			main_time_wait(conn);
			break;
		case CLOSE_WAIT:
			main_close_wait(conn);
			break;
		case LAST_ACK:
			main_last_ack(conn);
			break;
		}

		if (conn->main_wait_flag && !conn->to_gbn_flag && !conn->to_delayed_flag) {
			/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);

			PRINT_DEBUG("");
			if (sem_wait(&conn->main_wait_sem)) {
				PRINT_ERROR("conn->main_wait_sem wait prob");
				exit(-1);
			}

			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			conn->main_wait_flag = 0;
			//sem_init(&conn->main_wait_sem, 0, 0);
		} else {
			/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
			sem_post(&conn->sem);

			/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
		}
	}

	/*#*/PRINT_DEBUG("");
	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn_remove(conn);
	/*#*/PRINT_DEBUG("");
	sem_post(&conn_list_sem);

//close & free connection
	conn_stop(conn);
	conn_free(conn);

	PRINT_DEBUG("main_thread: Exited: conn=%d", (int)conn);
	pthread_exit(NULL);
}

void stopTimer(int fd) {
	PRINT_DEBUG("stopping timer=%d", fd);

	struct itimerspec its;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

void startTimer(int fd, double millis) {
	PRINT_DEBUG("starting timer=%d m=%f", fd, millis);

	struct itimerspec its; //TODO check if casts right
	its.it_value.tv_sec = (long int) (millis / 1000);
	its.it_value.tv_nsec = (long int) ((fmod(millis, 1000.0) * 1000000) + 0.5);
	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;

	if (timerfd_settime(fd, 0, &its, NULL) == -1) {
		PRINT_ERROR("Error setting timer.");
		exit(-1);
	}
}

struct tcp_connection *conn_create(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("conn_create: Entered: host=%u/%d, rem=%u/%d", host_ip, host_port, rem_ip, rem_port);

	struct tcp_connection *conn = (struct tcp_connection *) malloc(sizeof(struct tcp_connection));
	if (conn == NULL) {
		PRINT_ERROR("Unable to create conn: host=%u/%d, rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
		exit(-1);
	}

	conn->next = NULL;
	sem_init(&conn->sem, 0, 1);
	conn->running_flag = 1;
	conn->threads = 1;
	conn->state = CLOSED;
	PRINT_DEBUG("conn_create: create: state=%d conn=%d", conn->state, (int)conn);

	conn->host_ip = host_ip;
	conn->host_port = host_port;
	conn->rem_ip = rem_ip;
	conn->rem_port = rem_port;

	conn->write_queue = queue_create(TCP_MAX_QUEUE_DEFAULT); //TODO: could wait on this
	conn->send_queue = queue_create(TCP_MAX_QUEUE_DEFAULT);
	conn->recv_queue = queue_create(TCP_MAX_QUEUE_DEFAULT);
//conn->read_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO might not need

	conn->main_wait_flag = 0;
	sem_init(&conn->main_wait_sem, 0, 0);

//conn->write_threads = 0;
	sem_init(&conn->write_sem, 0, 1);
	sem_init(&conn->write_wait_sem, 0, 0);
	conn->index = 0;

//conn->recv_threads = 0;

	conn->first_flag = 1;
	conn->duplicate = 0;
	conn->fast_flag = 0;
	conn->fin_sent = 0;
	conn->fin_sep = 0;

	conn->to_gbn_flag = 0;
	conn->gbn_flag = 0;
	conn->to_gbn_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_gbn_fd == -1) {
		PRINT_ERROR("ERROR: unable to create to_fd.");
		exit(-1);
	}

	conn->delayed_flag = 0;
	conn->delayed_ack_flags = 0;
	conn->to_delayed_flag = 0;
	conn->to_delayed_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_delayed_fd == -1) {
		PRINT_ERROR("ERROR: unable to create delayed_fd.");
		exit(-1);
	}

	conn->send_max_win = TCP_MAX_WINDOW_DEFAULT;
	conn->send_win = conn->send_max_win;
	conn->send_win_seq = 0;
	conn->send_win_ack = 0;
	conn->send_seq_num = 0;
	conn->send_seq_end = 0;

	conn->recv_max_win = TCP_MAX_WINDOW_DEFAULT;
	conn->recv_win = conn->recv_max_win;
	conn->recv_seq_num = 0;
	conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

	conn->MSS = TCP_MSS_DEFAULT;
	conn->cong_state = SLOWSTART;
	conn->cong_window = conn->MSS;

	conn->rtt_flag = 0;
	conn->rtt_first = 1;
	conn->rtt_seq_end = 0;
	memset(&conn->rtt_stamp, 0, sizeof(struct timeval));
	conn->rtt_est = 0;
	conn->rtt_dev = 0;
	conn->timeout = TCP_GBN_TO_DEFAULT;

	conn->active_open = 0;

	conn->tsopt_attempt = 1; //TODO change to 0, trial values atm
	conn->tsopt_enabled = 0;

	conn->sack_attempt = 1;
	conn->sack_enabled = 0;
	conn->sack_len = 0;

	conn->wsopt_attempt = 1;
	conn->wsopt_enabled = 0;
	conn->ws_send = TCP_WS_DEFAULT;
	conn->ws_recv = TCP_WS_DEFAULT;

	//################################################################## alternate implementation, uses 1
	conn->send_buf = NULL;
	conn->send_len = 0;
	conn->send_start = 0;
	conn->send_next = 0;
	conn->send_end = 0;
	conn->send_pkt = (struct tcp_packet *) malloc(sizeof(struct tcp_packet));
	if (conn->send_pkt == NULL) {
		PRINT_ERROR("problem");
	}
	conn->send_pkt->ip_hdr.src_ip = conn->host_ip;
	conn->send_pkt->ip_hdr.dst_ip = conn->rem_ip;
	conn->send_pkt->ip_hdr.zeros = 0;
	conn->send_pkt->ip_hdr.protocol = TCP_PROTOCOL;
	conn->send_pkt->tcp_hdr.src_port = conn->host_port;
	conn->send_pkt->tcp_hdr.dst_port = conn->rem_port;
	/*
	 conn->send_pkt.ip_hdr.src_ip = conn->host_ip;
	 conn->send_pkt.ip_hdr.dst_ip = conn->rem_ip;
	 conn->send_pkt.ip_hdr.zeros = 0;
	 conn->send_pkt.ip_hdr.protocol = TCP_PROTOCOL;
	 conn->send_pkt->tcp_hdr.src_port = conn->host_port;
	 conn->send_pkt->tcp_hdr.dst_port = conn->rem_port;
	 */
	//##################################################################
//start timers
	struct tcp_to_thread_data *gbn_data = (struct tcp_to_thread_data *) malloc(sizeof(struct tcp_to_thread_data));
	gbn_data->id = tcp_thread_count++;
	gbn_data->fd = conn->to_gbn_fd;
	gbn_data->running = &conn->running_flag;
	gbn_data->flag = &conn->to_gbn_flag;
	gbn_data->waiting = &conn->main_wait_flag;
	gbn_data->sem = &conn->main_wait_sem;
	PRINT_DEBUG("conn_create: to_gbn_fd: host=%u/%d, rem=%u/%d conn=%d id=%d to_gbn_fd=%d",
			host_ip, host_port, rem_ip, rem_port, (int)conn, gbn_data->id, conn->to_gbn_fd);
	if (pthread_create(&conn->to_gbn_thread, NULL, to_thread, (void *) gbn_data)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

	struct tcp_to_thread_data *delayed_data = (struct tcp_to_thread_data *) malloc(sizeof(struct tcp_to_thread_data));
	delayed_data->id = tcp_thread_count++;
	delayed_data->fd = conn->to_delayed_fd;
	delayed_data->running = &conn->running_flag;
	delayed_data->flag = &conn->to_delayed_flag;
	delayed_data->waiting = &conn->main_wait_flag;
	delayed_data->sem = &conn->main_wait_sem;
	PRINT_DEBUG("conn_create: to_gbn_fd: host=%u/%d, rem=%u/%d conn=%d id=%d to_gbn_fd=%d",
			host_ip, host_port, rem_ip, rem_port, (int)conn, delayed_data->id, conn->to_delayed_fd);
	if (pthread_create(&conn->to_delayed_thread, NULL, to_thread, (void *) delayed_data)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

//TODO add keepalive timer - implement through gbn timer
//TODO add silly window timer
//TODO add nagel timer

//start main thread
	if (pthread_create(&conn->main_thread, NULL, main_thread, (void *) conn)) {
		PRINT_ERROR("ERROR: unable to create main_thread thread.");
		exit(-1);
	}

	PRINT_DEBUG("conn_create: Exited: host=%u/%d, rem=%u/%d conn=%d", host_ip, host_port, rem_ip, rem_port, (int)conn);
	return conn;
}

int conn_insert(struct tcp_connection *conn) { //TODO change from append to insertion to ordered LL, return -1 if already inserted
	struct tcp_connection *temp = NULL;

	if (conn_list == NULL) {
		conn_list = conn;
	} else {
		temp = conn_list;
		while (temp->next != NULL) {
			temp = temp->next;
		}

		temp->next = conn;
		conn->next = NULL;
	}

	conn_num++;
	return 1;
}

//find a TCP connection with given host addr/port and remote addr/port
//NOTE: this means for incoming IP FF call with (dst_ip, src_ip, dst_p, src_p)
struct tcp_connection *conn_find(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("conn_find: Entered: host=%u/%d, rem=%u/%d", host_ip, host_port, rem_ip, rem_port);

	struct tcp_connection *temp = conn_list;
	while (temp != NULL) { //TODO change to return NULL once conn_list is ordered LL
		if (temp->rem_port == rem_port && /*temp->rem_ip == rem_ip && temp->host_ip == host_ip &&*/temp->host_port == host_port) {
			PRINT_DEBUG("conn_find: Exited: host=%u/%d, rem=%u/%d, conn=%d", host_ip, host_port, rem_ip, rem_port, (int)temp);
			return temp;
		}
		temp = temp->next;
	}

	PRINT_DEBUG("conn_find: Exited: host=%u/%d, rem=%u/%d, conn=%d", host_ip, host_port, rem_ip, rem_port, 0);
	return NULL;
}

void conn_remove(struct tcp_connection *conn) {
	struct tcp_connection *temp = conn_list;
	if (temp == NULL) {
		return;
	}

	if (temp == conn) {
		conn_list = conn_list->next;
		conn_num--;
		return;
	}

	while (temp->next != NULL) {
		if (temp->next == conn) {
			temp->next = conn->next;
			conn_num--;
			break;
		}
		temp = temp->next;
	}
}

int conn_is_empty(void) {
	return conn_num == 0;
}

int conn_has_space(uint32_t len) {
	return conn_num + len <= TCP_CONN_MAX;
}

int conn_send_jinni(struct tcp_connection *conn, uint32_t exec_call, uint32_t ret_val) {
	PRINT_DEBUG("conn_send_jinni: Entered: conn=%d, exec_call=%d, ret_val=%d", (int)conn, exec_call, ret_val);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		return 0;
	}
	metadata_create(params);

	int status = 1;

	int ret = 0;
	ret += metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT) == 0;

	ret += metadata_writeToElement(params, "host_ip", &conn->host_ip, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "host_port", &conn->host_port, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "rem_ip", &conn->rem_ip, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "rem_port", &conn->rem_port, META_TYPE_INT) == 0;

	ret += metadata_writeToElement(params, "status", &status, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT) == 0;
	if (ret) {
		PRINT_ERROR("meta write failed, meta=%d", (int) params);
		metadata_destroy(params);
		return 0;
	}

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("ff creation failed, meta=%d", (int) params);
		metadata_destroy(params);
		return 0;
	}

	ff->dataOrCtrl = CONTROL;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = JINNIID;
	ff->destinationID.next = NULL;
	ff->ctrlFrame.senderID = TCPID;
	ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
	ff->ctrlFrame.serialNum = tcp_serial_num++;
	ff->ctrlFrame.metaData = params;

	/*#*/PRINT_DEBUG("");
	if (tcp_to_switch(ff)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

void conn_shutdown(struct tcp_connection *conn) {
	PRINT_DEBUG("conn_shutdown: Entered: conn=%d", (int) conn);

	conn->running_flag = 0;
	sem_post(&conn->main_wait_sem);
}

void conn_stop(struct tcp_connection *conn) {
	PRINT_DEBUG("conn_stop: Entered: conn=%d", (int) conn);

	conn->running_flag = 0;

//stop threads
	startTimer(conn->to_gbn_fd, 1);
	startTimer(conn->to_delayed_fd, 1);
//TODO stop keepalive timer
//TODO stop silly window timer
//TODO stop nagel timer
//sem_post(&conn->main_wait_sem);
	sem_post(&conn->write_wait_sem);
//sem_post(&conn->write_sem);
//clear all threads using this conn_stub

	while (1) {
		/*#*/PRINT_DEBUG("");
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		if (conn->threads <= 1) {
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_list_sem);
			break;
		} else {
			/*#*/PRINT_DEBUG("conn_stop: conn=%d threads=%d", (int)conn, conn->threads);
			sem_post(&conn_list_sem);
		}

		/*#*/PRINT_DEBUG("sem_post: conn=%d", (int) conn);
		sem_post(&conn->sem);
		/*#*/PRINT_DEBUG("sem_wait: conn=%d", (int) conn);
		if (sem_wait(&conn->sem)) {
			PRINT_ERROR("conn->sem wait prob");
			exit(-1);
		}
	}

	/*#*/PRINT_DEBUG("");
//post to read/write/connect/etc threads
	pthread_join(conn->to_gbn_thread, NULL);
	pthread_join(conn->to_delayed_thread, NULL);
	/*#*/PRINT_DEBUG("");
	pthread_join(conn->main_thread, NULL);
}

void conn_free(struct tcp_connection *conn) {
	PRINT_DEBUG("conn_free: conn=%d", (int) conn);

	if (conn->write_queue)
		queue_free(conn->write_queue);
	if (conn->send_queue)
		queue_free(conn->send_queue);
	if (conn->recv_queue)
		queue_free(conn->recv_queue);
//if (conn->read_queue)
//	queue_free(conn->read_queue);
	free(conn);
}

//Seed the above random number generator
void tcp_srand() {
	srand(time(NULL)); //Just use the standard C random number generator for now
}

//Get a random number to use as a starting sequence number
int tcp_rand() {
	return rand(); //Just use the standard C random number generator for now
}

uint8_t *copy_uint8(uint8_t *ptr, uint8_t val) {
	*ptr++ = val;
	return ptr;
}

uint8_t *copy_uint16(uint8_t *ptr, uint16_t val) {
	*ptr++ = (uint8_t)(val >> 8);
	*ptr++ = (uint8_t)(val & 0x00FF);
	return ptr;
}

uint8_t *copy_uint32(uint8_t *ptr, uint32_t val) {
	*ptr++ = (uint8_t)(val >> 24);
	*ptr++ = (uint8_t)((val & 0x00FF0000) >> 16);
	*ptr++ = (uint8_t)((val & 0x0000FF00) >> 8);
	*ptr++ = (uint8_t)(val & 0x000000FF);
	return ptr;
}

uint8_t *copy_uint64(uint8_t *ptr, uint64_t val) {
	*ptr++ = (uint8_t)(val >> 56);
	*ptr++ = (uint8_t)((val & 0x00FF000000000000) >> 48);
	*ptr++ = (uint8_t)((val & 0x0000FF0000000000) >> 40);
	*ptr++ = (uint8_t)((val & 0x000000FF00000000) >> 32);
	*ptr++ = (uint8_t)((val & 0x00000000FF000000) >> 24);
	*ptr++ = (uint8_t)((val & 0x0000000000FF0000) >> 16);
	*ptr++ = (uint8_t)((val & 0x000000000000FF00) >> 8);
	*ptr++ = (uint8_t)(val & 0x00000000000000FF);
	return ptr;
}

struct finsFrame *seg_to_fdf(struct tcp_segment *seg) {
	PRINT_DEBUG("seg_to_fdf: Entered: seg=%d", (int)seg);

	PRINT_DEBUG( "seg_to_fdf: info: src=%u/%d, dst=%u/%d, seq=%d, len=%d, opts=%d, ack=%d, flags=%d, win=%d, checksum=%d F=%d, S=%d R=%d A=%d",
			seg->src_ip, seg->src_port, seg->dst_ip, seg->dst_port, seg->seq_num, seg->data_len, seg->opt_len, seg->ack_num, seg->flags, seg->win_size, seg->checksum, seg->flags&FLAG_FIN, (seg->flags&FLAG_SYN)>>1, (seg->flags&FLAG_RST)>>2, (seg->flags&FLAG_ACK)>>4);
	PRINT_DEBUG( "seg_to_fdf: info: host: src=%u/%d, dst=%u/%d, netw: src=%u/%d, dst=%u/%d",
			ntohl(seg->src_ip), ntohs(seg->src_port), ntohl(seg->dst_ip), ntohs(seg->dst_port), htonl(seg->src_ip), htons(seg->src_port), htonl(seg->dst_ip), htons(seg->dst_port));

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("seg_to_fdf: failed to create matadata: seg=%d", (int)seg);
		return NULL;
	}
	metadata_create(params);

	int ret = 0;
	ret += metadata_writeToElement(params, "src_ip", &seg->src_ip, META_TYPE_INT) == 0; //Write the source ip in
	ret += metadata_writeToElement(params, "dst_ip", &seg->dst_ip, META_TYPE_INT) == 0; //And the destination ip
	ret += metadata_writeToElement(params, "src_port", &seg->src_port, META_TYPE_INT) == 0; //Write the source port in
	ret += metadata_writeToElement(params, "dst_port", &seg->dst_port, META_TYPE_INT) == 0; //And the destination port

	uint32_t protocol = (uint32_t) TCP_PROTOCOL;
	ret += metadata_writeToElement(params, "protocol", &protocol, META_TYPE_INT) == 0;

	if (ret) {
		PRINT_ERROR("seg_to_fdf: failed matadata write: seg=%d meta=%d", (int)seg, (int)params);
		metadata_destroy(params);
		return NULL;
	}

	struct finsFrame *ff = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("seg_to_fdf: failed to create ff: seg=%d meta=%d", (int)seg, (int)params);
		metadata_destroy(params);
		return NULL;
	}

	ff->dataOrCtrl = DATA; //leave unset?
	ff->destinationID.id = IPV4ID; // destination module ID
	ff->destinationID.next = NULL;
	ff->dataFrame.directionFlag = DOWN; // ingress or egress network data; see above
	ff->dataFrame.metaData = params;
	ff->dataFrame.pduLength = seg->data_len + TCP_HEADER_BYTES(seg->flags); //Add in the header size for this, too
	ff->dataFrame.pdu = (unsigned char *) malloc(ff->dataFrame.pduLength);
	PRINT_DEBUG("seg_to_fdf: seg=%d ff=%d meta=%d data_len=%d hdr=%d pduLength=%d",
			(int)seg, (int)ff, (int) ff->dataFrame.metaData, seg->data_len, TCP_HEADER_BYTES(seg->flags), ff->dataFrame.pduLength);

	if (ff->dataFrame.pdu == NULL) {
		PRINT_ERROR("seg_to_fdf: failed to create pdu: seg=%d meta=%d", (int)seg, (int)params);
		freeFinsFrame(ff);
		return NULL;
	}

	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	/*
	 uint8_t *ptr = ff->dataFrame.pdu;
	 ptr = copy_uint16(ptr, seg->src_port);
	 ptr = copy_uint16(ptr, seg->dst_port);
	 ptr = copy_uint32(ptr, seg->seq_num);
	 ptr = copy_uint32(ptr, seg->ack_num);
	 ptr = copy_uint16(ptr, seg->flags);
	 ptr = copy_uint16(ptr, seg->win_size);
	 ptr = copy_uint16(ptr, seg->checksum);
	 ptr = copy_uint16(ptr, seg->urg_pointer);
	 */

	struct tcpv4_header *hdr = (struct tcpv4_header *) ff->dataFrame.pdu;
	hdr->src_port = htons(seg->src_port);
	hdr->dst_port = htons(seg->dst_port);
	hdr->seq_num = htonl(seg->seq_num);
	hdr->ack_num = htonl(seg->ack_num);
	hdr->flags = htons(seg->flags);
	hdr->win_size = htons(seg->win_size);
	hdr->checksum = htons(seg->checksum);
	hdr->urg_pointer = htons(seg->urg_pointer);

	if (seg->opt_len > 0) {
		memcpy(hdr->options, seg->options, seg->opt_len);
		//ptr += seg->opt_len;
	}

	if (seg->data_len > 0) {
		uint8_t *ptr = hdr->options + seg->opt_len;
		memcpy(ptr, seg->data, seg->data_len);
		//ptr += seg->data_len;
	}

	PRINT_DEBUG("seg_to_fdf: Exited: seg=%d ff=%d meta=%d", (int)seg, (int)ff, (int) ff->dataFrame.metaData);
	return ff;
}

struct tcp_segment *fdf_to_seg(struct finsFrame *ff) {
	PRINT_DEBUG("fdf_to_seg: Entered: ff=%d", (int)ff);

	if (ff->dataFrame.pduLength < MIN_TCP_HEADER_BYTES) {
		PRINT_ERROR("pduLength too small");
		return NULL;
	}

	struct tcp_segment *seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	if (!seg) {
		PRINT_ERROR("seg malloc error");
		return NULL;
	}

	metadata *params = ff->dataFrame.metaData;
	if (params == NULL) {
		PRINT_ERROR("metadata NULL");
		free(seg);
		return NULL;
	}

	int ret = 0;
	ret += metadata_readFromElement(params, "src_ip", &seg->src_ip) == 0; //host
	ret += metadata_readFromElement(params, "dst_ip", &seg->dst_ip) == 0; //remote

	uint32_t protocol;
	ret += metadata_readFromElement(params, "protocol", &protocol) == 0;

	if (ret || (uint16_t) protocol != TCP_PROTOCOL) {
		PRINT_DEBUG("fdf_to_seg: error: ret=%d, protocol=%d", ret, protocol);
		free(seg);
		return NULL;
	}

	/*
	 uint8_t *ptr = ff->dataFrame.pdu;

	 //For big-vs-little endian issues, I shall shift everything and deal with it manually here
	 seg->src_port = (uint16_t)(*ptr++) << 8;
	 seg->src_port += *ptr++;

	 seg->dst_port = (uint16_t)(*ptr++) << 8;
	 seg->dst_port += *ptr++;

	 seg->seq_num = (uint32_t)(*ptr++) << 24;
	 seg->seq_num += (uint32_t)(*ptr++) << 16;
	 seg->seq_num += (uint32_t)(*ptr++) << 8;
	 seg->seq_num += *ptr++;

	 seg->ack_num = (uint32_t)(*ptr++) << 24;
	 seg->ack_num += (uint32_t)(*ptr++) << 16;
	 seg->ack_num += (uint32_t)(*ptr++) << 8;
	 seg->ack_num += *ptr++;

	 seg->flags = (uint16_t)(*ptr++) << 8;
	 seg->flags += *ptr++;

	 seg->win_size = (uint16_t)(*ptr++) << 8;
	 seg->win_size += *ptr++;

	 seg->checksum = (uint16_t)(*ptr++) << 8;
	 seg->checksum += *ptr++;

	 seg->urg_pointer = (uint16_t)(*ptr++) << 8;
	 seg->urg_pointer += *ptr++;

	 //host_IP_netformat = addr->sin_addr.s_addr;
	 //PRINT_DEBUG("bind address: host=%s/%d host_IP_netformat=%d", inet_ntoa(addr->sin_addr), hostport, host_IP_netformat);

	 //Now copy the rest of the data, starting with the options
	 seg->opt_len = TCP_OPTIONS_BYTES(seg->flags);
	 if (seg->opt_len > 0) {
	 //seg->options = (uint8_t *) malloc(MAX_TCP_OPTIONS_BYTES);
	 memcpy(seg->options, ptr, seg->opt_len);
	 ptr += seg->opt_len;
	 }
	 */

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
		seg->data = (uint8_t *) malloc(seg->data_len);
		uint8_t *ptr = hdr->options + seg->opt_len;
		memcpy(seg->data, ptr, seg->data_len);
		//ptr += seg->data_len;
	}

	seg->seq_end = seg->seq_num + seg->data_len;

	PRINT_DEBUG( "fdf_to_seg: info: src=%u/%d, dst=%u/%d, seq=%d, len=%d, opts=%d, ack=%d, flags=%d, win=%d, checksum=%d F=%d, S=%d R=%d A=%d",
			seg->src_ip, seg->src_port, seg->dst_ip, seg->dst_port, seg->seq_num, seg->data_len, seg->opt_len, seg->ack_num, seg->flags, seg->win_size, seg->checksum, seg->flags&FLAG_FIN, (seg->flags&FLAG_SYN)>>1, (seg->flags&FLAG_RST)>>2, (seg->flags&FLAG_ACK)>>4);
	PRINT_DEBUG( "fdf_to_seg: info: host: src=%u/%d, dst=%u/%d, netw: src=%u/%d, dst=%u/%d",
			ntohl(seg->src_ip), ntohs(seg->src_port), ntohl(seg->dst_ip), ntohs(seg->dst_port), htonl(seg->src_ip), htons(seg->src_port), htonl(seg->dst_ip), htons(seg->dst_port));

	return seg;
}

struct tcp_segment *seg_create(struct tcp_connection *conn) {
	struct tcp_segment *seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	if (seg == NULL) {
		PRINT_ERROR("Unable to create tcp_segment: conn=%d", (int) conn);
		exit(-1);
	}

	seg->src_ip = conn->host_ip;
	seg->dst_ip = conn->rem_ip;
	seg->src_port = conn->host_port;
	seg->dst_port = conn->rem_port;
	seg->seq_num = conn->send_seq_end;
	seg->seq_end = seg->seq_num;
	seg->ack_num = 0;
	seg->flags = 0;
	seg->win_size = 0;
	seg->checksum = 0;
	seg->urg_pointer = 0;
	seg->opt_len = 0;
	//seg->options = malloc(MAX_TCP_OPTIONS_BYTES);
	seg->data_len = 0;
	seg->data = NULL;

	return seg;
}

void seg_add_data(struct tcp_segment *seg, struct tcp_connection *conn, int data_len) {
	int avail;
	struct tcp_node *temp_node;

	seg->data_len = data_len;
	seg->seq_end = seg->seq_num + seg->data_len;
	seg->data = (uint8_t *) malloc(data_len);
	uint8_t *ptr = seg->data;

	int output = data_len;
	while (output && !queue_is_empty(conn->write_queue)) {
		avail = conn->write_queue->front->len - conn->index;
		if (output < avail) {
			memcpy(ptr, conn->write_queue->front->data + conn->index, output);
			ptr += output;
			conn->index += output;
			output -= output;
		} else {
			memcpy(ptr, conn->write_queue->front->data + conn->index, avail);
			ptr += avail;
			conn->index = 0;
			output -= avail;

			temp_node = queue_remove_front(conn->write_queue);
			node_free(temp_node);
		}
	}
}

void seg_add_options(struct tcp_segment *seg, struct tcp_connection *conn) {
	PRINT_DEBUG("seg_add_options: Entered: conn=%d, seg=%d", (int)conn, (int)seg);

	uint32_t i;
	uint32_t len;
	uint8_t *pt;
	struct tcp_node *node;
	uint32_t left;
	uint32_t right;

	//add options //TODO implement options system
	switch (conn->state) {
	case SYN_SENT:
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
		seg->opt_len += TCP_MSS_BYTES;
		*pt++ = TCP_MSS;
		*pt++ = TCP_MSS_BYTES;
		*(uint16_t *) pt = htons(conn->MSS);
		pt += sizeof(uint16_t);

		if (conn->sack_attempt) {
			if (!conn->tsopt_attempt) {
				seg->opt_len += 2;
				*pt++ = TCP_NOP; //NOP
				*pt++ = TCP_NOP; //NOP
			}

			seg->opt_len += TCP_SACK_PERM_BYTES;
			*pt++ = TCP_SACK_PERM;
			*pt++ = TCP_SACK_PERM_BYTES;
		}

		if (conn->tsopt_attempt) {
			if (!conn->sack_attempt) {
				seg->opt_len += 2;
				*pt++ = TCP_NOP; //NOP
				*pt++ = TCP_NOP; //NOP
			}
			seg->opt_len += TCP_TS_BYTES;
			*pt++ = TCP_TS;
			*pt++ = TCP_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL)));
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = 0;
			pt += sizeof(uint32_t);
		}

		if (conn->wsopt_attempt) {
			seg->opt_len++;
			*pt++ = TCP_NOP; //NOP

			seg->opt_len += TCP_WS_BYTES;
			*pt++ = TCP_WS; //WS opt
			*pt++ = TCP_WS_BYTES;
			*pt++ = conn->ws_recv; //believe default is 6
		}
		break;
	case SYN_RECV:
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
		seg->opt_len += TCP_MSS_BYTES;
		*pt++ = TCP_MSS;
		*pt++ = TCP_MSS_BYTES;
		*(uint16_t *) pt = htons(conn->MSS);
		pt += sizeof(uint16_t);

		if (conn->sack_enabled) {
			if (!conn->tsopt_enabled) {
				seg->opt_len += 2;
				*pt++ = TCP_NOP; //NOP
				*pt++ = TCP_NOP; //NOP
			}

			seg->opt_len += TCP_SACK_PERM_BYTES;
			*pt++ = TCP_SACK_PERM;
			*pt++ = TCP_SACK_PERM_BYTES;
		}

		if (conn->tsopt_enabled) {
			if (!conn->sack_enabled) {
				seg->opt_len += 2;
				*pt++ = TCP_NOP; //NOP
				*pt++ = TCP_NOP; //NOP
			}

			seg->opt_len += TCP_TS_BYTES;
			*pt++ = TCP_TS;
			*pt++ = TCP_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL))); //TODO complete
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = 0;
			pt += sizeof(uint32_t);
		}

		if (conn->wsopt_enabled) {
			seg->opt_len++;
			*pt++ = TCP_NOP; //NOP

			seg->opt_len += TCP_WS_BYTES;
			*pt++ = TCP_WS; //WS opt
			*pt++ = TCP_WS_BYTES;
			*pt++ = conn->ws_recv; //believe default is 6
		}
		break;
	case ESTABLISHED:
		seg->opt_len = 0;
		pt = seg->options;

		if (conn->tsopt_enabled) {
			seg->opt_len += 2;
			*pt++ = TCP_NOP; //NOP
			*pt++ = TCP_NOP; //NOP

			seg->opt_len += TCP_TS_BYTES;
			*pt++ = TCP_TS;
			*pt++ = TCP_TS_BYTES;

			*(uint32_t *) pt = htonl(((int) time(NULL))); //TODO complete
			pt += sizeof(uint32_t);
			*(uint32_t *) pt = 0;
			pt += sizeof(uint32_t);
		}

		if (conn->sack_enabled) {
			seg->opt_len += 2;
			*pt++ = TCP_NOP; //NOP
			*pt++ = TCP_NOP; //NOP

			seg->opt_len += 2;
			*pt++ = TCP_SACK;
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
				seg->opt_len += 2 * sizeof(uint32_t);
				*len_pt += 2 * sizeof(uint32_t);

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

void seg_update_options(struct tcp_segment *seg, struct tcp_connection *conn) {
	PRINT_DEBUG("seg_update_options: Entered: conn=%d, seg=%d", (int)conn, (int)seg);

	//update options, since options are always 40 bytes long, so can just rewrite it
}

void seg_update(struct tcp_segment *seg, struct tcp_connection *conn, uint16_t flags) { //updates ack/win/opts/timestamps
	//clear flags
	//memset(&seg->flags, 0, sizeof(uint16_t));
	//seg->flags &= ~FLAG_PSH;
	seg->flags |= (flags & (FLAG_CONTROL | FLAG_ECN)); //TODO this is where FLAG_FIN, etc should be added

	switch (conn->state) {
	case CLOSED:
		break;
	case LISTEN:
		break;
	case SYN_SENT:
		break;
	case SYN_RECV:
		break;
	case ESTABLISHED:
		seg_delayed_ack(seg, conn);
		break;
	case FIN_WAIT_1:
		seg_delayed_ack(seg, conn);
		if (conn->fin_sent && !conn->fin_sep && seg->seq_num + seg->data_len == conn->send_seq_end) { //TODO remove?
		//send fin
			PRINT_DEBUG("seg_update: add FIN");
			seg->flags |= FLAG_FIN;
		}
		break;
	case FIN_WAIT_2:
		break;
	case CLOSING:
		seg_delayed_ack(seg, conn);
		break;
	case CLOSE_WAIT:
		seg_delayed_ack(seg, conn);
		break;
	case LAST_ACK:
		seg_delayed_ack(seg, conn); //TODO move outside of switch? get rid of switch
		if (conn->fin_sent && !conn->fin_sep && seg->seq_num + seg->data_len == conn->send_seq_end) {
			//send fin
			PRINT_DEBUG("seg_update: add FIN");
			seg->flags |= FLAG_FIN;
		}
		break;
	case TIME_WAIT:
		break;
	}

	if (flags & FLAG_ACK_PLUS) {
		seg->ack_num = conn->recv_seq_num + 1;
	} else if (seg->flags & FLAG_ACK) {
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
		seg_add_options(seg, conn);
	} else {
		seg_add_options(seg, conn);
	}

	//TODO PAWS

	int offset = seg->opt_len / 4; //TODO improve logic, use ceil? round up
	seg->flags |= ((MIN_TCP_HEADER_WORDS + offset) << 12) & FLAG_DATAOFFSET;
	PRINT_DEBUG("seg_update: offset=%d header_len=%d pkt_len=%d", offset, TCP_HEADER_BYTES(seg->flags), TCP_HEADER_BYTES(seg->flags)+seg->data_len);

//TODO alt checksum
	seg->checksum = seg_checksum(seg);
}

uint16_t seg_checksum(struct tcp_segment *seg) { //TODO check if checksum works, check rollover
	int i;
//TODO add TCP alternate checksum w/data in options (15)

	uint32_t sum = 0;

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

//options, opt_len always has to be a factor of 2
	uint8_t * ptr = (uint8_t *) seg->options;
	for (i = 0, ptr--; i < seg->opt_len; i += 2) {
		sum += (*++ptr << 8) + *++ptr;
	}

//data
	ptr = (uint8_t *) seg->data;
	for (i = 1, ptr--; i < seg->data_len; i += 2) {
		sum += (*++ptr << 8) + *++ptr;
	}

	if (seg->data_len & 0x1) {
		sum += *++ptr << 8;
	}

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	sum = ~sum;
	return htons((uint16_t) sum);
}

int seg_send(struct tcp_segment *seg) {
	PRINT_DEBUG("seg_send: Entered: seg=%d", (int)seg);

	struct finsFrame *ff = seg_to_fdf(seg);

	/*//###############################
	 struct tcp_segment *seg_test = fdf_to_seg(ff);
	 if (seg_test) {
	 if (seg->src_ip != seg_test->src_ip)
	 PRINT_DEBUG("diff: src_ip: seg=%d, test=%d", seg->src_ip, seg_test->src_ip);
	 if (seg->dst_ip != seg_test->dst_ip)
	 PRINT_DEBUG("diff: dst_ip: seg=%d, test=%d", seg->dst_ip, seg_test->dst_ip);
	 if (seg->src_port != seg_test->src_port)
	 PRINT_DEBUG("diff: src_port: seg=%d, test=%d", seg->src_port, seg_test->src_port);
	 if (seg->dst_port != seg_test->dst_port)
	 PRINT_DEBUG("diff: dst_port: seg=%d, test=%d", seg->dst_port, seg_test->dst_port);
	 if (seg->seq_num != seg_test->seq_num)
	 PRINT_DEBUG("diff: seq_num: seg=%d, test=%d", seg->seq_num, seg_test->seq_num);
	 if (seg->ack_num != seg_test->ack_num)
	 PRINT_DEBUG("diff: ack_num: seg=%d, test=%d", seg->ack_num, seg_test->ack_num);
	 if (seg->flags != seg_test->flags)
	 PRINT_DEBUG("diff: flags: seg=%d, test=%d", seg->flags, seg_test->flags);
	 if (seg->win_size != seg_test->win_size)
	 PRINT_DEBUG("diff: win_size: seg=%d, test=%d", seg->win_size, seg_test->win_size);
	 if (seg->checksum != seg_test->checksum)
	 PRINT_DEBUG("diff: checksum: seg=%d, test=%d", seg->checksum, seg_test->checksum);
	 if (seg->urg_pointer != seg_test->urg_pointer)
	 PRINT_DEBUG("diff: urg_pointer: seg=%d, test=%d", seg->urg_pointer, seg_test->urg_pointer);
	 if (seg->opt_len != seg_test->opt_len)
	 PRINT_DEBUG("diff: opt_len: seg=%d, test=%d", seg->opt_len, seg_test->opt_len);
	 if (seg->data_len != seg_test->data_len)
	 PRINT_DEBUG("diff: data_len: seg=%d, test=%d", seg->data_len, seg_test->data_len);
	 //check options/data?
	 }
	 //###############################*/

	if (ff) {
		if (tcp_to_switch(ff)) {
			PRINT_DEBUG("seg_send: Exited, normal: seg=%d ff=%d meta=%d", (int)seg, (int)ff, (int) ff->dataFrame.metaData);
			return 1;
		} else {
			PRINT_DEBUG("seg_send: Exited, failed: seg=%d ff=%d meta=%d", (int)seg, (int)ff, (int) ff->dataFrame.metaData);
			freeFinsFrame(ff);
			return 0;
		}
	} else {
		PRINT_DEBUG("seg_send: Exited, failed: seg=%d ff=%d meta=%d", (int)seg, (int)0, (int)0);
		return 0;
	}
}

void seg_free(struct tcp_segment *seg) {
	PRINT_DEBUG("seg_free: Entered: seg=%d", (int)seg);

	if (seg->data_len && seg->data) {
		free(seg->data); //keep data ptr
	}

	if (seg->opt_len && seg->options) {
		//free(seg->options); //TODO change when have options object
	}
	free(seg);
}

void seg_delayed_ack(struct tcp_segment *seg, struct tcp_connection *conn) {
	if (conn->delayed_flag) {
		stopTimer(conn->to_delayed_fd);
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		seg->flags |= conn->delayed_ack_flags;
	}
}

// 0=out of window, 1=in window
int in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end) {
//check if tcp_seg is in connection window
//Notation: [=rem_seq_num, ]=rem_seq_end, <=node->seq_num, >=node->seq_end, |=rollover,
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

int in_window_overlaps(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end) {
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

int metadata_read_conn(metadata *params, uint32_t *status, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port) {
	uint32_t host_port_buf;
	uint32_t rem_port_buf;

	int ret = 0;
	ret += metadata_readFromElement(params, "status", status) == 0;

	ret += metadata_readFromElement(params, "host_ip", host_ip) == 0;
	ret += metadata_readFromElement(params, "host_port", &host_port_buf) == 0;
	*host_port = (uint16_t) host_port_buf;

	if (ret && *status) {
		ret += metadata_readFromElement(params, "rem_ip", rem_ip) == 0;
		ret += metadata_readFromElement(params, "rem_port", &rem_port_buf) == 0;
		*rem_port = (uint16_t) rem_port_buf;
	}

	return !ret;
}

void metadata_write_conn(metadata *params, uint32_t *status, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port) {
	uint32_t host_port_buf;
	uint32_t rem_port_buf;

	metadata_writeToElement(params, "status", status, META_TYPE_INT);

	metadata_writeToElement(params, "host_ip", host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", host_port, META_TYPE_INT);

	if (*status) {
		metadata_writeToElement(params, "rem_ip", rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", rem_port, META_TYPE_INT);
	}
}

void tcp_init() {

	PRINT_DEBUG("TCP started");

	conn_stub_list = NULL;
	conn_stub_num = 0;
	sem_init(&conn_stub_list_sem, 0, 1);

	conn_list = NULL;
	conn_num = 0;
	sem_init(&conn_list_sem, 0, 1);

	tcp_srand();
	while (1) {
		tcp_get_FF();
		PRINT_DEBUG("");
		//	free(pff);
	}
}

void tcp_get_FF() {

	struct finsFrame *ff;

	PRINT_DEBUG("");
	do {
		sem_wait(&Switch_to_TCP_Qsem);
		ff = read_queue(Switch_to_TCP_Queue);
		sem_post(&Switch_to_TCP_Qsem);
	} while (ff == NULL);
	PRINT_DEBUG("");

	if (ff->dataOrCtrl == CONTROL) {
		tcp_fcf(ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		if ((ff->dataFrame).directionFlag == UP) {
			tcp_in_fdf(ff);
			PRINT_DEBUG("");
		} else { //directionFlag==DOWN
			tcp_out_fdf(ff);
			PRINT_DEBUG("");
		}
	}
}

void tcp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("tcp_fcf: Entered");

//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		tcp_read_param(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		tcp_set_param(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		tcp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("tcp_fcf: opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		break;
	default:
		PRINT_DEBUG("tcp_fcf: opcode=default (%d)", ff->ctrlFrame.opcode);
		break;
	}
}

void tcp_exec(struct finsFrame *ff) {
	int ret = 0;
	uint32_t exec_call;
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;
	uint32_t backlog;
	uint32_t flags;

	PRINT_DEBUG("tcp_exec: Entered: ff=%d", (int)ff);

	metadata *params = ff->ctrlFrame.metaData;
	if (params) {
		ret = metadata_readFromElement(params, "exec_call", &exec_call) == 0;
		switch (exec_call) {
		case EXEC_TCP_LISTEN:
			PRINT_DEBUG("tcp_exec: exec_call=EXEC_TCP_LISTEN (%d)", exec_call);

			ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
			ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
			ret += metadata_readFromElement(params, "backlog", &backlog) == 0;

			if (ret) {
				PRINT_ERROR("tcp_exec: ret=%d", ret);
				//TODO send nack
			} else {
				tcp_exec_listen(host_ip, (uint16_t) host_port, backlog);
			}
			break;
		case EXEC_TCP_CONNECT:
			PRINT_DEBUG("tcp_exec: exec_call=EXEC_TCP_CONNECT (%d)", exec_call);

			ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
			ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
			ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == 0;
			ret += metadata_readFromElement(params, "rem_port", &rem_port) == 0;

			if (ret) {
				PRINT_ERROR("tcp_exec: ret=%d", ret);
				//TODO send nack
			} else {
				tcp_exec_connect(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port); //TODO add ff->ctrlFrame.serialNum?
			}
			break;
		case EXEC_TCP_ACCEPT:
			PRINT_DEBUG("tcp_exec: exec_call=EXEC_TCP_ACCEPT (%d)", exec_call);

			ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
			ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
			ret += metadata_readFromElement(params, "flags", &flags) == 0;

			if (ret) {
				PRINT_ERROR("tcp_exec: ret=%d", ret);
				//TODO send nack
			} else {
				tcp_exec_accept(host_ip, (uint16_t) host_port, flags);
			}
			break;
		case EXEC_TCP_CLOSE:
			PRINT_DEBUG("tcp_exec: exec_call=EXEC_TCP_CLOSE (%d)", exec_call);

			ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
			ret += metadata_readFromElement(params, "host_port", &host_port) == 0;
			ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == 0;
			ret += metadata_readFromElement(params, "rem_port", &rem_port) == 0;

			if (ret) {
				PRINT_ERROR("tcp_exec: ret=%d", ret);
				//TODO send nack
			} else {
				tcp_exec_close(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
			}
			break;
		case EXEC_TCP_CLOSE_STUB:
			PRINT_DEBUG("tcp_exec: exec_call=EXEC_TCP_CLOSE_STUB (%d)", exec_call);

			ret += metadata_readFromElement(params, "host_ip", &host_ip) == 0;
			ret += metadata_readFromElement(params, "host_port", &host_port) == 0;

			if (ret) {
				PRINT_ERROR("tcp_exec: ret=%d", ret);
				//TODO send nack
			} else {
				tcp_exec_close_stub(host_ip, (uint16_t) host_port);
			}
			break;
		default:
			PRINT_ERROR("tcp_exec: Error unknown exec_call=%d", exec_call);
			//TODO implement?
			break;
		}
	} else {
		//TODO send nack
		PRINT_ERROR("tcp_exec: Error fcf.metadata==NULL");
	}

	freeFinsFrame(ff); //TODO remove? pass ff so that it can be passed back eventually
}

int tcp_to_switch(struct finsFrame *ff) {
	if (ff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("tcp_to_switch: Entered: ff=%d meta=%d", (int)ff, (int) ff->ctrlFrame.metaData);
	} else {
		PRINT_DEBUG("tcp_to_switch: Entered: ff=%d meta=%d", (int)ff, (int) ff->dataFrame.metaData);
	}
	if (sem_wait(&TCP_to_Switch_Qsem)) {
		PRINT_ERROR("TCP_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, TCP_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&TCP_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&TCP_to_Switch_Qsem);

	return 0;
}

int tcp_fcf_to_jinni(uint32_t status, uint32_t exec_call, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, uint32_t ret_val) {
	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		return 0;
	}
	metadata_create(params);

	metadata_writeToElement(params, "status", &status, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (status) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("ff creation failed, meta=%d", (int)params);
		metadata_destroy(params);
		return 0;
	}

	ff->dataOrCtrl = CONTROL;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = JINNIID;
	ff->destinationID.next = NULL;
	ff->ctrlFrame.senderID = TCPID;
	ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
	ff->ctrlFrame.serialNum = tcp_serial_num++;
	ff->ctrlFrame.metaData = params;

	/*#*/PRINT_DEBUG("");
	if (tcp_to_switch(ff)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

int tcp_fdf_to_jinni(u_char *dataLocal, int len, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("tcp_fdf_to_jinni: Entered: host=%u/%d, rem=%u/%d, len=%d", host_ip, host_port, rem_ip, rem_port, len);

	uint32_t src_ip_netw = htonl(host_ip);
	uint32_t src_port_netw = (uint32_t) htons(host_port);
	uint32_t dst_ip_netw = htonl(rem_ip);
	uint32_t dst_port_netw = (uint32_t) htons(rem_port);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		return 0;
	}
	metadata_create(params);

	/** metadata_writeToElement() set the value of an element if it already exist
	 * or it creates the element and set its value in case it is new
	 */

	int ret = 0;
	ret += metadata_writeToElement(params, "src_ip", &src_ip_netw, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "src_port", &src_port_netw, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "dst_ip", &dst_ip_netw, META_TYPE_INT) == 0;
	ret += metadata_writeToElement(params, "dst_port", &dst_port_netw, META_TYPE_INT) == 0;

	uint16_t protocol = TCP_PROTOCOL;
	protocol = htons(protocol);
	ret += metadata_writeToElement(params, "protocol", &protocol, META_TYPE_INT) == 0;

	if (ret) {
		PRINT_ERROR("tcp_fdf_to_jinni: failed matadata write, meta=%d", (int)params);
		metadata_destroy(params);
		return 0;
	}

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("tcp_fdf_to_jinni: ff creation failed, meta=%d", (int)params);
		metadata_destroy(params);
		return 0;
	}

	PRINT_DEBUG("tcp_fdf_to_jinni: src=%u/%d, dst=%u/%d, ff=%d", src_ip_netw, src_port_netw, dst_ip_netw, dst_port_netw, (int)ff);

	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = JINNIID;
	ff->destinationID.next = NULL;
	ff->dataFrame.directionFlag = UP;
	ff->dataFrame.pduLength = len;
	ff->dataFrame.pdu = dataLocal;
	ff->dataFrame.metaData = params;

	/**TODO insert the frame into jinni_to_switch queue
	 * check if insertion succeeded or not then
	 * return 1 on success, or -1 on failure
	 * */
	/*#*/PRINT_DEBUG("");
	if (tcp_to_switch(ff)) {
		return 1;
	} else {
		freeFinsFrame(ff);
		return 0;
	}
}

//TODO: deprecated, remove?------------------------------------------------------------------------------------------------

//--------------------------------------------
// Calculate the checksum of this TCP segment.
// (basically identical to ICMP_checksum().)
//--------------------------------------------
uint16_t ff_checksum_tcp(struct finsFrame *ff) {
	int sum = 0;
	unsigned char *w = ff->dataFrame.pdu;
	int nleft = ff->dataFrame.pduLength;

//if(nleft % 2)  //Check if we've got an uneven number of bytes here, and deal with it accordingly if we do.
//{
//	nleft--;  //By decrementing the number of bytes we have to add in
//	sum += ((int)(ff->dataframe.pdu[nleft])) << 8; //And shifting these over, adding them in as if they're the high byte of a 2-byte pair
//This is as per specification of the checksum from the RFC: "If the total length is odd, the received data is padded with one
// octet of zeros for computing the checksum." We don't explicitly add an octet of zeroes, but this has the same result.
//}

	while (nleft > 0) {
		//Deal with the high and low words of each 16-bit value here. I tried earlier to do this 'normally' by
		//casting the pdu to unsigned short, but the little-vs-big-endian thing messed it all up. I'm just avoiding
		//the whole issue now by treating the values as high-and-low-word pairs, and bit-shifting to compensate.
		sum += (int) (*w++) << 8; //First one is high word: shift before adding in
		sum += *w++; //Second one is low word: just add in
		nleft -= 2; //Decrement by 2, since we're taking 2 at a time
	}

//Fully fill out the checksum
	for (;;) {
		sum = (sum >> 16) + (sum & 0xFFFF); //Get the sum shifted over added into the current sum
		if (!(sum >> 16)) //Continue this until the sum shifted over is zero
			break;
	}
	return ~((uint16_t)(sum)); //Return one's complement of the sum
}
