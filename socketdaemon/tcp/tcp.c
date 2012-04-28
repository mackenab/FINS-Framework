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
int conn_stub_num;

struct tcp_connection *conn_list; //The list of current connections we have
int conn_num;

struct tcp_node *node_create(uint8_t *data, uint32_t len, uint32_t seq_num,
		uint32_t seq_end) {
	struct tcp_node *node = NULL;

	node = (struct tcp_node *) malloc(sizeof(struct tcp_node));
	node->data = data;
	node->len = len;
	node->seq_num = seq_num;
	node->seq_end = seq_end;

	node->next = NULL;

	return node;
}

// assumes nodes are in window, -1=less than, 0=problem/equal, 1=greater
int node_compare(struct tcp_node *node, struct tcp_node *cmp,
		uint32_t win_seq_num, uint32_t win_seq_end) {
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
	if (node->data) {
		free(node->data);
	}
	free(node);
}

struct tcp_queue *queue_create(uint32_t max) {
	struct tcp_queue *queue = NULL;
	queue = (struct tcp_queue *) malloc(sizeof(struct tcp_queue));

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

void queue_add(struct tcp_queue *queue, struct tcp_node *node,
		struct tcp_node *prev) {
	node->next = prev->next;
	prev->next = node;
	queue->len += node->len;
}

//assumes the node being inserted is in the window
int queue_insert(struct tcp_queue *queue, struct tcp_node *node,
		uint32_t win_seq_num, uint32_t win_seq_end) {

	struct tcp_node *temp_node;
	int ret;

	//empty
	if (queue_is_empty(queue)) {
		queue_prepend(queue, node);
		return 0;
	}

	//before front
	ret = node_compare(node, queue->front, win_seq_num, win_seq_end);
	if (ret == -1) { // [ <> () ] |
		queue_prepend(queue, node);
		return 0;
	} else if (ret == 0) {
		return -1;
	}

	//after end
	ret = node_compare(node, queue->end, win_seq_num, win_seq_end);
	if (ret == 1) { // [ {} <> ] |
		queue_append(queue, node);
		return 0;
	} else if (ret == 0) {
		return -1;
	}

	//iterate through queue
	temp_node = queue->front;
	while (temp_node->next) {
		ret = node_compare(node, temp_node->next, win_seq_num, win_seq_end);
		if (ret == -1) {
			queue_add(queue, node, temp_node);
			return 0;
		}
		if (ret == 0) {
			return -1;
		}

		temp_node = temp_node->next;
	}

	//unable to insert, but didn't trip any overlaps - big error/not possible?
	return -1;
}

struct tcp_node *queue_find(struct tcp_queue *queue, uint32_t seq_num) {
	struct tcp_node *comp = NULL;

	comp = queue->front;
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
	struct tcp_node *old;

	old = queue->front;
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
	struct tcp_node *node;
	struct tcp_node *next;

	node = queue->front;
	while (node) {
		next = node->next;
		node_free(node);
		node = next;
	}

	free(queue);
}

struct tcp_connection_stub *conn_stub_create(uint32_t host_addr,
		uint16_t host_port, uint32_t backlog) {

	struct tcp_connection_stub *conn_stub = NULL;
	conn_stub = (struct tcp_connection_stub *) malloc(
			sizeof(struct tcp_connection_stub));

	conn_stub->next = NULL;
	sem_init(&conn_stub->sem, 0, 1);
	//state?

	conn_stub->host_addr = host_addr;
	conn_stub->host_port = host_port;

	conn_stub->syn_queue = queue_create(backlog);

	conn_stub->syn_threads = 0;

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
	return 0;
}

struct tcp_connection_stub *conn_stub_find(uint32_t host_addr,
		uint16_t host_port) {
	struct tcp_connection_stub *temp = NULL;

	temp = conn_stub_list;
	while (temp != NULL) { //TODO change to return NULL once conn_list is ordered LL
		if (temp->host_addr == host_addr && temp->host_port == host_port) {
			return temp;
		}
		temp = temp->next;
	}

	return NULL;
}

void conn_stub_remove(struct tcp_connection_stub *conn_stub) {
	struct tcp_connection_stub *temp = NULL;

	temp = conn_stub_list;
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
	return conn_stub_num + len <= MAX_CONNECTIONS;
}

void conn_stub_free(struct tcp_connection_stub *conn_stub) {
	if (conn_stub->syn_queue)
		queue_free(conn_stub->syn_queue);
	free(conn_stub);
}

void *to_thread(void *local) {
	struct tcp_to_thread_data *to_data = (struct tcp_to_thread_data *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to: %u thread started", (unsigned int) to_data->fd);
	while (*to_data->running) {
		ret = read(*to_data->fd, &exp, sizeof(uint64_t)); //blocking read
		if (!(*to_data->running)) {
			break;
		}
		if (ret != sizeof(uint64_t)) {
			//read error
			continue;
		}
		*to_data->flag = 1;
		if (*to_data->waiting) {
			PRINT_DEBUG("posting to wait_sem");
			sem_post(to_data->sem);
		}
	}
	PRINT_DEBUG("to: %u thread stop", (unsigned int) to_data->fd);

	pthread_exit(NULL);
}

void *setup_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;

	struct tcp_node *node;
	struct tcp_segment *seg;

	while (conn->running_flag) {
		PRINT_DEBUG("before state=%d", conn->state);

		if (sem_wait(&conn->send_queue->sem)) {
			PRINT_ERROR("conn->send_queue->sem wait prob");
			exit(-1);
		}

		PRINT_DEBUG("switch state=%d", conn->state);
		switch (conn->state) {
		case CLOSED:
			conn->setup_wait_flag = 1;
			break;
		case SYN_SENT:
			if (conn->to_gbn_flag) {
				PRINT_DEBUG("SYN Timeout");

				conn->to_gbn_flag = 0;

				sem_init(&conn->setup_wait_sem, 0, 0);

				seg = (struct tcp_segment *) conn->send_queue->front->data;

				tcp_send_seg(seg);
				startTimer(conn->to_gbn_fd, conn->timeout); //TODO double timeout?

				//TODO add counter & terminate if too long
			}
			conn->setup_wait_flag = 1;
			break;
		case LISTEN:
			conn->setup_wait_flag = 1;
			break;
		case SYN_RECV:
			//send SYN ACK
			break;
		default:
			//error/unimplemented
			break;
		}
		sem_post(&conn->send_queue->sem);

		if (conn->running_flag && conn->setup_wait_flag && !conn->to_gbn_flag) {
			//wait
			if (sem_wait(&conn->setup_wait_sem)) {
				PRINT_ERROR("conn->setup_wait_sem wait prob");
				exit(-1);
			}
			conn->setup_wait_flag = 0;
			sem_init(&conn->setup_wait_sem, 0, 0);
		}
	}

	pthread_exit(NULL);
}

void *main_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;

	struct tcp_node *gbn_node;
	struct tcp_segment *seg;
	double cong_space;
	uint32_t sent_window;
	int data_len;
	struct tcp_node *temp_node;

	while (conn->running_flag) {
		PRINT_DEBUG(
				"flags: to_gbn=%d fast=%d gbn=%d delayed=%d to_delay=%d first=%d wait=%d ",
				conn->to_gbn_flag, conn->fast_flag, conn->gbn_flag,
				conn->delayed_flag, conn->to_delayed_flag, conn->first_flag,
				conn->main_wait_flag);

		if (conn->to_gbn_flag) {
			//gbn timeout
			if (!queue_is_empty(conn->send_queue)) {
				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->send_queue->sem wait prob");
					exit(-1);
				}
				if (!queue_is_empty(conn->send_queue)) {
					//set flags
					conn->to_gbn_flag = 0;
					conn->fast_flag = 0;
					conn->gbn_flag = 1;
					conn->first_flag = 1;

					//rtt
					conn->rtt_flag = 0;

					//congestion control stuff
					switch (conn->cong_state) {
					case INITIAL:
						//TODO something
						break;
					case SLOWSTART:
						conn->threshhold = conn->cong_window / 2;
						if (conn->threshhold < conn->MSS) {
							conn->threshhold = conn->MSS;
						}
						conn->cong_state = AVOIDANCE;
						conn->cong_window = conn->threshhold;
						break;
					case AVOIDANCE:
					case RECOVERY:
						conn->threshhold = conn->rem_max_window;
						conn->cong_state = SLOWSTART;
						conn->cong_window = conn->MSS;
						break;
					default:
						PRINT_ERROR("unknown congState=%d\n", conn->cong_state);
						break;
					}

					conn->main_wait_flag = 0; //handle cases where TO after set waitFlag
					sem_init(&conn->main_wait_sem, 0, 0);
				} else {
					conn->to_gbn_flag = 0;
					conn->fast_flag = 0;
					conn->gbn_flag = 0;
					conn->first_flag = 0;
				}
				sem_post(&conn->send_queue->sem);
			}
		}

		if (conn->fast_flag) {
			//fast retransmit
			if (!queue_is_empty(conn->send_queue)) {
				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->send_queue->sem wait prob");
					exit(-1);
				}
				//flags
				conn->fast_flag = 0;

				if (!queue_is_empty(conn->send_queue)) {
					seg
							= (struct tcp_segment *) conn->send_queue->front->data;
					if (conn->rem_window > seg->data_len) {
						conn->rem_window -= seg->data_len;
					} else {
						conn->rem_window = 0;
					}
					sem_post(&conn->send_queue->sem);

					tcp_update(seg, conn, 0);
					tcp_send_seg(seg);
				} else {
					sem_post(&conn->send_queue->sem);
				}
			} else {
				conn->fast_flag = 0;
			}
		} else if (conn->gbn_flag) {
			//GBN
			if (!queue_is_empty(conn->send_queue)) {
				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->send_queue->sem wait prob");
					exit(-1);
				}
				if (!queue_is_empty(conn->send_queue)) {
					if (conn->first_flag) {
						conn->first_flag = 0;

						//take first seg
						gbn_node = conn->send_queue->front;
						seg = (struct tcp_segment *) gbn_node->data;
						if (conn->rem_window > seg->data_len) {
							conn->rem_window -= seg->data_len;
						} else {
							conn->rem_window = 0;
						}
						sem_post(&conn->send_queue->sem);

						tcp_update(seg, conn, 0);
						tcp_send_seg(seg);

						startTimer(conn->to_gbn_fd, conn->timeout);
						//PRINT_DEBUG("dropping seqEndRTT=%d\n", myTCP->seqEndRTT);
						//myTCP->seqEndRTT = 0;

					} else {
						sent_window = conn->send_queue->len;
						cong_space = conn->cong_window - sent_window;

						if (conn->rem_window && cong_space > 0) { //TODO check if right
							gbn_node = gbn_node->next;
							if (gbn_node) {
								seg = (struct tcp_segment *) gbn_node->data;
								if (conn->rem_window > seg->data_len) {
									conn->rem_window -= seg->data_len;
								} else {
									conn->rem_window = 0;
								}
								sem_post(&conn->send_queue->sem);

								//improbable but unsafe, if get ACK for seg before sent
								tcp_update(seg, conn, 0);
								tcp_send_seg(seg);
							} else {
								conn->gbn_flag = 0;
								conn->first_flag = 0;

								sem_post(&conn->send_queue->sem);
							}
						} else {
							conn->main_wait_flag = 1;
							sem_post(&conn->send_queue->sem);

							PRINT_DEBUG("GBN: flagging waitFlag");
						}
					}
				} else {
					conn->gbn_flag = 0;
					conn->first_flag = 0;

					sem_post(&conn->send_queue->sem);
				}
				//sem_post(&conn->send_queue->sem);
			} else {
				conn->gbn_flag = 0;
				conn->first_flag = 0;
			}
		} else {
			//normal
			PRINT_DEBUG("Normal");

			sent_window = conn->send_queue->len;
			cong_space = conn->cong_window - sent_window;

			if (!queue_is_empty(conn->write_queue) && conn->rem_window
					&& sent_window < conn->rem_max_window && cong_space
					>= conn->MSS) {
				PRINT_DEBUG("sending packet");

				seg = tcp_create(conn);

				if (sem_wait(&conn->write_queue->sem)) {
					PRINT_ERROR("conn->write_queue->sem wait prob");
					exit(-1);
				}
				if (conn->write_queue->len > conn->MSS) {
					data_len = conn->MSS;
				} else {
					data_len = conn->write_queue->len;
				}
				if (data_len > conn->rem_window) { //leave for now, move to outside if for Nagle
					data_len = conn->rem_window;
				}
				if (data_len > cong_space) { //TODO unneeded if (cong_space >= MSS) kept, keep if change to (cong_space > 0)
					data_len = (int) cong_space;
				}

				tcp_add_data(seg, conn, data_len);
				sem_post(&conn->write_queue->sem);

				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->write_queue->sem wait prob");
					exit(-1);
				}
				temp_node = node_create((uint8_t *) seg, data_len,
						seg->seq_num, seg->seq_num + data_len - 1);
				queue_append(conn->send_queue, temp_node);

				conn->host_seq_end += data_len;
				if (conn->rem_window > data_len) {
					conn->rem_window -= data_len;
				} else {
					conn->rem_window = 0;
				}
				sem_post(&conn->send_queue->sem);

				tcp_update(seg, conn, 0);
				tcp_send_seg(seg);

				if (conn->rtt_flag == 0) {
					gettimeofday(&conn->rtt_stamp, 0);
					conn->rtt_flag = 1;
					conn->rtt_seq_end = conn->host_seq_end;
					PRINT_DEBUG("setting seqEndRTT=%d stampRTT=(%d, %d)\n",
							conn->rtt_seq_end, conn->rtt_stamp.tv_sec,
							conn->rtt_stamp.tv_usec);
				}

				if (conn->first_flag) {
					conn->first_flag = 0;
					startTimer(conn->to_gbn_fd, conn->timeout);
				}

				//TODO move conn->send_queue->sem post to here?

				sem_post(&conn->write_wait_sem); //unstop write_thread if waiting
			} else {
				PRINT_DEBUG("Normal: flagging waitFlag");
				conn->main_wait_flag = 1;
			}
		}

		if (conn->to_delayed_flag) {
			//delayed ACK timeout, send ACK
			if (sem_wait(&conn->recv_queue->sem)) {
				PRINT_ERROR("conn->recv_queue->sem wait prob");
				exit(-1);
			}
			if (conn->to_delayed_flag) {
				conn->delayed_flag = 0;
				conn->to_delayed_flag = 0;

				//send ack
				seg = tcp_create(conn);
				tcp_update(seg, conn, FLAG_ACK);
				tcp_send_seg(seg);

				tcp_free(seg);
			}
			sem_post(&conn->recv_queue->sem);
		}

		if (conn->running_flag && conn->main_wait_flag && !conn->to_gbn_flag
				&& !conn->to_delayed_flag && !conn->fast_flag) {
			//wait
			if (sem_wait(&conn->main_wait_sem)) {
				PRINT_ERROR("conn->main_wait_sem wait prob");
				exit(-1);
			}
			conn->main_wait_flag = 0;
			sem_init(&conn->main_wait_sem, 0, 0);
		}
	}

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

struct tcp_connection *conn_create(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port) {

	struct tcp_connection *conn = NULL;
	conn = (struct tcp_connection *) malloc(sizeof(struct tcp_connection));

	conn->next = NULL;
	sem_init(&conn->sem, 0, 1);
	conn->state = CLOSED;

	conn->host_addr = host_addr;
	conn->host_port = host_port;
	conn->rem_addr = rem_addr;
	conn->rem_port = rem_port;

	conn->write_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO: could wait on this
	conn->send_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->recv_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->read_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO might not need

	conn->setup_wait_flag = 0;
	sem_init(&conn->setup_wait_sem, 0, 0);

	conn->main_wait_flag = 0;
	sem_init(&conn->main_wait_sem, 0, 0);

	conn->write_threads = 0;
	sem_init(&conn->write_sem, 0, 1);
	sem_init(&conn->write_wait_sem, 0, 0);
	conn->index = 0;

	conn->recv_threads = 0;

	conn->running_flag = 1;
	conn->first_flag = 1;

	conn->duplicate = 0;
	conn->fast_flag = 0;

	conn->to_gbn_flag = 0;
	conn->gbn_flag = 0;

	conn->delayed_flag = 0;
	conn->to_delayed_flag = 0;

	conn->cong_state = INITIAL;
	//conn->cong_window = conn->MSS;

	conn->rtt_flag = 0;
	conn->rtt_first = 1;

	conn->timeout = DEFAULT_GBN_TIMEOUT;

	//conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
	//conn->host_seq_end = conn->host_seq_num;
	conn->host_max_window = DEFAULT_MAX_WINDOW;
	conn->host_window = conn->host_max_window;

	//TODO ---agree on these values during setup
	conn->MSS = DEFAULT_MSS;

	//conn->rem_seq_num = 0;
	//conn->rem_seq_end = conn->rem_seq_num;
	conn->rem_max_window = DEFAULT_MAX_WINDOW;
	conn->rem_window = conn->rem_max_window;
	//---

	//setup timers
	conn->to_gbn_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_gbn_fd == -1) {
		PRINT_ERROR("ERROR: unable to create to_fd.");
		exit(-1);
	}
	struct tcp_to_thread_data gbn_data;
	gbn_data.running = &conn->running_flag;
	gbn_data.fd = &conn->to_gbn_fd;
	gbn_data.flag = &conn->to_gbn_flag;
	gbn_data.waiting = &conn->main_wait_flag;
	gbn_data.sem = &conn->main_wait_sem;
	if (pthread_create(&conn->to_gbn_thread, NULL, to_thread,
			(void *) &gbn_data)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

	conn->to_delayed_fd = timerfd_create(CLOCK_REALTIME, 0);
	if (conn->to_delayed_fd == -1) {
		PRINT_ERROR("ERROR: unable to create delayed_fd.");
		exit(-1);
	}
	struct tcp_to_thread_data delayed_data;
	delayed_data.running = &conn->running_flag;
	delayed_data.fd = &conn->to_delayed_fd;
	delayed_data.flag = &conn->to_delayed_flag;
	delayed_data.waiting = &conn->main_wait_flag;
	delayed_data.sem = &conn->main_wait_sem;
	if (pthread_create(&conn->to_delayed_thread, NULL, to_thread,
			(void *) &delayed_data)) {
		PRINT_ERROR("ERROR: unable to create recv_thread thread.");
		exit(-1);
	}

	//TODO add keepalive timer
	//TODO add silly window timer
	//TODO add nagel timer

	//start main thread
	if (pthread_create(&conn->setup_thread, NULL, setup_thread, (void *) conn)) {
		PRINT_ERROR("ERROR: unable to create setup_thread thread.");
		exit(-1);
	}
	/*
	 if (pthread_create(&conn->main_thread, NULL, main_thread, (void *) conn)) {
	 PRINT_ERROR("ERROR: unable to create main_thread thread.");
	 exit(-1);
	 }
	 */
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
	return 0;
}

//find a TCP connection with given host addr/port and remote addr/port
//NOTE: this means for incoming IP FF call with (dst_ip, src_ip, dst_p, src_p)
struct tcp_connection *conn_find(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port) {
	struct tcp_connection *temp = NULL;

	temp = conn_list;
	while (temp != NULL) { //TODO change to return NULL once conn_list is ordered LL
		if (temp->rem_port == rem_port && temp->rem_addr == rem_addr
				&& temp->host_addr == host_addr && temp->host_port == host_port) {
			return temp;
		}
		temp = temp->next;
	}

	return NULL;
}

void conn_remove(struct tcp_connection *conn) {
	struct tcp_connection *temp = NULL;

	temp = conn_list;
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
	return conn_num + len <= MAX_CONNECTIONS;
}

void conn_free(struct tcp_connection *conn) {
	conn->running_flag = 0;

	//stop threads
	startTimer(conn->to_gbn_fd, 1);
	startTimer(conn->to_delayed_fd, 1);
	//TODO stop keepalive timer
	//TODO stop silly window timer
	//TODO stop nagel timer
	sem_post(&conn->setup_wait_sem);
	sem_post(&conn->main_wait_sem);

	pthread_join(conn->to_gbn_thread, NULL);
	pthread_join(conn->to_delayed_thread, NULL);
	pthread_join(conn->setup_thread, NULL);
	pthread_join(conn->main_thread, NULL);

	if (conn->write_queue)
		queue_free(conn->write_queue);
	if (conn->send_queue)
		queue_free(conn->send_queue);
	if (conn->recv_queue)
		queue_free(conn->recv_queue);
	if (conn->read_queue)
		queue_free(conn->read_queue);

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

struct tcp_segment *tcp_create(struct tcp_connection *conn) {
	struct tcp_segment *seg;

	seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	seg->src_ip = conn->host_addr;
	seg->dst_ip = conn->rem_addr;
	seg->src_port = conn->host_port;
	seg->dst_port = conn->rem_port;
	seg->seq_num = conn->host_seq_end;
	seg->ack_num = conn->rem_seq_num + 1;
	seg->flags = 0;
	seg->win_size = conn->host_window; //recv sem?
	seg->checksum = 0;
	seg->urg_pointer = 0;
	seg->opt_len = 0;
	seg->options = NULL;
	seg->data_len = 0;
	seg->data = NULL;

	return seg;
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

struct finsFrame *tcp_to_fdf(struct tcp_segment *tcp) {
	struct finsFrame *ff = NULL;
	metadata *meta;
	uint8_t *ptr;

	ff = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	ff->dataOrCtrl = DATA; //leave unset?
	ff->destinationID.id = IPV4ID; // destination module ID
	ff->destinationID.next = NULL;

	ff->dataFrame.directionFlag = DOWN; // ingress or egress network data; see above
	ff->dataFrame.metaData = (metadata *) malloc(sizeof(metadata));

	meta = ff->dataFrame.metaData;
	metadata_writeToElement(meta, "srcip", &tcp->src_ip, META_TYPE_INT); //Write the source ip in
	metadata_writeToElement(meta, "dstip", &tcp->dst_ip, META_TYPE_INT); //And the destination ip
	metadata_writeToElement(meta, "srcport", &tcp->src_port, META_TYPE_INT); //Write the source port in
	metadata_writeToElement(meta, "dstport", &tcp->dst_port, META_TYPE_INT); //And the destination port

	ff->dataFrame.pduLength = tcp->data_len + HEADERSIZE(tcp->flags); //Add in the header size for this, too
	ff->dataFrame.pdu = (unsigned char *) malloc(ff->dataFrame.pduLength);
	ptr = ff->dataFrame.pdu;

	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	ptr = copy_uint16(ptr, tcp->src_port);
	ptr = copy_uint16(ptr, tcp->dst_port);
	ptr = copy_uint32(ptr, tcp->seq_num);
	ptr = copy_uint32(ptr, tcp->ack_num);
	ptr = copy_uint16(ptr, tcp->flags);
	ptr = copy_uint16(ptr, tcp->win_size);
	ptr = copy_uint16(ptr, tcp->checksum);
	ptr = copy_uint16(ptr, tcp->urg_pointer);

	/*//might be the better way
	 *(uint16_t *) ptr = htons(tcp->dst_port);
	 ptr += 2;
	 *(uint32_t *) ptr = htonl(tcp->seq_num);
	 ptr += 4;
	 */

	if (tcp->opt_len > 0) {
		memcpy(ptr, tcp->options, tcp->opt_len);
		ptr += tcp->opt_len;
	}

	if (tcp->data_len > 0) {
		memcpy(ptr, tcp->data, tcp->data_len);
		ptr += tcp->data_len;
	}

	return ff;
}

struct tcp_segment *fdf_to_tcp(struct finsFrame *ff) {
	struct tcp_segment *seg;
	uint8_t *ptr;

	seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	if (!seg) {
		PRINT_ERROR("tcpreturn malloc error");
		return NULL;
	}

	if (ff->dataFrame.pduLength < MIN_TCP_HEADER_LEN) {
		return NULL;
	}

	metadata *meta = ff->dataFrame.metaData;
	metadata_readFromElement(meta, "srcip", &seg->src_ip); //host
	metadata_readFromElement(meta, "dstip", &seg->dst_ip); //remote

	ptr = ff->dataFrame.pdu;

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

	//Now copy the rest of the data, starting with the options
	seg->opt_len = HEADERSIZE(seg->flags) - MIN_TCP_HEADER_LEN;
	if (seg->opt_len > 0) {
		seg->options = (uint8_t *) malloc(seg->opt_len);
		memcpy(seg->options, ptr, seg->opt_len);
		ptr += seg->opt_len;
	}

	//And fill in the data length and the data, also
	seg->data_len = ff->dataFrame.pduLength - HEADERSIZE(seg->flags);
	if (seg->data_len > 0) {
		seg->data = (uint8_t *) malloc(seg->data_len);
		memcpy(seg->data, ptr, seg->data_len);
		ptr += seg->data_len;
	}

	return seg;
}

void tcp_add_data(struct tcp_segment *seg, struct tcp_connection *conn,
		int data_len) {
	uint8_t *ptr;
	int output;
	int avail;
	struct tcp_node *temp_node;

	seg->data_len = data_len;
	seg->data = (uint8_t *) malloc(data_len);
	ptr = seg->data;

	output = data_len;
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

uint16_t tcp_checksum(struct tcp_segment *seg) { //TODO check if checksum works
	uint32_t sum = 0;
	uint16_t * ptr;
	uint32_t i;


	//TODO add TCP alternate checksum w/data in options (15)


	//fake IP header
	sum += ((uint16_t)(seg->src_ip >> 16)) + ((uint16_t)(seg->src_ip
			& 0xFFFF));
	sum += ((uint16_t)(seg->dst_ip >> 16)) + ((uint16_t)(seg->dst_ip
			& 0xFFFF));
	sum += (uint16_t) TCP_PROTOCOL;
	sum += (uint16_t)(IP_HEADERSIZE + HEADERSIZE(seg->flags)
			+ seg->data_len);

	//fake TCP header
	sum += seg->src_port;
	sum += seg->dst_port;
	sum += ((uint16_t)(seg->seq_num >> 16)) + ((uint16_t)(seg->seq_num
			& 0xFFFF));
	sum += ((uint16_t)(seg->ack_num >> 16)) + ((uint16_t)(seg->ack_num
			& 0xFFFF));
	sum += seg->flags;
	sum += seg->win_size;
	//sum += seg->checksum; //dummy checksum=0
	sum += seg->urg_pointer;

	//options, opt_len always has to be a factor of 2
	ptr = (uint16_t *) seg->options;
	for (i = 0; i < seg->opt_len; i += 2) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t)(*ptr));
		ptr += 2;
	}

	//data
	ptr = (uint16_t *) seg->data;
	for (i = 0; i < seg->data_len - 1; i += 2) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t)(*ptr));
		ptr += 2;
	}
	if (seg->data_len & 0x1 == 1) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t) 0);
	}

	sum = ~sum;

	return ((uint16_t) sum);
}

void tcp_update(struct tcp_segment *seg, struct tcp_connection *conn,
		uint32_t flags) {
	int offset;

	//clear flags
	memset(&seg->flags, 0, sizeof(uint16_t));

	//TODO update options/flags?
	seg->flags |= flags;

	//add options //TODO implement options system, move to conn_send_seg?
	seg->options = NULL;
	seg->opt_len = 0;

	//TODO PAWS

	offset = seg->opt_len / 32; //TODO improve logic, use ceil?
	seg->flags |= (MIN_DATA_OFFSET_LEN + offset) << 12;

	if (sem_wait(&conn->recv_queue->sem)) {
		PRINT_ERROR("conn->recv_queue->sem wait prob");
		exit(-1);
	}
	if (conn->delayed_flag) {
		//add ACK
		stopTimer(conn->to_delayed_fd);
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		seg->flags |= FLAG_ACK;
		seg->ack_num = conn->rem_seq_num;
	} else {
		seg->ack_num = 0;
	}
	sem_post(&conn->recv_queue->sem);

	seg->checksum = tcp_checksum(seg);
}

void tcp_send_seg(struct tcp_segment *seg) {
	struct finsFrame *ff;

	ff = tcp_to_fdf(seg);
	tcp_to_switch(ff);
}

void tcp_free(struct tcp_segment *seg) {
	if (seg->data_len)
		free(seg->data);

	if (seg->opt_len)
		free(seg->options); //TODO change when have options object

	free(seg);
}

int in_tcp_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num,
		uint32_t win_seq_end) {
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
		PRINT_DEBUG();
		//	free(pff);
	}
}

void tcp_get_FF() {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_TCP_Qsem);
		ff = read_queue(Switch_to_TCP_Queue);
		sem_post(&Switch_to_TCP_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL) {
		// send to something to deal with FCF
		//PRINT_DEBUG("send to CONTROL HANDLER !");
		if ((ff->dataFrame).directionFlag == UP) {
			tcp_in_fcf(ff);
			PRINT_DEBUG();
		} else { //directionFlag==DOWN
			tcp_out_fcf(ff);
			PRINT_DEBUG();
		}
	} else if (ff->dataOrCtrl == DATA) {
		if ((ff->dataFrame).directionFlag == UP) {
			tcp_in_fdf(ff);
			PRINT_DEBUG();
		} else { //directionFlag==DOWN
			tcp_out_fdf(ff);
			PRINT_DEBUG();
		}
	}
}

void tcp_to_switch(struct finsFrame *ff) {

	sem_wait(&TCP_to_Switch_Qsem);
	write_queue(ff, TCP_to_Switch_Queue);
	sem_post(&TCP_to_Switch_Qsem);
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

void conn_send_ack_old(struct tcp_connection *conn) {
	struct tcp_segment *seg;
	struct finsFrame *ff;
	int offset;

	//ack code
	seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	seg->src_ip = conn->host_addr;
	seg->dst_ip = conn->rem_addr;
	seg->src_port = conn->host_port;
	seg->dst_port = conn->rem_port;
	seg->seq_num = conn->host_seq_end;
	seg->flags = 0;
	seg->flags |= FLAG_ACK;
	seg->ack_num = conn->rem_seq_num;
	seg->win_size = conn->host_window; //recv sem?
	seg->checksum = 0;
	seg->urg_pointer = 0;

	//add options
	seg->options = NULL;
	seg->opt_len = 0;

	//TODO implement options system
	//TODO change to conn_update_seg ?

	offset = seg->opt_len / 32; //TODO improve logic, use ceil?
	seg->flags |= (MIN_DATA_OFFSET_LEN + offset) << 12;
	seg->data_len = 0;
	seg->data = NULL;
	seg->checksum = tcp_checksum(seg);

	ff = tcp_to_fdf(seg);
	tcp_to_switch(ff);
	//conn->host_seq_num++; //do i want to increment the host? not in 2-way

	free(seg);
}
