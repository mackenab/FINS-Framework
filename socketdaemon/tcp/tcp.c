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

void *to_gbn_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to_gbn_thread thread started");

	while (conn->running_flag) {
		ret = read(conn->to_gbn_fd, &exp, sizeof(uint64_t)); //blocking read
		if (ret != sizeof(uint64_t)) {
			//read error
		}
		conn->to_gbn_flag = 1;
		if (conn->main_wait_flag) {
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	}
}

void *to_delayed_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to_delayed_thread thread started");

	while (conn->running_flag) {
		ret = read(conn->to_delayed_fd, &exp, sizeof(uint64_t)); //blocking read
		if (ret != sizeof(uint64_t)) {
			//read error
		}
		conn->to_delayed_flag = 1;
		if (conn->main_wait_flag) {
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	}
}

void *to_thread(void *local) {
	struct tcp_to_thread_data *to_data = (struct tcp_to_thread_data *) local;
	int ret;
	uint64_t exp;

	PRINT_DEBUG("to: %u thread started", to_data->fd);

	while (*to_data->running) {
		ret = read(*to_data->fd, &exp, sizeof(uint64_t)); //blocking read
		if (ret != sizeof(uint64_t)) {
			//read error
		}
		*to_data->flag = 1;
		if (*to_data->waiting) {
			PRINT_DEBUG("posting to wait_sem");
			sem_post(to_data->sem);
		}
	}

	PRINT_DEBUG("to: %u thread stop", to_data->fd);
}

void *main_thread(void *local) {
	struct tcp_connection *conn = (struct tcp_connection *) local;

	double cong_space;
	uint32_t sent_window;
	struct tcp_node *gbn_node;
	struct tcp_segment *tcp_seg;
	int data_len;
	uint8_t *ptr;
	int temp;
	int avail;
	struct tcp_node *temp_node;
	int index = 0;

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
					tcp_seg
							= (struct tcp_segment *) conn->send_queue->front->data;
					if (conn->rem_window > tcp_seg->data_len) {
						conn->rem_window -= tcp_seg->data_len;
					} else {
						conn->rem_window = 0;
					}
					sem_post(&conn->send_queue->sem);

					conn_update_seg(conn, tcp_seg);
					conn_send_seg(conn, tcp_seg);
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

						//take first tcp_seg
						gbn_node = conn->send_queue->front;
						tcp_seg = (struct tcp_segment *) gbn_node->data;
						if (conn->rem_window > tcp_seg->data_len) {
							conn->rem_window -= tcp_seg->data_len;
						} else {
							conn->rem_window = 0;
						}
						sem_post(&conn->send_queue->sem);

						conn_update_seg(conn, tcp_seg);
						conn_send_seg(conn, tcp_seg);

						startTimer(conn->to_gbn_fd, conn->timeout);
						//PRINT_DEBUG("dropping seqEndRTT=%d\n", myTCP->seqEndRTT);
						//myTCP->seqEndRTT = 0;

					} else {
						sent_window = conn->send_queue->len;
						cong_space = conn->cong_window - sent_window;

						if (conn->rem_window && cong_space > 0) { //TODO check if right
							gbn_node = gbn_node->next;
							if (gbn_node) {
								tcp_seg = (struct tcp_segment *) gbn_node->data;
								if (conn->rem_window > tcp_seg->data_len) {
									conn->rem_window -= tcp_seg->data_len;
								} else {
									conn->rem_window = 0;
								}
								sem_post(&conn->send_queue->sem);

								//improbable but unsafe, if get ACK for seg before sent
								conn_update_seg(conn, tcp_seg);
								conn_send_seg(conn, tcp_seg);
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

				tcp_seg = (struct tcp_segment *) malloc(
						sizeof(struct tcp_segment));
				tcp_seg->src_port = conn->host_port;
				tcp_seg->dst_port = conn->rem_port;
				tcp_seg->seq_num = conn->host_seq_end;
				tcp_seg->ack_num = 0;
				tcp_seg->flags = 0;
				tcp_seg->win_size = conn->host_window; //recv sem?
				tcp_seg->checksum = 0;
				tcp_seg->urg_pointer = 0;

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

				tcp_seg->data_len = data_len;
				tcp_seg->data = (uint8_t *) malloc(data_len);
				ptr = tcp_seg->data;

				temp = data_len;
				while (temp && !queue_is_empty(conn->write_queue)) {
					avail = conn->write_queue->front->len - index;
					if (temp < avail) {
						memcpy(ptr, conn->write_queue->front->data + index,
								temp);
						ptr += temp;
						index += temp;
						temp -= temp;
					} else {
						memcpy(ptr, conn->write_queue->front->data + index,
								avail);
						ptr += avail;
						index = 0;
						temp -= avail;

						temp_node = queue_remove_front(conn->write_queue);
						free(temp_node->data);
						free(temp_node);
					}
				}
				sem_post(&conn->write_queue->sem);

				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->write_queue->sem wait prob");
					exit(-1);
				}
				temp_node = node_create((uint8_t *) tcp_seg, data_len,
						tcp_seg->seq_num, tcp_seg->seq_num + data_len - 1);
				queue_append(conn->send_queue, temp_node);

				conn->host_seq_end += data_len;
				if (conn->rem_window > data_len) {
					conn->rem_window -= data_len;
				} else {
					conn->rem_window = 0;
				}
				sem_post(&conn->send_queue->sem);

				conn_update_seg(conn, tcp_seg);
				conn_send_seg(conn, tcp_seg);

				//TODO: add rtt_sem?
				if (conn->rtt_flag == 0) {
					gettimeofday(&conn->rtt_stamp, 0);
					conn->rtt_flag = 1;
					conn->rtt_seq_end = conn->host_seq_end;
					PRINT_DEBUG("setting seqEndRTT=%d stampRTT=(%d, %d)\n",
							conn->rtt_seq_end, conn->rtt_stamp.tv_sec,
							conn->rtt_stamp.tv_usec);
				}

				//TODO: add flag_sem?
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

				conn_send_ack(conn);
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

	sem_init(&conn->conn_sem, 0, 1);
	conn->conn_state = ESTABLISHED; //TODO: here?

	conn->host_addr = host_addr;
	conn->host_port = host_port;
	conn->rem_addr = rem_addr;
	conn->rem_port = rem_port;

	conn->write_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO: could wait on this
	conn->send_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->recv_queue = queue_create(DEFAULT_MAX_QUEUE);
	conn->read_queue = queue_create(DEFAULT_MAX_QUEUE); //TODO might not need

	conn->main_wait_flag = 0;
	sem_init(&conn->main_wait_sem, 0, 0);

	conn->write_threads = 0;
	sem_init(&conn->write_sem, 0, 1);
	sem_init(&conn->write_wait_sem, 0, 0);

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
	conn->cong_window = conn->MSS;

	conn->rtt_flag = 0;
	conn->rtt_first = 1;

	conn->timeout = DEFAULT_GBN_TIMEOUT;

	//TODO ---agree on these values during setup
	conn->MSS = 1024;

	conn->host_seq_num = 0;
	conn->host_seq_end = 0;
	conn->host_max_window = DEFAULT_MAX_WINDOW;
	conn->host_window = conn->host_max_window;

	conn->rem_seq_num = 0;
	conn->rem_seq_end = 0;
	conn->rem_max_window = DEFAULT_MAX_WINDOW;
	conn->rem_window = conn->rem_max_window;
	//---

	//TODO ----set after setup
	conn->cong_state = SLOWSTART;
	conn->cong_window = conn->MSS;
	conn->threshhold = conn->rem_max_window / 2.0;
	//----

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
	if (pthread_create(&conn->main_thread, NULL, main_thread, (void *) conn)) {
		PRINT_ERROR("ERROR: unable to create main_thread thread.");
		exit(-1);
	}

	return conn;
}

void conn_append(struct tcp_connection *conn) {
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
}

//find a TCP connection with given host addr/port and remote addr/port
//NOTE: this means for incoming IP FF call with (dst_ip, src_ip, dst_p, src_p)
struct tcp_connection *conn_find(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port) {
	struct tcp_connection *temp = NULL;

	temp = conn_list;
	while (temp != NULL) {
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
	//free the memory
}

void conn_send_ack(struct tcp_connection *conn) {
	struct tcp_segment *tcp_seg;
	struct finsFrame *ff;
	int offset;

	//ack code
	tcp_seg = (struct tcp_segment *) malloc(sizeof(struct tcp_segment));
	tcp_seg->src_port = conn->host_port;
	tcp_seg->dst_port = conn->rem_port;
	tcp_seg->seq_num = conn->host_seq_end;
	tcp_seg->flags = 0;
	tcp_seg->flags |= FLAG_ACK;
	tcp_seg->ack_num = conn->rem_seq_num;
	tcp_seg->win_size = conn->host_window; //recv sem?
	tcp_seg->checksum = 0;
	tcp_seg->urg_pointer = 0;

	//add options //TODO implement options system
	tcp_seg->options = NULL;
	tcp_seg->opt_len = 0;

	offset = tcp_seg->opt_len / 32; //TODO improve logic, use ceil?
	tcp_seg->flags |= (MIN_DATA_OFFSET_LEN + offset) << 12;
	tcp_seg->data_len = 0;
	tcp_seg->data = NULL;
	tcp_seg->checksum = tcp_checksum(conn->host_addr, conn->rem_addr, tcp_seg);

	ff = tcp_to_fdf(tcp_seg);
	metadata_writeToElement(ff->dataFrame.metaData, "srcip",
			&(conn->host_addr), META_TYPE_INT);
	metadata_writeToElement(ff->dataFrame.metaData, "dstip", &(conn->rem_addr),
			META_TYPE_INT);

	tcp_to_switch(ff);
	//conn->host_seq_num++; //do i want to increment the host? not in 2-way

	free(tcp_seg);
}

void conn_update_seg(struct tcp_connection *conn, struct tcp_segment *tcp_seg) {
	int offset;

	//TODO update options/flags?
	//add options //TODO implement options system, move to conn_send_seg?
	tcp_seg->options = NULL;
	//TODO PAWS

	tcp_seg->opt_len = 0;

	offset = tcp_seg->opt_len / 32; //TODO improve logic, use ceil?
	tcp_seg->flags |= (MIN_DATA_OFFSET_LEN + offset) << 12;

	if (sem_wait(&conn->recv_queue->sem)) {
		PRINT_ERROR("conn->recv_queue->sem wait prob");
		exit(-1);
	}
	if (conn->delayed_flag) {
		//add ACK
		stopTimer(conn->to_delayed_fd);
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		tcp_seg->flags |= FLAG_ACK;
		tcp_seg->ack_num = conn->rem_seq_num;
	} else {
		tcp_seg->flags &= ~FLAG_ACK;
		tcp_seg->ack_num = 0;
	}
	sem_post(&conn->recv_queue->sem);

	tcp_seg->checksum = tcp_checksum(conn->host_addr, conn->rem_addr, tcp_seg);
}

void conn_send_seg(struct tcp_connection *conn, struct tcp_segment *tcp_seg) {
	struct finsFrame *ff;

	ff = tcp_to_fdf(tcp_seg);
	metadata_writeToElement(ff->dataFrame.metaData, "srcip",
			&(conn->host_addr), META_TYPE_INT);
	metadata_writeToElement(ff->dataFrame.metaData, "dstip", &(conn->rem_addr),
			META_TYPE_INT);

	tcp_to_switch(ff); //send segment
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
	struct finsFrame *ffreturn = NULL;

	ffreturn = (struct finsFrame*) malloc(sizeof(struct finsFrame));
	//ffreturn->dataOrCtrl; //leave unset?
	//ffreturn->destinationID;	// destination module ID
	//ffreturn->directionFlag;// ingress or egress network data; see above

	ffreturn->dataFrame.metaData = (metadata *) malloc(sizeof(metadata));
	metadata_writeToElement(ffreturn->dataFrame.metaData, "srcport",
			&(tcp->src_port), META_TYPE_INT); //Write the source port in
	metadata_writeToElement(ffreturn->dataFrame.metaData, "dstport",
			&(tcp->dst_port), META_TYPE_INT); //And the destination port

	ffreturn->dataFrame.pduLength = tcp->data_len + HEADERSIZE(tcp->flags); //Add in the header size for this, too
	ffreturn->dataFrame.pdu = (unsigned char*) malloc(
			ffreturn->dataFrame.pduLength);

	uint8_t *ptr = ffreturn->dataFrame.pdu; //Start pointing at the beginning of the pdu data
	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	//Source port

	/*//might be the better way
	 *(uint16_t *) ptr = htons(tcp->dst_port);
	 ptr += 2;
	 *(uint32_t *) ptr = htonl(tcp->seq_num);
	 ptr += 4;
	 */

	ptr = copy_uint16(ptr, tcp->src_port);
	ptr = copy_uint16(ptr, tcp->dst_port);
	ptr = copy_uint32(ptr, tcp->seq_num);
	ptr = copy_uint32(ptr, tcp->ack_num);
	ptr = copy_uint16(ptr, tcp->flags);
	ptr = copy_uint16(ptr, tcp->win_size);
	ptr = copy_uint16(ptr, tcp->checksum);
	ptr = copy_uint16(ptr, tcp->urg_pointer);

	if (tcp->opt_len > 0) {
		memcpy(ptr, tcp->options, tcp->opt_len);
		ptr += tcp->opt_len;
	}

	if (tcp->data_len > 0) {
		memcpy(ptr, tcp->data, tcp->data_len);
		ptr += tcp->data_len;
	}

	return ffreturn;
}

//------------------------------------------------------------------------------
// Fill out a tcp segment from a finsFrame. Gets the data it needs from the PDU.
//------------------------------------------------------------------------------
struct tcp_segment *fdf_to_tcp(struct finsFrame *ff) {
	struct tcp_segment *tcpreturn = NULL;
	tcpreturn = (struct tcp_segment*) malloc(sizeof(struct tcp_segment));
	if (!tcpreturn) {
		PRINT_ERROR("tcpreturn malloc error");
		return NULL;
	}

	if (ff->dataFrame.pduLength < MIN_TCP_HEADER_LEN) {
		return NULL;
	}

	uint8_t *ptr = ff->dataFrame.pdu; //Start pointing at the beginning of the pdu data
	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	//Source port
	tcpreturn->src_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->src_port += *ptr++;
	//Destination port
	tcpreturn->dst_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->dst_port += *ptr++;
	//Sequence number
	tcpreturn->seq_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->seq_num += *ptr++;
	//Acknowledgment number
	tcpreturn->ack_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->ack_num += *ptr++;
	//Flags and data offset
	tcpreturn->flags = (uint16_t)(*ptr++) << 8;
	tcpreturn->flags += *ptr++;
	//Window size
	tcpreturn->win_size = (uint16_t)(*ptr++) << 8;
	tcpreturn->win_size += *ptr++;
	//Checksum
	tcpreturn->checksum = (uint16_t)(*ptr++) << 8;
	tcpreturn->checksum += *ptr++;
	//Urgent pointer
	tcpreturn->urg_pointer = (uint16_t)(*ptr++) << 8;
	tcpreturn->urg_pointer += *ptr++;

	//Now copy the rest of the data, starting with the options
	tcpreturn->opt_len = HEADERSIZE(tcpreturn->flags) - MIN_TCP_HEADER_LEN;
	if (tcpreturn->opt_len > 0) {
		tcpreturn->options = (uint8_t*) malloc(tcpreturn->opt_len);
		int i;
		for (i = 0; i < tcpreturn->opt_len; i++) {
			tcpreturn->options[i] = *ptr++;
		}
	}

	//And fill in the data length and the data, also
	tcpreturn->data_len = ff->dataFrame.pduLength
			- HEADERSIZE(tcpreturn->flags);
	if (tcpreturn->data_len > 0) {
		tcpreturn->data = (uint8_t*) malloc(tcpreturn->data_len);
		int i;
		for (i = 0; i < tcpreturn->data_len; i++) {
			tcpreturn->data[i] = *ptr++;
		}
	}

	return tcpreturn; //Done
}

int tcp_in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num,
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
		PRINT_DEBUG("send to CONTROL HANDLER !");
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == UP)) {
		tcp_in(ff);
		PRINT_DEBUG();
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == DOWN)) {
		tcp_out(ff);
		PRINT_DEBUG();
	}

}

void tcp_to_switch(struct finsFrame *ff) {

	sem_wait(&TCP_to_Switch_Qsem);
	write_queue(ff, TCP_to_Switch_Queue);
	sem_post(&TCP_to_Switch_Qsem);

}

//Get a random number to use as a starting sequence number
int tcp_rand() {
	return rand(); //Just use the standard C random number generator for now
}

//Seed the above random number generator
void tcp_srand() {
	srand(time(NULL)); //Just use the standard C random number generator for now
}

//--------------------------------------------
// Calculate the checksum of this TCP segment.
// (basically identical to ICMP_checksum().)
//--------------------------------------------
uint16_t TCP_checksum(struct finsFrame *ff) { //TODO: redo/check
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

uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
		struct tcp_segment *tcp_seg) { //TODO check if checksum works
	uint32_t sum = 0;
	uint16_t *ptr;
	uint32_t i;

	//fake IP header
	sum += ((uint16_t)(src_addr >> 16)) + ((uint16_t)(src_addr & 0xFFFF));
	sum += ((uint16_t)(dst_addr >> 16)) + ((uint16_t)(dst_addr & 0xFFFF));
	sum += (uint16_t) TCP_PROTOCOL;
	sum += (uint16_t)(IP_HEADERSIZE + HEADERSIZE(tcp_seg->flags)
			+ tcp_seg->data_len);

	//fake TCP header
	sum += tcp_seg->src_port;
	sum += tcp_seg->dst_port;
	sum += ((uint16_t)(tcp_seg->seq_num >> 16)) + ((uint16_t)(tcp_seg->seq_num
			& 0xFFFF));
	sum += ((uint16_t)(tcp_seg->ack_num >> 16)) + ((uint16_t)(tcp_seg->ack_num
			& 0xFFFF));
	sum += tcp_seg->flags;
	sum += tcp_seg->win_size;
	//sum += tcp_seg->checksum; //dummy checksum=0
	sum += tcp_seg->urg_pointer;

	//options, opt_len always has to be a factor of 2
	ptr = (uint16_t *) tcp_seg->options;
	for (i = 0; i < tcp_seg->opt_len; i += 2) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t)(*ptr));
		ptr += 2;
	}

	//data
	ptr = (uint16_t *) tcp_seg->data;
	for (i = 0; i < tcp_seg->data_len - 1; i += 2) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t)(*ptr));
		ptr += 2;
	}
	if (tcp_seg->data_len & 0x1 == 1) {
		sum += ((uint16_t)(*ptr << 8)) + ((uint16_t) 0);
	}

	sum = ~sum;

	return ((uint16_t) sum);
}
