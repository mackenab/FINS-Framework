/*
 * @file tcp_in.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "tcp.h"

void calcRTT(struct tcp_connection *conn) {
	struct timeval current;
	double decimal, sampRTT;
	double alpha = 0.125, beta = 0.25;

	gettimeofday(&current, 0);

	PRINT_DEBUG("getting seqEndRTT=%d stampRTT=(%d, %d)\n", conn->rtt_seq_end,
			conn->rtt_stamp.tv_sec, conn->rtt_stamp.tv_usec);
	PRINT_DEBUG("getting seqEndRTT=%d current=(%d, %d)\n", conn->rtt_seq_end,
			current.tv_sec, current.tv_usec);

	PRINT_DEBUG("old sampleRTT=%f estRTT=%f devRTT=%f timout=%f\n", sampRTT,
			conn->rtt_est, conn->rtt_dev, conn->timeout);

	conn->rtt_flag = 0;

	if (conn->rtt_stamp.tv_usec > current.tv_usec) {
		decimal = (1000000.0 + current.tv_usec - conn->rtt_stamp.tv_usec)
				/ 1000000.0;
		sampRTT = current.tv_sec - conn->rtt_stamp.tv_sec - 1.0;
		sampRTT += decimal;
	} else {
		decimal = (current.tv_usec - conn->rtt_stamp.tv_usec) / 1000000.0;
		sampRTT = current.tv_sec - conn->rtt_stamp.tv_sec;
		sampRTT += decimal;
	}
	sampRTT *= 1000.0;

	if (conn->rtt_first) {
		conn->rtt_first = 0;
		conn->rtt_est = sampRTT;
		conn->rtt_dev = sampRTT / 2;
	} else {
		conn->rtt_est = (1 - alpha) * conn->rtt_est + alpha * sampRTT;
		conn->rtt_dev = (1 - beta) * conn->rtt_dev + beta * fabs(sampRTT
				- conn->rtt_est);
	}

	conn->timeout = conn->rtt_est + conn->rtt_dev / beta;
	if (conn->timeout < MIN_GBN_TIMEOUT) {
		conn->timeout = MIN_GBN_TIMEOUT;
	} else if (conn->timeout > MAX_GBN_TIMEOUT) {
		conn->timeout = MAX_GBN_TIMEOUT;
	}

	PRINT_DEBUG("new sampleRTT=%f estRTT=%f devRTT=%f timout=%f\n", sampRTT,
			conn->rtt_est, conn->rtt_dev, conn->timeout);
}

void *syn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct tcp_segment *tcp_seg = thread_data->tcp_seg;
	uint32_t rem_addr = thread_data->addr;

	uint16_t calc;
	struct tcp_node *node;
	int ret;

	calc = tcp_checksum(rem_addr, conn_stub->host_addr, tcp_seg);
	if (tcp_seg->checksum != calc) {
		PRINT_ERROR("Checksum: recv=%u calc=%u\n", tcp_seg->checksum, calc);
	} else {
		if (queue_has_space(conn_stub->recv_queue, 1)) {
			if (sem_wait(&conn_stub->recv_queue->sem)) {
				PRINT_ERROR("conn->send_queue wait prob");
				exit(-1);
			}
			if (queue_has_space(conn_stub->recv_queue, 1)) {
				node = node_create((uint8_t *) tcp_seg, 1, tcp_seg->seq_num,
						tcp_seg->seq_num);
				queue_append(conn_stub->recv_queue, node);
			}
			sem_post(&conn_stub->recv_queue->sem);
		}
	}
}

void *recv_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;
	struct tcp_segment *tcp_seg = thread_data->tcp_seg;

	uint16_t calc;
	struct tcp_node *node;
	struct tcp_node *temp_node;
	struct tcp_segment *temp_seg;
	struct finsFrame *ff;

	uint32_t seq_end;
	//uint32_t rem_seq_end;
	int ret;

	calc = tcp_checksum(conn->rem_addr, conn->host_addr, tcp_seg);
	if (tcp_seg->checksum != calc) {
		PRINT_ERROR("Checksum: recv=%u calc=%u\n", tcp_seg->checksum, calc);
	} else {
		if (tcp_seg->flags & FLAG_ACK) {
			//check if valid ACK
			if (tcp_in_window(tcp_seg->ack_num, tcp_seg->ack_num,
					conn->host_seq_num, conn->host_seq_end)) {
				if (sem_wait(&conn->send_queue->sem)) {
					PRINT_ERROR("conn->send_queue wait prob");
					exit(-1);
				}
				if (tcp_in_window(tcp_seg->ack_num, tcp_seg->ack_num,
						conn->host_seq_num, conn->host_seq_end)) {
					if (tcp_seg->ack_num == conn->host_seq_num) {
						//check for FR
						conn->rem_window = tcp_seg->win_size;
						conn->duplicate++;

						//TODO process ACK flags/options

						if (conn->duplicate == 3) {
							conn->duplicate = 0;
							//sem_post(&conn->send_queue->sem); //?

							conn->fast_flag = 1;

							//RTT
							conn->rtt_flag = 0;
							startTimer(conn->to_gbn_fd, conn->timeout);

							//Cong
							switch (conn->cong_state) {
							case INITIAL:
								//connection setup
								break;
							case SLOWSTART:
							case AVOIDANCE:
								conn->cong_state = RECOVERY;
								conn->threshhold = conn->cong_window / 2;
								if (conn->threshhold < conn->MSS) {
									conn->threshhold = conn->MSS;
								}
								conn->cong_window = conn->threshhold + 3
										* conn->MSS;
								break;
							case RECOVERY:
								//conn->fast_flag = 0;
								break;
							default:
								PRINT_ERROR("unknown cong_state=%d\n",
										conn->cong_state);
								break;
							}
						} else {
							//sem_post(&conn->send_queue->sem); //?
						}
					} else if (tcp_seg->ack_num == conn->host_seq_end) {
						//TODO process ACK flags/options

						//remove all
						while (!queue_is_empty(conn->send_queue)) {
							temp_node = queue_remove_front(conn->send_queue);
							temp_seg = (struct tcp_segment *) temp_node->data;
							free(temp_seg->data);
							node_free(temp_node);
						}

						conn->host_seq_num = tcp_seg->ack_num;
						conn->rem_window = tcp_seg->win_size;
						conn->duplicate = 0;
						//sem_post(&conn->send_queue->sem); //?

						//flags
						conn->fast_flag = 0;
						conn->gbn_flag = 0;

						//RTT
						if (conn->rtt_flag && tcp_seg->ack_num
								== conn->rtt_seq_end) {
							calcRTT(conn);
						}
						stopTimer(conn->to_gbn_fd);

						//Cong
						switch (conn->cong_state) {
						case INITIAL:
							//connection setup
							break;
						case SLOWSTART:
							conn->cong_window += conn->MSS;
							if (conn->cong_window >= conn->threshhold) {
								conn->cong_state = AVOIDANCE;
							}
							break;
						case AVOIDANCE:
							conn->cong_window += conn->MSS * conn->MSS
									/ conn->cong_window;
							break;
						case RECOVERY:
							conn->cong_state = AVOIDANCE;
							conn->cong_window = conn->threshhold;
							break;
						default:
							PRINT_ERROR("unknown congState=%d\n",
									conn->cong_state);
							break;
						}
					} else {
						node = queue_find(conn->send_queue, tcp_seg->ack_num);
						if (node) {
							//TODO process ACK flags/options

							while (!queue_is_empty(conn->send_queue)
									&& conn->send_queue->front != node) {
								temp_node
										= queue_remove_front(conn->send_queue);
								temp_seg
										= (struct tcp_segment *) temp_node->data;
								free(temp_seg->data);
								node_free(temp_node);
							}

							//valid ACK
							conn->host_seq_num = tcp_seg->ack_num;
							conn->rem_window = tcp_seg->win_size;
							conn->duplicate = 0;
							//sem_post(&conn->send_queue->sem); //?

							//flags
							if (conn->gbn_flag) {
								conn->first_flag = 1;
							}

							//RTT
							if (conn->rtt_flag && tcp_seg->ack_num
									== conn->rtt_seq_end) {
								calcRTT(conn);
							}
							if (!conn->gbn_flag) {
								startTimer(conn->to_gbn_fd, conn->timeout);
							}

							//Cong
							switch (conn->cong_state) {
							case INITIAL:
								//connection setup
								break;
							case SLOWSTART:
								conn->cong_window += conn->MSS;
								if (conn->cong_window >= conn->threshhold) {
									conn->cong_state = AVOIDANCE;
								}
								break;
							case AVOIDANCE:
								conn->cong_window += conn->MSS * conn->MSS
										/ conn->cong_window;
								break;
							case RECOVERY:
								conn->cong_state = AVOIDANCE;
								conn->cong_window = conn->threshhold;
								break;
							default:
								PRINT_ERROR("unknown congState=%d\n",
										conn->cong_state);
								break;
							}
						} else {
							PRINT_DEBUG("Invalid ACK: was not sent.");
							//drop entire tcp_seg?
						}
					}
					sem_post(&conn->send_queue->sem); //TODO move?

					if (conn->main_wait_flag) {
						PRINT_DEBUG("posting to main_wait_sem\n");
						sem_post(&conn->main_wait_sem);
					}
				} else {
					PRINT_DEBUG("Invalid ACK: out of sent window.");
					sem_post(&conn->send_queue->sem); //TODO move?
				}
			} else {
				PRINT_DEBUG("Invalid ACK: out of sent window.");
			}
		}

		// data handling
		if (tcp_seg->data_len) { //TODO seg's with no data not processed
			if (sem_wait(&conn->recv_queue->sem)) {
				PRINT_ERROR("conn->recv_queue->sem wait prob");
				exit(-1);
			}
			if (conn->rem_seq_num == tcp_seg->seq_num) {
				//in order seq num
				//TODO: process flags/options

				//TODO: insert to read_queue/send to daemon

				conn->host_window -= tcp_seg->data_len;
				conn->rem_seq_num += tcp_seg->data_len;
				conn->rem_seq_end = conn->rem_seq_num + conn->host_max_window;

				free(tcp_seg->data);
				free(tcp_seg);

				//remove /transfer
				while (!queue_is_empty(conn->recv_queue)) {
					if (conn->recv_queue->front->seq_num < conn->rem_seq_num) {
						if (conn->rem_seq_num <= conn->rem_seq_end) {
							temp_node = queue_remove_front(conn->recv_queue);
							tcp_seg = (struct tcp_segment *) temp_node->data;
							conn->host_window += tcp_seg->data_len;
							free(tcp_seg->data);
							node_free(temp_node);
						} else {
							if (conn->recv_queue->front->seq_num
									< conn->rem_seq_end) { //wrap around
								break;
							} else {
								temp_node
										= queue_remove_front(conn->recv_queue);
								tcp_seg
										= (struct tcp_segment *) temp_node->data;
								conn->host_window += tcp_seg->data_len;
								free(tcp_seg->data);
								node_free(temp_node);
							}
						}
					} else if (conn->recv_queue->front->seq_num
							== conn->rem_seq_num) {
						tcp_seg
								= (struct tcp_segment *) conn->recv_queue->front->data;

						//TODO: Process Flags/options

						PRINT_DEBUG("Connected to seq=%d datalen:%d\n",
								tcp_seg->seq_num, tcp_seg->data_len);

						//TODO: insert to read_queue/send to daemon

						conn->rem_seq_num += tcp_seg->data_len;
						conn->rem_seq_end = conn->rem_seq_num
								+ conn->host_max_window;

						temp_node = queue_remove_front(conn->recv_queue);
						tcp_seg = (struct tcp_segment *) temp_node->data;
						free(tcp_seg->data);
						node_free(temp_node);
					} else {
						if (conn->rem_seq_num <= conn->rem_seq_end) {
							if (conn->recv_queue->front->seq_num
									< conn->rem_seq_end) {
								break;
							} else {
								temp_node
										= queue_remove_front(conn->recv_queue);
								tcp_seg
										= (struct tcp_segment *) temp_node->data;
								conn->host_window += tcp_seg->data_len;
								free(tcp_seg->data);
								node_free(temp_node);
							}
						} else {
							break;
						}
					}
				}

				sem_post(&conn->main_wait_sem); //signal recv main thread
			} else {
				//re-ordered segment
				seq_end = tcp_seg->seq_num + tcp_seg->data_len;

				if (tcp_in_window(tcp_seg->seq_num, seq_end, conn->rem_seq_num,
						conn->rem_seq_end)) { // 0=in window, -1=out of window
					node = node_create((uint8_t *) tcp_seg, tcp_seg->data_len,
							tcp_seg->seq_num, seq_end);
					ret = queue_insert(conn->recv_queue, node,
							conn->rem_seq_num, conn->rem_seq_end);
					if (ret) {
						PRINT_DEBUG(
								"Dropping duplicate rem=(%u, %u) got=(%u, %u)\n",
								conn->rem_seq_num, conn->rem_seq_end,
								tcp_seg->seq_num, seq_end);
						free(tcp_seg->data);
						node_free(node);
					} else {
						conn->host_window -= tcp_seg->data_len;
					}
				} else {
					PRINT_DEBUG(
							"Dropping out of window rem=(%u, %u) got=(%u, %u)\n",
							conn->rem_seq_num, conn->rem_seq_end,
							tcp_seg->seq_num, seq_end);
					free(tcp_seg->data);
					free(tcp_seg);
				}
			}

			//send ack
			if (conn->delayed_flag) {
				stopTimer(conn->to_delayed_fd);
				conn->delayed_flag = 0;
				conn->to_delayed_flag = 0;

				conn_send_ack(conn);
			} else {
				conn->delayed_flag = 1;
				conn->to_delayed_flag = 0;
				startTimer(conn->to_delayed_fd, DELAYED_TIMEOUT);
			}

			sem_post(&conn->recv_queue->sem);
		}
	}

	pthread_exit(NULL);
}

void tcp_in_fdf(struct finsFrame *ff) {
	uint32_t src_ip;
	uint32_t dst_ip;
	struct tcp_segment *tcp_seg;
	struct tcp_connection_stub *conn_stub;
	struct tcp_connection *conn;
	pthread_t thread;
	struct tcp_thread_data *data;
	int ret;

	//this handles if it's a FDF atm

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &src_ip); //host
	metadata_readFromElement(meta, "dstip", &dst_ip); //remote

	tcp_seg = fdf_to_tcp(ff);
	if (tcp_seg) {
		if (tcp_seg->flags & FLAG_SYN) {
			//and if not ACK
			if (!(tcp_seg->flags & FLAG_ACK)) {
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_stub_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_find(dst_ip, tcp_seg->dst_port); //TODO check if right, is reversed
				sem_post(&conn_stub_list_sem);

				if (conn_stub) {
					if (conn_stub->running_flag) {
						if (sem_wait(&conn_stub->sem)) {
							PRINT_ERROR("conn_stub->sem wait prob");
							exit(-1);
						}
						if (conn_stub->recv_threads < MAX_RECV_THREADS) {
							data = (struct tcp_thread_data *) malloc(
									sizeof(struct tcp_thread_data));
							data->conn_stub = conn_stub;
							data->tcp_seg = tcp_seg;
							data->addr = src_ip;
							if (pthread_create(&thread, NULL, syn_thread,
									(void *) data)) {
								PRINT_ERROR(
										"ERROR: unable to create recv_thread thread.");
								exit(-1);
							}
							conn_stub->recv_threads++;
						} else {
							PRINT_DEBUG(
									"Too many recv threads=%d. Dropping...",
									conn_stub->recv_threads);
						}
						sem_post(&conn_stub->sem);
					}
				} else {
					PRINT_DEBUG("Found no stub. Dropping...");
				}
			} else {
				//TODO do similar thin
			}
		} else {

			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_find(dst_ip, tcp_seg->dst_port, src_ip,
					tcp_seg->src_port); //TODO check if right, is reversed
			sem_post(&conn_list_sem);

			if (conn) {
				if (conn->running_flag) {
					if (sem_wait(&conn->sem)) {
						PRINT_ERROR("conn->conn_sem wait prob");
						exit(-1);
					}
					if (conn->recv_threads < MAX_RECV_THREADS) {
						data = (struct tcp_thread_data *) malloc(
								sizeof(struct tcp_thread_data));
						data->conn = conn;
						data->tcp_seg = tcp_seg;

						if (pthread_create(&thread, NULL, recv_thread,
								(void *) data)) {
							PRINT_ERROR(
									"ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
						conn->recv_threads++;
					} else {
						PRINT_DEBUG("Too many recv threads=%d. Dropping...",
								conn->recv_threads);
					}
					sem_post(&conn->sem);
				}
			} else {
				PRINT_DEBUG("Found no connection. Dropping...");
			}
		}
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}

	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

void tcp_in_fcf(struct finsFrame *ff) {
	//TODO
	freeFinsFrame(ff);
}
