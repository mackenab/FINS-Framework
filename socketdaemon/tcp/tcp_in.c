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

	PRINT_DEBUG("getting seqEndRTT=%d stampRTT=(%d, %d)\n", conn->rtt_seq_end, conn->rtt_stamp.tv_sec, conn->rtt_stamp.tv_usec);
	PRINT_DEBUG("getting seqEndRTT=%d current=(%d, %d)\n", conn->rtt_seq_end, current.tv_sec, current.tv_usec);

	PRINT_DEBUG("old sampleRTT=%f estRTT=%f devRTT=%f timout=%f\n", sampRTT, conn->rtt_est, conn->rtt_dev, conn->timeout);

	conn->rtt_flag = 0;

	if (conn->rtt_stamp.tv_usec > current.tv_usec) {
		decimal = (1000000.0 + current.tv_usec - conn->rtt_stamp.tv_usec) / 1000000.0;
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
		conn->rtt_dev = (1 - beta) * conn->rtt_dev + beta * fabs(sampRTT - conn->rtt_est);
	}

	conn->timeout = conn->rtt_est + conn->rtt_dev / beta;
	if (conn->timeout < MIN_GBN_TIMEOUT) {
		conn->timeout = MIN_GBN_TIMEOUT;
	} else if (conn->timeout > MAX_GBN_TIMEOUT) {
		conn->timeout = MAX_GBN_TIMEOUT;
	}

	PRINT_DEBUG("new sampleRTT=%f estRTT=%f devRTT=%f timout=%f\n", sampRTT, conn->rtt_est, conn->rtt_dev, conn->timeout);
}

void *syn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct tcp_segment *seg = thread_data->seg;

	uint16_t calc;
	struct tcp_node *node;

	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn_stub->running_flag) {
		calc = tcp_checksum(seg); //TODO add alt checksum
		if (seg->checksum == calc) {
			if (queue_has_space(conn_stub->syn_queue, 1)) {
				node = node_create((uint8_t *) seg, 1, seg->seq_num, seg->seq_num);
				queue_append(conn_stub->syn_queue, node);

				sem_post(&conn_stub->accept_wait_sem);
			} else {
				//queue full
				tcp_free(seg);
			}
		} else {
			PRINT_ERROR("Checksum: recv=%u calc=%u\n", seg->checksum, calc);
			tcp_free(seg);
		}
	} else {
		tcp_free(seg);
	}

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	sem_post(&conn_stub_list_sem);

	sem_post(&conn_stub->sem);

	free(thread_data);
	pthread_exit(NULL);
}

int process_flags(struct tcp_connection *conn, struct tcp_segment *seg) {
	switch (conn->state) {
	case ESTABLISHED:
		//can get ACKs, send/resend data, receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			//if FIN, send ACK, CLOSE_WAIT
			conn->state = CLOSE_WAIT;
			return 1;
		} else {
			return 0;
		}
		break;
	case FIN_WAIT_1:
		//merge with established, can still get ACKs, receive, send ACKs, & resend data
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if ((seg->flags & FLAG_ACK) && conn->host_seq_num == conn->host_seq_end) {
				//if FIN ACK, send ACK, TIME_WAIT
				conn->state = TIME_WAIT;
				startTimer(conn->to_gbn_fd, 2 * DEFAULT_MSL);
				return 1;
			} else {
				//if FIN, send ACK, CLOSING
				conn->state = CLOSING;
				return 1;
			}
		} else if ((seg->flags & FLAG_ACK) && conn->host_seq_num == conn->host_seq_end) {
			//if ACK, send -, FIN_WAIT_2
			conn->state = FIN_WAIT_2;
			return 0;
		}
		break;
	case FIN_WAIT_2:
		//merge with established, can still receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			//if FIN, send ACK, TIME_WAIT
			conn->state = TIME_WAIT;
			startTimer(conn->to_gbn_fd, 2 * DEFAULT_MSL);
			return 1;
		}
		break;
	case CLOSING:
		//self, can still get ACKs & resend
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if ((seg->flags & FLAG_ACK) && conn->host_seq_num == conn->host_seq_end) {
			//if ACK, send -, TIME_WAIT
			conn->state = TIME_WAIT;
			startTimer(conn->to_gbn_fd, 2 * DEFAULT_MSL);
		}
		return 0;
	case TIME_WAIT:
		//TIMEOUT
		//if FIN, send ACK, -
		startTimer(conn->to_gbn_fd, 2 * DEFAULT_MSL);
		return 1;
	case CLOSE_WAIT:
		//can still send & get ACKs
		return 0;
	case LAST_ACK:
		//can still get ACKs & resend data
		if ((seg->flags & FLAG_ACK) && conn->host_seq_num == conn->host_seq_end) {
			//if ACK, send -, CLOSED
			conn->state = CLOSED;
		}
		return 0;
	}
}

void tcp_recv_syn(struct tcp_connection_stub *conn_stub, struct tcp_segment *seg) {
	struct tcp_node *node;

	if (queue_has_space(conn_stub->syn_queue, 1)) {
		node = node_create((uint8_t *) seg, 1, seg->seq_num, seg->seq_num);
		queue_append(conn_stub->syn_queue, node);

		sem_post(&conn_stub->accept_wait_sem);
	} else {
		//queue full
		//drop
	}
}

void tcp_recv_syn_sent(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_node *temp_node;
	struct tcp_segment *temp_seg;

	//TODO ACK, If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset <SEQ=SEG.ACK><CTL=RST>
	//TODO ACK, If SND.UNA =< SEG.ACK =< SND.NXT

	if ((seg->flags & FLAG_SYN) && !(seg->flags & (FLAG_FIN | FLAG_RST))) {
		if (seg->flags & FLAG_ACK) {
			//if SYN ACK, send ACK, ESTABLISHED
			if (seg->ack_num == conn->host_seq_num + 1) {
				conn->state = ESTABLISHED;

				conn->host_seq_num = seg->ack_num;
				conn->host_seq_end = conn->host_seq_num;
				conn->rem_seq_num = seg->seq_num;
				conn->rem_window = seg->win_size;

				//TODO process options, MSS, max_window
				//conn->MSS =
				//conn->rem_max_window =

				//flags
				conn->first_flag = 1;
				conn->duplicate = 0;
				conn->fast_flag = 0;
				conn->gbn_flag = 0;

				//RTT
				stopTimer(conn->to_gbn_fd);
				conn->timeout = DEFAULT_GBN_TIMEOUT;

				//Cong
				conn->cong_state = SLOWSTART;
				conn->cong_window = conn->MSS;
				conn->threshhold = conn->rem_max_window / 2.0;

				//TODO piggy back data? release to established with delayed TO on
				//send ACK
				temp_seg = tcp_create(conn);
				tcp_update(temp_seg, conn, FLAG_ACK);
				tcp_send_seg(temp_seg);
				tcp_free(temp_seg);

				//send ACK to handler, prob connect
				metadata *params = (metadata *) malloc(sizeof(metadata));
				metadata_create(params);
				if (params == NULL) {
					PRINT_DEBUG("metadata creation failed");
					exit(-1);
				}

				uint32_t exec_call = EXEC_TCP_CONNECT;
				uint32_t ret_val = 1;
				metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
				metadata_writeToElement(params, "host_ip", &conn->host_ip, META_TYPE_INT);
				metadata_writeToElement(params, "host_port", &conn->host_port, META_TYPE_INT);
				metadata_writeToElement(params, "rem_ip", &conn->rem_ip, META_TYPE_INT);
				metadata_writeToElement(params, "rem_port", &conn->rem_port, META_TYPE_INT);
				metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

				if (tcp_fcf_to_jinni(params)) {
					//fine
				} else {
					//TODO error
				}
			} else {
				PRINT_DEBUG("Invalid ACK: was not sent.");

				//SYN ACK for dup SYN, send RST, resend SYN

				//TODO finish, search send_queue & only RST if old SYN

				//TODO remove dup SYN packet from send_queue

				//send RST
				temp_seg = tcp_create(conn);
				temp_seg->seq_num = seg->ack_num;
				tcp_update(temp_seg, conn, FLAG_RST);
				tcp_send_seg(temp_seg);
				tcp_free(temp_seg);

				//TODO WAIT then send SYN
			}
		} else {
			//if SYN, send SYN ACK, SYN_RECV (simultaneous)
			conn->state = SYN_RECV;

			conn->rem_seq_num = seg->seq_num; //TODO change 1 to tcp->data_len? & send 1 byte of data?
			conn->rem_window = seg->win_size;

			//TODO process options, decide: MSS, max window size!!

			//TODO remove SYN packet from send_queue

			temp_seg = tcp_create(conn);
			tcp_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);

			temp_node = node_create((uint8_t *) temp_seg, 1, temp_seg->seq_num, temp_seg->seq_num); //host_seq_num == host_seq_end
			queue_append(conn->send_queue, temp_node);

			tcp_send_seg(temp_seg);
			startTimer(conn->to_gbn_fd, conn->timeout); //TODO figure out to's
		}
	} else {
		PRINT_DEBUG("Invalid Seg: SYN_SENT & not SYN.");
	}

	tcp_free(seg);
}

void tcp_recv_syn_recv(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_segment *temp_seg;

	if (seg->flags & FLAG_RST) {
		//TODO handle RSTs back
		//if RST, send -, LISTEN

		//TODO finish? verify/add conn_stub, free conn
	} else if (seg->flags & FLAG_FIN) {
		//drop
	} else if (seg->flags & FLAG_ACK) {
		//if ACK/SYN ACK, send -, ESTABLISHED
		if (seg->ack_num == conn->host_seq_num + 1) {
			conn->state = ESTABLISHED;

			conn->host_seq_num = seg->ack_num;
			conn->host_seq_end = conn->host_seq_num;
			conn->rem_seq_num = seg->seq_num;
			conn->rem_window = seg->win_size;

			//TODO process options

			//flags
			conn->first_flag = 1;
			conn->fast_flag = 0;
			conn->gbn_flag = 0;

			//RTT
			stopTimer(conn->to_gbn_fd);
			conn->timeout = DEFAULT_GBN_TIMEOUT;

			//Cong
			conn->cong_state = SLOWSTART;
			conn->cong_window = conn->MSS;
			conn->threshhold = conn->rem_max_window / 2.0;

			if (!(seg->flags & FLAG_ACK)) {
				handle_data(conn, seg);
			}

			//send ACK to handler, prob accept
			metadata *params = (metadata *) malloc(sizeof(metadata));
			metadata_create(params);
			if (params == NULL) {
				PRINT_DEBUG("metadata creation failed");
				exit(-1);
			}

			uint32_t exec_call = EXEC_TCP_ACCEPT;
			uint32_t ret_val = 1;
			metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
			metadata_writeToElement(params, "host_ip", &conn->host_ip, META_TYPE_INT);
			metadata_writeToElement(params, "host_port", &conn->host_port, META_TYPE_INT);
			metadata_writeToElement(params, "rem_ip", &conn->rem_ip, META_TYPE_INT);
			metadata_writeToElement(params, "rem_port", &conn->rem_port, META_TYPE_INT);
			metadata_writeToElement(params, "ret_val", &ret_val, META_TYPE_INT);

			if (tcp_fcf_to_jinni(params)) {
				//fine
			} else {
				//TODO error
			}
		} else {
			PRINT_DEBUG("Invalid ACK: was not sent.");
			//TODO send RST?
		}
	} else if (seg->flags & FLAG_SYN) {
		//if SYN, send SYN ACK, SYN_RECV
		conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
		conn->host_seq_end = conn->host_seq_num;
		conn->rem_seq_num = seg->seq_num;
		conn->rem_window = seg->win_size;

		//TODO process options, decide: MSS, max window size!!
		//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

		//conn_change_options(conn, tcp->options, SYN);

		//send SYN ACK
		temp_seg = tcp_create(conn);
		tcp_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
		tcp_send_seg(temp_seg);
		tcp_free(temp_seg);
	} else {
		PRINT_DEBUG("Invalid Seg: SYN_RECV & not ACK.");
	}

	tcp_free(seg);
}

void handle_ACK(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_node *node;
	struct tcp_node *temp_node;
	struct tcp_segment *temp_seg;

//check if valid ACK
	if (in_tcp_window(seg->ack_num, seg->ack_num, conn->host_seq_num, conn->host_seq_end)) {
		if (seg->ack_num == conn->host_seq_num) {
			conn->rem_window = seg->win_size;
			conn->duplicate++;

			//TODO process ACK options

			//check for FR
			if (conn->duplicate == 3) {
				conn->duplicate = 0;
				conn->fast_flag = 1;

				//RTT
				conn->rtt_flag = 0;
				startTimer(conn->to_gbn_fd, conn->timeout);

				//Cong
				switch (conn->cong_state) {
				case SLOWSTART:
				case AVOIDANCE:
					conn->cong_state = RECOVERY;
					conn->threshhold = conn->cong_window / 2;
					if (conn->threshhold < conn->MSS) {
						conn->threshhold = conn->MSS;
					}
					conn->cong_window = conn->threshhold + 3 * conn->MSS;
					break;
				case RECOVERY:
					//conn->fast_flag = 0; //TODO send FR every 3 repeated, check if should do only first
					break;
				}
			} else {
				//duplicate ACK, no FR though
			}
		} else if (seg->ack_num == conn->host_seq_end) {
			//remove all segs
			while (!queue_is_empty(conn->send_queue)) {
				temp_node = queue_remove_front(conn->send_queue);
				temp_seg = (struct tcp_segment *) temp_node->data;
				tcp_free(temp_seg);
				free(temp_node);
			}

			conn->host_seq_num = seg->ack_num;
			conn->rem_window = seg->win_size;
			conn->duplicate = 0;

			//TODO process ACK options

			//flags
			conn->fast_flag = 0;
			conn->gbn_flag = 0;

			//RTT
			if (conn->rtt_flag && seg->ack_num == conn->rtt_seq_end) {
				calcRTT(conn);
			}
			stopTimer(conn->to_gbn_fd);

			//Cong
			switch (conn->cong_state) {
			case SLOWSTART:
				conn->cong_window += conn->MSS;
				if (conn->cong_window >= conn->threshhold) {
					conn->cong_state = AVOIDANCE;
				}
				break;
			case AVOIDANCE:
				conn->cong_window += conn->MSS * conn->MSS / conn->cong_window;
				break;
			case RECOVERY:
				conn->cong_state = AVOIDANCE;
				conn->cong_window = conn->threshhold;
				break;
			}
		} else {
			node = queue_find(conn->send_queue, seg->ack_num);
			if (node) {
				//remove ACK segs
				while (!queue_is_empty(conn->send_queue) && conn->send_queue->front != node) {
					temp_node = queue_remove_front(conn->send_queue);
					temp_seg = (struct tcp_segment *) temp_node->data;
					tcp_free(temp_seg);
					free(temp_node);
				}

				//valid ACK
				conn->host_seq_num = seg->ack_num;
				conn->rem_window = seg->win_size;
				conn->duplicate = 0;

				//TODO process ACK options

				//flags
				if (conn->gbn_flag) {
					conn->first_flag = 1;
				}

				//RTT
				if (conn->rtt_flag && seg->ack_num == conn->rtt_seq_end) {
					calcRTT(conn);
				}
				if (!conn->gbn_flag) {
					startTimer(conn->to_gbn_fd, conn->timeout);
				}

				//Cong
				switch (conn->cong_state) {
				case SLOWSTART:
					conn->cong_window += conn->MSS;
					if (conn->cong_window >= conn->threshhold) {
						conn->cong_state = AVOIDANCE;
					}
					break;
				case AVOIDANCE:
					conn->cong_window += conn->MSS * conn->MSS / conn->cong_window;
					break;
				case RECOVERY:
					conn->cong_state = AVOIDANCE;
					conn->cong_window = conn->threshhold;
					break;
				}
			} else {
				PRINT_DEBUG("Invalid ACK: was not sent.");
			}
		}

		if (conn->main_wait_flag) {
			PRINT_DEBUG("posting to main_wait_sem\n");
			sem_post(&conn->main_wait_sem);
		}
	} else {
		PRINT_DEBUG("Invalid ACK: out of sent window.");
	}
}

int handle_data(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_node *temp_node;
	struct tcp_segment *temp_seg;

	uint32_t seq_end;
	int ret;
	int send_ack = 0;

// data handling
	if (seg->seq_num == conn->rem_seq_num) {
		//in order seq num

		ret = process_flags(conn, seg);
		if (ret == -1) {
			//drop
		} else { //TODO check if ACKs send data_len==0
			send_ack |= ret | seg->data_len;
		}

		//TODO process seg options

		if (seg->data_len) {
			//TODO: insert to read_queue/send to daemon
		}

		conn->host_window -= seg->data_len;
		conn->rem_seq_num += seg->data_len;
		conn->rem_seq_end = conn->rem_seq_num + conn->host_max_window;

		tcp_free(seg);

		//remove /transfer
		while (!queue_is_empty(conn->recv_queue)) {
			if (conn->recv_queue->front->seq_num < conn->rem_seq_num) {
				if (conn->rem_seq_num <= conn->rem_seq_end) {
					temp_node = queue_remove_front(conn->recv_queue);
					temp_seg = (struct tcp_segment *) temp_node->data;
					conn->host_window += temp_seg->data_len;
					tcp_free(temp_seg);
					free(temp_node);
				} else {
					if (conn->recv_queue->front->seq_num < conn->rem_seq_end) { //wrap around
						break;
					} else {
						temp_node = queue_remove_front(conn->recv_queue);
						temp_seg = (struct tcp_segment *) temp_node->data;
						conn->host_window += temp_seg->data_len;
						tcp_free(temp_seg);
						free(temp_node);
					}
				}
			} else if (conn->recv_queue->front->seq_num == conn->rem_seq_num) {
				temp_node = queue_remove_front(conn->recv_queue);
				temp_seg = (struct tcp_segment *) temp_node->data;

				ret = process_flags(conn, seg);
				if (ret == -1) {
					//drop
				} else { //TODO check if ACKs send data_len==0
					send_ack |= ret | seg->data_len;
				}

				//TODO process seg options

				PRINT_DEBUG("Connected to seq=%d datalen:%d\n", temp_seg->seq_num, temp_seg->data_len);

				if (seg->data_len) {
					//TODO: insert to read_queue/send to daemon
				}

				conn->rem_seq_num += temp_seg->data_len;
				conn->rem_seq_end = conn->rem_seq_num + conn->host_max_window;

				tcp_free(temp_seg);
				free(temp_node);
			} else {
				if (conn->rem_seq_num <= conn->rem_seq_end) {
					if (conn->recv_queue->front->seq_num < conn->rem_seq_end) {
						break;
					} else {
						temp_node = queue_remove_front(conn->recv_queue);
						temp_seg = (struct tcp_segment *) temp_node->data;
						conn->host_window += temp_seg->data_len;
						tcp_free(temp_seg);
						free(temp_node);
					}
				} else {
					break;
				}
			}
		}

		sem_post(&conn->main_wait_sem); //signal recv main thread
	} else {
		//re-ordered segment
		seq_end = seg->seq_num + seg->data_len;

		if (in_tcp_window(seg->seq_num, seq_end, conn->rem_seq_num, conn->rem_seq_end)) {
			temp_node = node_create((uint8_t *) seg, seg->data_len, seg->seq_num, seq_end);
			ret = queue_insert(conn->recv_queue, temp_node, conn->rem_seq_num, conn->rem_seq_end);
			if (ret) {
				conn->host_window -= seg->data_len;
			} else {
				PRINT_DEBUG("Dropping duplicate rem=(%u, %u) got=(%u, %u)\n", conn->rem_seq_num, conn->rem_seq_end, seg->seq_num, seq_end);
				tcp_free(seg);
				free(temp_node);
			}
		} else {
			PRINT_DEBUG("Dropping out of window rem=(%u, %u) got=(%u, %u)\n", conn->rem_seq_num, conn->rem_seq_end, seg->seq_num, seq_end);
			tcp_free(seg);
		}
	}

//send ack
	if (send_ack) {
		if (conn->delayed_flag) {
			stopTimer(conn->to_delayed_fd);
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;

			temp_seg = tcp_create(conn);
			tcp_update(temp_seg, conn, FLAG_ACK);
			tcp_send_seg(temp_seg);
			tcp_free(temp_seg);
		} else {
			conn->delayed_flag = 1;
			conn->to_delayed_flag = 0;
			startTimer(conn->to_delayed_fd, DELAYED_TIMEOUT);
		}
	}
}

void tcp_recv_established(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO can receive, send ACKs, send/resend data, & get ACKs
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	handle_data(conn, seg);
}

void tcp_recv_fin_wait_1(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO merge with established, can still get ACKs, receive, send ACKs, & resend data
//if FIN, send ACK, CLOSING
//if FIN ACK, send ACK, TIME_WAIT
//if ACK, send -, FIN_WAIT_2
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	handle_data(conn, seg);
}

void tcp_recv_fin_wait_2(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO merge with established, can still receive, send ACKs
//if FIN, send ACK, TIME_WAIT
	handle_data(conn, seg);
}

void tcp_recv_closing(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO self, can still get ACKs & resend
//if ACK, send -, TIME_WAIT
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);

		if (seg->seq_num == conn->rem_seq_num) {
			if (seg->flags & (FLAG_SYN | FLAG_RST)) {
				//drop
			} else if (conn->host_seq_num == conn->host_seq_end) {
				//if ACK, send -, TIME_WAIT
				conn->state = TIME_WAIT;
				startTimer(conn->to_gbn_fd, 2 * DEFAULT_MSL);
			}

			//TODO process seg options //?
		}
	}

	tcp_free(seg);
}

void tcp_recv_close_wait(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO can still send & get ACKs
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	tcp_free(seg);
}

void tcp_recv_last_ack(struct tcp_connection *conn, struct tcp_segment *seg) {
//TODO can still get ACKs & resend data
//if ACK, send -, CLOSED
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);

		if (conn->rem_seq_num == seg->seq_num) {
			if (conn->host_seq_num == conn->host_seq_end) {
				//if ACK, send -, CLOSED
				conn->state = CLOSED;
			}

			//TODO process seg options //?
		}
	}

	tcp_free(seg);
}

void *recv_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;
	struct tcp_segment *seg = thread_data->seg;

	uint16_t calc;

	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		calc = tcp_checksum(seg); //TODO add alt checksum
		if (seg->checksum == calc) {
			switch (conn->state) {
			case CLOSED:
				//TODO if RST, -, -
				//TODO if ACK, <SEQ=SEG.ACK><CTL=RST>
				//TODO else, <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

				tcp_free(seg);
				break;
			case LISTEN:
				//ERROR shouldn't ever arrive here in this thread, kept if merge stbs
				PRINT_DEBUG("Shouldn't arrive here state=%d", conn->state);
				tcp_free(seg);
				break;
			case SYN_SENT:
				tcp_recv_syn_sent(conn, seg);
				break;
			case SYN_RECV:
				tcp_recv_syn_recv(conn, seg);
				break;
			case ESTABLISHED:
				tcp_recv_established(conn, seg);
				break;
			case FIN_WAIT_1:
				tcp_recv_fin_wait_1(conn, seg);
				break;
			case FIN_WAIT_2:
				tcp_recv_fin_wait_2(conn, seg);
				break;
			case CLOSING:
				tcp_recv_closing(conn, seg);
				break;
			case CLOSE_WAIT:
				tcp_recv_close_wait(conn, seg);
				break;
			case LAST_ACK:
				tcp_recv_last_ack(conn, seg);
				break;
			case TIME_WAIT:
				//TODO Does nothing, timesout?? What if get something?
				//TIMEOUT
				tcp_free(seg);
				break;
			}
		} else {
			PRINT_ERROR("Checksum: recv=%u calc=%u\n", seg->checksum, calc);
			tcp_free(seg);
		}
	} else {
		tcp_free(seg);
	}

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	sem_post(&conn_list_sem);

	sem_post(&conn->sem);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_in_fdf(struct finsFrame *ff) {
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	int start;
	struct tcp_connection_stub *conn_stub;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	seg = fdf_to_tcp(ff);
	if (seg) {
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		conn = conn_find(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
		if (conn) {
			start = (conn->threads < MAX_THREADS) ? conn->threads++ : 0;
			sem_post(&conn_list_sem);

			if (start) {
				thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->conn = conn;
				thread_data->seg = seg;

				if (pthread_create(&thread, NULL, recv_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
			} else {
				PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
			}
		} else {
			sem_post(&conn_list_sem);

			if (seg->flags & FLAG_ACK) {
				//TODO send <SEQ=SEG.ACK><CTL=RST>
			} else if ((seg->flags & FLAG_SYN) && !(seg->flags & (FLAG_FIN | FLAG_RST))) {
				//TODO check security, send RST if lower, etc

				//check if listening sockets
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_stub_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_find(seg->dst_ip, seg->dst_port);
				if (conn_stub) {
					start = (conn_stub->threads < MAX_THREADS) ? conn_stub->threads++ : 0;
					sem_post(&conn_stub_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->conn_stub = conn_stub;
						thread_data->seg = seg;

						if (pthread_create(&thread, NULL, syn_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
					}
				} else {
					sem_post(&conn_stub_list_sem);
					PRINT_DEBUG("Found no stub. Dropping...");
					tcp_free(seg);
				}
			} else {
				PRINT_DEBUG("Found no connection. Dropping...");
				tcp_free(seg);
			}
		}
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}

	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}
