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
	double decimal = 0, sampRTT = 0;
	double alpha = 0.125, beta = 0.25;

	gettimeofday(&current, 0);

	PRINT_DEBUG("getting seqEndRTT=%d stampRTT=(%d, %d)\n", conn->rtt_seq_end, (int)conn->rtt_stamp.tv_sec, (int)conn->rtt_stamp.tv_usec);
	PRINT_DEBUG("getting seqEndRTT=%d current=(%d, %d)\n", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

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
	if (conn->timeout < TCP_GBN_TO_MIN) {
		conn->timeout = TCP_GBN_TO_MIN;
	} else if (conn->timeout > TCP_GBN_TO_MAX) {
		conn->timeout = TCP_GBN_TO_MAX;
	}

	PRINT_DEBUG("new sampleRTT=%f estRTT=%f devRTT=%f timout=%f\n", sampRTT, conn->rtt_est, conn->rtt_dev, conn->timeout);
}

void handle_ACK(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_node *node;
	struct tcp_node *temp_node;
	struct tcp_segment *temp_seg;

	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	PRINT_DEBUG("ACK=%u send=(%u, %u) sent=%u sep=%u ack=%u",
			seg->ack_num-conn->issn, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->fin_sent, conn->fin_sep, conn->fin_ack);

	//check if valid ACK
	if (in_window(seg->ack_num, seg->ack_num, conn->send_seq_num, conn->send_seq_end)) {
		if (seg->ack_num == conn->send_seq_num) {

			if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			}

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//TODO process ACK options

			conn->duplicate++;
			//check for FR
			if (conn->duplicate == 3) {
				conn->duplicate = 0;

				//RTT
				conn->rtt_flag = 0;
				startTimer(conn->to_gbn_fd, conn->timeout);

				//Cong
				switch (conn->cong_state) {
				case RENO_SLOWSTART:
				case RENO_AVOIDANCE:
					if (conn->send_seq_num == conn->issn) {
						//TODO do nothing don't FR
					} else { //TODO should be only if there's no data & it doesn't update the adv window
						conn->cong_state = RENO_RECOVERY;
						conn->fast_flag = 1;

						conn->threshhold = conn->cong_window / 2.0;
						if (conn->threshhold < (double) conn->MSS) {
							conn->threshhold = (double) conn->MSS;
						}
						conn->cong_window = conn->threshhold + 3.0 * conn->MSS;
					}
					break;
				case RENO_RECOVERY:
					conn->fast_flag = 1; //TODO send FR every 3 repeated, check if should do only first then ff=0
					//conn->cong_window += (double) conn->MSS; //in RFC but FR is sent right afterward in same code
					break;
				}
			} else {
				//duplicate ACK, no FR though
			}
		} else if (seg->ack_num == conn->send_seq_end) {
			//remove all segs
			while (!queue_is_empty(conn->send_queue)) {
				temp_node = queue_remove_front(conn->send_queue);
				temp_seg = (struct tcp_segment *) temp_node->data;
				seg_free(temp_seg);
				free(temp_node);
			}

			conn->send_seq_num = seg->ack_num;

			if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			}
			conn->duplicate = 0;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

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
			case RENO_SLOWSTART:
				conn->cong_window += (double) conn->MSS;
				if (conn->cong_window >= conn->threshhold) {
					conn->cong_state = RENO_AVOIDANCE;
				}
				break;
			case RENO_AVOIDANCE:
				conn->cong_window += ((double) conn->MSS) * ((double) conn->MSS) / conn->cong_window;
				break;
			case RENO_RECOVERY:
				conn->cong_state = RENO_AVOIDANCE;
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
					seg_free(temp_seg);
					free(temp_node);
				}

				//TODO process ACK options

				//valid ACK
				conn->send_seq_num = seg->ack_num;
				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->duplicate = 0;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
				//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

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
				case RENO_SLOWSTART:
					conn->cong_window += conn->MSS;
					if (conn->cong_window >= conn->threshhold) {
						conn->cong_state = RENO_AVOIDANCE;
					}
					break;
				case RENO_AVOIDANCE:
					conn->cong_window += ((double) conn->MSS) * ((double) conn->MSS) / conn->cong_window;
					break;
				case RENO_RECOVERY:
					conn->cong_state = RENO_AVOIDANCE;
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

	} else if (conn->fin_sent && conn->fin_sep && seg->ack_num == conn->fin_ack) {
		//remove all segs
		while (!queue_is_empty(conn->send_queue)) {
			temp_node = queue_remove_front(conn->send_queue);
			temp_seg = (struct tcp_segment *) temp_node->data;
			seg_free(temp_seg);
			free(temp_node);
		}

		conn->send_seq_num = seg->ack_num;
		conn->send_seq_end = conn->send_seq_num;

		if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
			if (conn->wsopt_enabled) {
				conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
			} else {
				conn->send_win = (uint32_t) seg->win_size;
			}
			conn->send_win_seq = seg->seq_num;
			conn->send_win_ack = seg->ack_num;
		}

		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
		//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
	} else {
		PRINT_DEBUG("Invalid ACK: out of sent window.");
	}
}

int process_flags(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *send_flags) {
	switch (conn->state) {
	case TCP_ESTABLISHED:
		//can get ACKs, send/resend data, receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			//if FIN, send ACK, CLOSE_WAIT
			PRINT_DEBUG("ESTABLISHED: FIN, send ACK, CLOSE_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_CLOSE_WAIT;

			*send_flags |= FLAG_ACK;
			return 1;
		} else if (seg->data_len) {
			conn->recv_seq_num += seg->data_len;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
	case TCP_FIN_WAIT_1:
		//merge with established, can still get ACKs, receive, send ACKs, & resend data
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
				if (conn->fin_sent) {
					//if FIN ACK, send ACK, TIME_WAIT
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send ACK, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TCP_TIME_WAIT;
					startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/); //TODO uncomment
				} else {
					//if FIN ACK, send FIN ACK, CLOSING (w FIN_SENT)
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send FIN ACK, CLOSING/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TCP_CLOSING;
					*send_flags |= FLAG_FIN;
				}
			} else {
				//if FIN/FIN ACK, send ACK, CLOSING
				PRINT_DEBUG("FIN_WAIT_1: FIN, send ACK, CLOSING: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSING;
			}

			*send_flags |= FLAG_ACK;
			return 1;
		} else if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			//if ACK, send -, FIN_WAIT_2
			if (conn->fin_sent) {
				PRINT_DEBUG("FIN_WAIT_1: ACK, send -, FIN_WAIT_2: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_FIN_WAIT_2;

				if (seg->data_len) {
					conn->recv_seq_num += seg->data_len;
					conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
					*send_flags |= FLAG_ACK;
					return 1;
				} else {
					return 0;
				}
			} else {
				PRINT_DEBUG("FIN_WAIT_1: ACK, send FIN, FIN_WAIT_1/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				if (seg->data_len) {
					conn->recv_seq_num += seg->data_len;
					conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
				}

				*send_flags |= FLAG_FIN | FLAG_ACK;
				return 1;
			}
		} else if (seg->data_len) {
			conn->recv_seq_num += seg->data_len;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
	case TCP_FIN_WAIT_2:
		//merge with established, can still receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			//if FIN, send ACK, TIME_WAIT
			PRINT_DEBUG("FIN_WAIT_2: FIN, send ACK, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_TIME_WAIT;
			startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);

			*send_flags |= FLAG_ACK;
			return 1;
		} else if (seg->data_len) {
			conn->recv_seq_num += seg->data_len;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
	case TCP_CLOSING:
		//self, can still get ACKs & resend
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			if (conn->fin_sent) {
				//if ACK, send -, TIME_WAIT
				PRINT_DEBUG("CLOSING: ACK, send -, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_TIME_WAIT;
				startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
				return 0;
			} else {
				PRINT_DEBUG("CLOSING: ACK, send FIN, CLOSING/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				*send_flags |= FLAG_FIN | FLAG_ACK;
				return 1;
			}
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			*send_flags |= FLAG_ACK;
			return 1;
		} else if (seg->data_len) { //TODO check!
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_TIME_WAIT:
		//TIMEOUT
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
		//startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
		//*send_flags |= FLAG_ACK;
		return 1;
	case TCP_CLOSE_WAIT:
		//can still send & get ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			*send_flags |= FLAG_ACK;
			return 1;
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
	case TCP_LAST_ACK:
		//can still get ACKs & resend data
		if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			if (conn->fin_sent) {
				//if ACK, send -, CLOSED
				PRINT_DEBUG("LAST_ACK: ACK, send -, CLOSED: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSED;
				if (seg->data_len) {
					*send_flags |= FLAG_ACK;
					return 1;
				} else {
					return 0;
				}
			} else {
				//if ACK, send FIN, LAST_ACK
				PRINT_DEBUG("LAST_ACK: ACK, send FIN, LAST_ACK/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				*send_flags |= FLAG_ACK | FLAG_FIN;
				return 1;
			}
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 0;
		}
	default:
		return 0;
	}
}

int process_flags_old(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *send_flags) {
	switch (conn->state) {
	case TCP_ESTABLISHED:
		//can get ACKs, send/resend data, receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if (seg->flags & FLAG_FIN) {
			//if FIN, send ACK, CLOSE_WAIT
			PRINT_DEBUG("ESTABLISHED: FIN, send ACK, CLOSE_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_CLOSE_WAIT;
			if (seg->data_len) {
				*send_flags |= FLAG_ACK;
			} else {
				*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
			}
			return 1;
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_FIN_WAIT_1:
		//merge with established, can still get ACKs, receive, send ACKs, & resend data
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if (seg->flags & FLAG_FIN) {
			if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
				if (conn->fin_sent) {
					//if FIN ACK, send ACK, TIME_WAIT
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send ACK, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TCP_TIME_WAIT;
					startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/); //TODO uncomment
					if (seg->data_len) {
						*send_flags |= FLAG_ACK;
					} else {
						*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
					}
					return 1;
				} else {
					//if FIN ACK, send FIN ACK, CLOSING (w FIN_SENT)
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send FIN ACK, CLOSING/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TCP_CLOSING;
					if (seg->data_len) {
						*send_flags |= FLAG_ACK | FLAG_FIN;
					} else {
						*send_flags |= FLAG_ACK | FLAG_FIN | FLAG_ACK_PLUS;
					}
					return 1;
				}
			} else {
				//if FIN, send ACK, CLOSING
				PRINT_DEBUG("FIN_WAIT_1: FIN, send ACK, CLOSING: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSING;
				if (seg->data_len) {
					*send_flags |= FLAG_ACK;
				} else {
					*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
				}
				return 1;
			}
		} else if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			//if ACK, send -, FIN_WAIT_2
			if (conn->fin_sent) {
				PRINT_DEBUG("FIN_WAIT_1: ACK, send -, FIN_WAIT_2: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_FIN_WAIT_2;
				if (seg->data_len) {
					*send_flags |= FLAG_ACK;
				}
				return 1;
			} else {
				PRINT_DEBUG("FIN_WAIT_1: ACK, send FIN, FIN_WAIT_1/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				if (seg->data_len) {
					*send_flags |= FLAG_ACK | FLAG_FIN;
				} else {
					*send_flags |= FLAG_FIN;
				}
				return 1;
			}
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_FIN_WAIT_2:
		//merge with established, can still receive, send ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if (seg->flags & FLAG_FIN) {
			//if FIN, send ACK, TIME_WAIT
			PRINT_DEBUG("FIN_WAIT_2: FIN, send ACK, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_TIME_WAIT;
			startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
			if (seg->data_len) {
				*send_flags |= FLAG_ACK;
			} else {
				*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
			}
			return 1;
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_CLOSING:
		//self, can still get ACKs & resend
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			if (conn->fin_sent) {
				//if ACK, send -, TIME_WAIT
				PRINT_DEBUG("CLOSING: ACK, send -, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_TIME_WAIT;
				startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
			} else {
				PRINT_DEBUG("CLOSING: ACK, send FIN, CLOSING/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				*send_flags |= FLAG_FIN;
			}
			return 1;
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			if (seg->data_len) {
				*send_flags |= FLAG_ACK;
			} else {
				*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
			}
			return 1;
		} else if (seg->data_len) { //TODO check!
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_TIME_WAIT:
		//TIMEOUT
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			if (seg->data_len) {
				*send_flags |= FLAG_ACK;
			} else {
				*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
			}
			return 1;
		} else {
			return 1;
		}
		//startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
		//*send_flags |= FLAG_ACK;
		return 1;
	case TCP_CLOSE_WAIT:
		//can still send & get ACKs
		if (seg->flags & (FLAG_SYN | FLAG_RST)) {
			//drop
			return 0;
		} else if (seg->flags & FLAG_FIN) { //TODO check!
			if (seg->data_len) {
				*send_flags |= FLAG_ACK;
			} else {
				*send_flags |= FLAG_ACK | FLAG_ACK_PLUS;
			}
			return 1;
		} else if (seg->data_len) {
			*send_flags |= FLAG_ACK;
			return 1;
		} else {
			return 1;
		}
	case TCP_LAST_ACK:
		//can still get ACKs & resend data
		if ((seg->flags & FLAG_ACK) && conn->send_seq_num == conn->send_seq_end) {
			if (conn->fin_sent) {
				//if ACK, send -, CLOSED
				PRINT_DEBUG("LAST_ACK: ACK, send -, CLOSED: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSED;
				if (seg->data_len) {
					*send_flags |= FLAG_ACK; //TODO remove?
				}
				return 1;
			} else {
				//if ACK, send FIN, LAST_ACK
				PRINT_DEBUG("LAST_ACK: ACK, send FIN, LAST_ACK/FIN_SENT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				if (seg->data_len) {
					*send_flags |= FLAG_ACK | FLAG_FIN;
				} else {
					*send_flags |= FLAG_FIN;
				}
				return 1;
			}
		} else {
			return 1;
		}
	default:
		return 0;
	}
}

int process_options(struct tcp_connection *conn, struct tcp_segment *seg) {
	uint8_t *pt = seg->options;
	uint8_t i = 0;
	uint8_t kind;
	uint8_t len;

	while (i < seg->opt_len) {
		kind = pt[i++];
		switch (kind) {
		case TCP_EOL:
			PRINT_DEBUG("EOL: (%u/%u)", i-1, seg->opt_len);
			return 1;
		case TCP_NOP:
			PRINT_DEBUG("NOP: (%u/%u)", i-1, seg->opt_len);
			continue;
		case TCP_MSS:
			len = pt[i++];
			if (len == TCP_MSS_BYTES) {
				uint16_t mss = ntohs(*(uint16_t *) (pt + i));
				i += sizeof(uint16_t);

				PRINT_DEBUG("MSS: (%u/%u) mss=%u", i-TCP_MSS_BYTES, seg->opt_len, mss);

				if (conn->state == TCP_SYN_RECV || conn->state == TCP_SYN_SENT) {
					if (mss < conn->MSS) {
						conn->MSS = mss;
					}
				}
			} else {
				PRINT_DEBUG("MSS: (%u/%u) len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_WS:
			len = pt[i++];
			if (len == TCP_WS_BYTES) {
				uint8_t ws = pt[i++];

				PRINT_DEBUG("WS: (%u/%u) ws=%u", i-TCP_WS_BYTES, seg->opt_len, ws);

				if (conn->state == TCP_SYN_RECV || conn->state == TCP_SYN_SENT) {
					if (conn->wsopt_attempt) {
						if (ws) {
							PRINT_DEBUG("WS: WS enabled");
							conn->wsopt_enabled = 1;
							if (ws < TCP_WS_MAX) {
								conn->ws_send = ws;
							} else {
								conn->ws_send = TCP_WS_MAX;
							}
						}
					}
				}
			} else {
				PRINT_DEBUG("WS: (%u/%u) len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_SACK_PERM:
			len = pt[i++];
			if (len == TCP_SACK_PERM_BYTES) {
				PRINT_DEBUG("SACK Perm: (%u/%u)", i-TCP_SACK_PERM_BYTES, seg->opt_len);

				if (conn->state == TCP_SYN_RECV || conn->state == TCP_SYN_SENT) {
					if (conn->sack_attempt) {
						PRINT_DEBUG("SACK Perm: SACK enabled");
						conn->sack_enabled = 1;
					}
				}
			} else {
				PRINT_DEBUG("SACK Perm: (%u/%u) len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_SACK:
			len = pt[i++];
			if (TCP_SACK_MIN_BYTES <= len && len <= TCP_SACK_MAX_BYTES) {
				//TODO
				PRINT_DEBUG("SACK: (%u/%u) len=%u", i-TCP_SACK_MIN_BYTES, seg->opt_len, len);
			} else {
				PRINT_DEBUG("SACK: (%u/%u) len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_TS:
			len = pt[i++];
			if (len == TCP_TS_BYTES) {
				uint32_t ts_val = ntohl(*(uint32_t *) (pt + i));
				i += sizeof(uint32_t);

				uint32_t ts_secr = ntohl(*(uint32_t *) (pt + i));
				i += sizeof(uint32_t);

				PRINT_DEBUG("TS: (%u/%u) len=%u ts_val=%u ts_secr=%u", i-TCP_TS_BYTES, seg->opt_len, len, ts_val, ts_secr);

				if (conn->state == TCP_SYN_RECV || conn->state == TCP_SYN_SENT) {
					if (conn->tsopt_attempt) {
						PRINT_DEBUG("TS: TS enabled");
						conn->tsopt_enabled = 1;

						//TODO
						if (conn->ts_rem > ts_val) {
							//error
							return 0;
						}
						//conn->ts_rem = ts_val;
					}
				} else if (conn->tsopt_enabled) {
					//TODO

					//conn->ts_rem = ts_val;
				}
			} else {
				PRINT_DEBUG("TS: (%u/%u) len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		default:
			break;
		}
	}

	return 1;
}

int process_seg(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *send_flags) {
	int ret = process_flags(conn, seg, send_flags);
	if (ret == -1) {
		PRINT_ERROR("problem, dropping");
		//send RST etc
		return 0;
	} else if (ret == 0) {
		//don't send anything, drop data
		if (seg->opt_len) {
			process_options(conn, seg); //TODO check correct place?
		}

		return 1;
	} else {
		//send data
	}
	
	//conn->recv_seq_num += (uint32_t) seg->data_len;
	//conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

	PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
			conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
	//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

	if (seg->data_len) {
		//send data to daemon
		if (tcp_fdf_to_daemon(seg->data, seg->data_len, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port)) {
			//fine
			/*#*/PRINT_DEBUG("");
			seg->data_len = 0;
		} else {
			//TODO big error
			PRINT_ERROR("todo error");
			return 0;
		}
	}

	return 1;
}

uint16_t handle_data(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_node *node;

	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	int ret;
	//uint16_t flags = 0;
	uint16_t send_flags = 0;

	//data handling
	if (seg->seq_num == conn->recv_seq_num) { //add check for overlapping?
		//in order seq num

		if (process_seg(conn, seg, &send_flags)) {
			conn->recv_win = ((uint16_t) seg->data_len < conn->recv_win) ? conn->recv_win - (uint16_t) seg->data_len : 0;
		} else {
			PRINT_DEBUG("todo error");
			//TODO error
		}
		seg_free(seg);

		//remove /transfer
		while (!queue_is_empty(conn->recv_queue)) {
			if (conn->recv_queue->front->seq_num < conn->recv_seq_num) {
				if (conn->recv_seq_num <= conn->recv_seq_end) {
					node = queue_remove_front(conn->recv_queue);
					seg = (struct tcp_segment *) node->data;
					if (conn->recv_win + (uint16_t) seg->data_len < conn->recv_win || conn->recv_max_win < conn->recv_win + (uint16_t) seg->data_len) {
						conn->recv_win = conn->recv_max_win;
					} else {
						conn->recv_win += (uint16_t) seg->data_len;
					}
					seg_free(seg);
					free(node);
				} else {
					if (conn->recv_queue->front->seq_num < conn->recv_seq_end) { //wrap around
						break;
					} else {
						node = queue_remove_front(conn->recv_queue);
						seg = (struct tcp_segment *) node->data;
						if (conn->recv_win + (uint16_t) seg->data_len < conn->recv_win || conn->recv_max_win < conn->recv_win + (uint16_t) seg->data_len) {
							conn->recv_win = conn->recv_max_win;
						} else {
							conn->recv_win += (uint16_t) seg->data_len;
						}
						seg_free(seg);
						free(node);
					}
				}
			} else if (conn->recv_queue->front->seq_num == conn->recv_seq_num) {
				node = queue_remove_front(conn->recv_queue);
				seg = (struct tcp_segment *) node->data;

				if (process_seg(conn, seg, &send_flags)) {
					PRINT_DEBUG("Connected to seq=%u datalen:%d\n", seg->seq_num, seg->data_len);
				} else {
					PRINT_DEBUG("todo error");
					//TODO error
				}

				seg_free(seg);
				free(node);
			} else {
				if (conn->recv_seq_num <= conn->recv_seq_end) {
					if (conn->recv_queue->front->seq_num < conn->recv_seq_end) {
						break;
					} else {
						node = queue_remove_front(conn->recv_queue);
						seg = (struct tcp_segment *) node->data;
						if (conn->recv_win + (uint16_t) seg->data_len < conn->recv_win || conn->recv_max_win < conn->recv_win + (uint16_t) seg->data_len) {
							conn->recv_win = conn->recv_max_win;
						} else {
							conn->recv_win += (uint16_t) seg->data_len;
						}
						seg_free(seg);
						free(node);
					}
				} else {
					break;
				}
			}
		}

		/*#*/PRINT_DEBUG("");
		sem_post(&conn->main_wait_sem); //signal recv main thread
	} else {
		if (seg->data_len) {
			send_flags |= FLAG_ACK;
		} else if (seg->flags & FLAG_FIN) {
			send_flags |= FLAG_ACK;
		}

		//re-ordered segment
		if (conn->recv_win) {
			if (in_window(seg->seq_num, seg->seq_end, conn->recv_seq_num, conn->recv_seq_end)) {
				node = node_create((uint8_t *) seg, seg->data_len, seg->seq_num, seg->seq_end);
				ret = queue_insert(conn->recv_queue, node, conn->recv_seq_num, conn->recv_seq_end);
				if (ret) {
					conn->recv_win = ((uint16_t) seg->data_len < conn->recv_win) ? conn->recv_win - (uint16_t) seg->data_len : 0;
				} else {
					PRINT_DEBUG("Dropping duplicate rem=(%u, %u) got=(%u, %u)\n", conn->recv_seq_num, conn->recv_seq_end, seg->seq_num, seg->seq_end);
					seg_free(seg);
					free(node);
				}
			} else {
				PRINT_DEBUG("Dropping out of window rem=(%u, %u) got=(%u, %u)\n", conn->recv_seq_num, conn->recv_seq_end, seg->seq_num, seg->seq_end);
				seg_free(seg);
			}
		} else {
			PRINT_DEBUG("Dropping window full host_window=%u\n", conn->recv_win);
			seg_free(seg);
		}
	}

	return send_flags;
}

void handle_reply(struct tcp_connection *conn, uint16_t flags) {
	struct tcp_segment *seg;
	PRINT_DEBUG("Entered: conn=%p, flags=%x", conn, flags);

	//send reply
	if (flags & FLAG_FIN) {
		if (conn->fin_sent) {
			//TODO prob
			PRINT_DEBUG("todo error");
			PRINT_DEBUG("removing fin");
			flags &= ~FLAG_FIN;
		} else {
			conn->fin_sent = 1;
			conn->fin_sep = 1;
			//conn->send_seq_end++;
			conn->fin_ack = conn->send_seq_end + 1;
		}
	}

	if (flags & FLAG_ACK) {
		if (conn->delayed_flag || (flags & FLAG_FIN)) {
			stopTimer(conn->to_delayed_fd);
			conn->delayed_flag = 0;
			conn->to_delayed_flag = 0;

			seg = seg_create(conn);
			seg_update(seg, conn, flags);
			seg_send(seg);
			seg_free(seg);
		} else {
			conn->delayed_flag = 1;
			conn->delayed_ack_flags = flags;
			conn->to_delayed_flag = 0;
			startTimer(conn->to_delayed_fd, TCP_DELAYED_TO_DEFAULT);
		}
	} else {
		seg = seg_create(conn);
		seg_update(seg, conn, flags);
		seg_send(seg);
		seg_free(seg);
	}
}

void *syn_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	struct tcp_segment *seg = thread_data->seg;

	uint16_t calc;
	struct tcp_node *node;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn_stub=%p", conn_stub);
	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn_stub->running_flag) {
		calc = seg_checksum(seg); //TODO add alt checksum, not really used
		PRINT_DEBUG("checksum=%u calc=%u %u", seg->checksum, calc, seg->checksum == calc);
		if (!calc || 1) { //TODO remove override when IP prob fixed
			if (queue_has_space(conn_stub->syn_queue, 1)) {
				node = node_create((uint8_t *) seg, 1, seg->seq_num, seg->seq_num);
				queue_append(conn_stub->syn_queue, node);

				PRINT_DEBUG("");
				sem_post(&conn_stub->accept_wait_sem);
			} else {
				//queue full
				PRINT_DEBUG("");
				seg_free(seg);
			}
		} else {
			PRINT_ERROR("Checksum: recv=%u calc=%u\n", seg->checksum, calc);
			seg_free(seg);
		}
	} else {
		PRINT_DEBUG("");
		seg_free(seg);
	}

	PRINT_DEBUG("");
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
	free(thread_data);
	pthread_exit(NULL);
}

void tcp_recv_syn(struct tcp_connection_stub *conn_stub, struct tcp_segment *seg) {
	struct tcp_node *node;

	if (queue_has_space(conn_stub->syn_queue, 1)) {
		node = node_create((uint8_t *) seg, 1, seg->seq_num, seg->seq_num);
		queue_append(conn_stub->syn_queue, node);

		/*#*/PRINT_DEBUG("");
		sem_post(&conn_stub->accept_wait_sem);
	} else {
		//queue full
		//drop
		PRINT_DEBUG("");
	}
}

void recv_closed(struct tcp_connection *conn, struct tcp_segment *seg) {
	//TODO if RST, -, -
	//TODO if ACK, <SEQ=SEG.ACK><CTL=RST>
	//TODO else, <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
	PRINT_DEBUG("Entered: dropping: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	if (seg->flags & FLAG_RST) {
		PRINT_DEBUG("todo");
	} else if (seg->flags & FLAG_ACK) {
		PRINT_DEBUG("todo");
	} else {
		PRINT_DEBUG("todo");
	}

	seg_free(seg);
}

void recv_listen(struct tcp_connection *conn, struct tcp_segment *seg) {
	//ERROR shouldn't ever arrive here in this thread, kept if merge stubs
	PRINT_DEBUG("Entered: Shouldn't arrive here: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO if RST, -, -
	//TODO if ACK, <SEQ=SEG.ACK><CTL=RST>
	//TODO if SYN, check sec,

	seg_free(seg);
}

void recv_syn_sent(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_segment *temp_seg;

	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO ACK, If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset <SEQ=SEG.ACK><CTL=RST>
	//TODO ACK, If SND.UNA =< SEG.ACK =< SND.NXT

	if (seg->flags & FLAG_RST) {
		//TODO find out
		PRINT_DEBUG("RST dropping");
	} else if (seg->flags & FLAG_FIN) {
		//TODO find out
		PRINT_DEBUG("FIN dropping");
	} else if (seg->flags & FLAG_SYN) {
		if (seg->flags & FLAG_ACK) {
			//if SYN ACK, send ACK, ESTABLISHED
			if (seg->ack_num == conn->send_seq_num + 1) {
				if (seg->opt_len) {
					process_options(conn, seg); //TODO check if right place
				}

				PRINT_DEBUG("SYN ACK, send ACK, ESTABLISHED: state=%d", conn->state);
				conn->state = TCP_ESTABLISHED;

				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				conn->send_win = (uint32_t) seg->win_size;
				conn->send_max_win = conn->send_win;

				conn->irsn = seg->seq_num;
				conn->recv_seq_num = seg->seq_num + 1;
				conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
				//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//flags
				conn->first_flag = 1;
				conn->duplicate = 0;
				conn->fast_flag = 0;
				conn->gbn_flag = 0;

				//RTT
				stopTimer(conn->to_gbn_fd);
				conn->timeout = TCP_GBN_TO_DEFAULT;

				//Cong
				conn->cong_state = RENO_SLOWSTART;
				conn->cong_window = (double) conn->MSS;
				conn->threshhold = conn->send_max_win / 2.0;

				//TODO piggy back data? release to established with delayed TO on
				//send ACK
				temp_seg = seg_create(conn);
				seg_update(temp_seg, conn, FLAG_ACK);
				seg_send(temp_seg);
				seg_free(temp_seg);

				//send ACK to handler, prob connect
				if (conn->ff) {
					//conn_send_daemon(conn, EXEC_TCP_CONNECT, 1, 0);
					tcp_reply_fcf(conn->ff, 1, 0);
					conn->ff = NULL;
				} else {
					PRINT_DEBUG("todo error");
				}
			} else {
				PRINT_DEBUG("Invalid ACK: was not sent: ack=%u, host_seq_num=%u", seg->ack_num, conn->send_seq_num);

				//SYN ACK for dup SYN, send RST, resend SYN

				//TODO finish, search send_queue & only RST if old SYN

				//TODO remove dup SYN packet from send_queue

				//send RST
				temp_seg = seg_create(conn);
				temp_seg->seq_num = seg->ack_num;
				seg_update(temp_seg, conn, FLAG_RST);
				seg_send(temp_seg);
				seg_free(temp_seg);

				//TODO WAIT then send SYN
			}
		} else {
			//TODO process options, decide: MSS, max window size!!
			if (seg->opt_len) {
				process_options(conn, seg);
			}

			//if SYN, send SYN ACK, SYN_RECV (simultaneous)
			PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
			conn->state = TCP_SYN_RECV;

			conn->send_win = (uint32_t) seg->win_size;
			conn->send_max_win = conn->send_win;

			conn->irsn = seg->seq_num;
			conn->recv_seq_num = seg->seq_num + 1;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			temp_seg = seg_create(conn);
			seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
			seg_send(temp_seg);
			seg_free(temp_seg);

			startTimer(conn->to_gbn_fd, TCP_MSL_TO_DEFAULT); //TODO figure out to's
		}
	} else {
		PRINT_DEBUG("Invalid Seg: SYN_SENT & not SYN.");
	}

	seg_free(seg);
}

void recv_syn_recv(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_segment *temp_seg;
	uint16_t flags;
	//uint8_t reply;

	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	if (seg->flags & FLAG_RST) {
		//TODO handle RSTs back
		//if RST, send -, LISTEN

		PRINT_DEBUG("");

		//TODO finish? verify/add conn_stub, free conn
	} else if (seg->flags & FLAG_FIN) {
		//drop
		PRINT_DEBUG("todo error");
	} else if (seg->flags & FLAG_ACK) {
		//if ACK/SYN ACK, send -, ESTABLISHED
		if (seg->ack_num == conn->send_seq_num + 1) {
			//TODO process options
			if (seg->opt_len) {
				process_options(conn, seg);
			}

			PRINT_DEBUG("ACK/SYN ACK, send -, ESTABLISHED: state=%d", conn->state);
			conn->state = TCP_ESTABLISHED;

			conn->send_seq_num = seg->ack_num;
			conn->send_seq_end = conn->send_seq_num;
			conn->recv_seq_num = seg->seq_num;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
			conn->send_win = (uint32_t) seg->win_size;
			conn->send_max_win = conn->send_win;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//flags
			conn->first_flag = 1;
			conn->fast_flag = 0;
			conn->gbn_flag = 0;

			//RTT
			stopTimer(conn->to_gbn_fd);
			conn->timeout = TCP_GBN_TO_DEFAULT;

			//Cong
			conn->cong_state = RENO_SLOWSTART;
			conn->cong_window = (double) conn->MSS;
			conn->threshhold = conn->send_max_win / 2.0;

			if (!(seg->flags & FLAG_ACK)) {
				flags = handle_data(conn, seg);

				if (flags) {
					handle_reply(conn, flags);
				}
			}

			//send ACK to handler, prob accept
			if (conn->ff) {
				//conn_send_daemon(conn, EXEC_TCP_ACCEPT, 1, 0);

				conn_reply_fcf(conn, 1, 0);
				conn->ff = NULL;
			} else {
				PRINT_DEBUG("todo error");
			}
		} else {
			PRINT_DEBUG("Invalid ACK: was not sent.");
			//TODO send RST?
			PRINT_DEBUG("todo error");
		}
	} else if (seg->flags & FLAG_SYN) {
		if (seg->opt_len) {
			process_options(conn, seg);
		}

		//if SYN, send SYN ACK, SYN_RECV
		PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
		conn->issn = tcp_rand(); //TODO uncomment
		conn->send_seq_num = conn->issn;
		conn->send_seq_end = conn->send_seq_num;
		conn->send_win = (uint32_t) seg->win_size;

		conn->irsn = seg->seq_num;
		conn->recv_seq_num = seg->seq_num + 1;
		conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
		//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

		//conn_change_options(conn, tcp->options, SYN); //?

		//send SYN ACK
		temp_seg = seg_create(conn);
		seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
		seg_send(temp_seg);
		seg_free(temp_seg);

		startTimer(conn->to_gbn_fd, TCP_MSL_TO_DEFAULT);
	} else {
		PRINT_DEBUG("Invalid Seg: SYN_RECV & not ACK.");
	}

	seg_free(seg);
}

void recv_established(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO can receive, send ACKs, send/resend data, & get ACKs

	if (seg->flags & FLAG_RST) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	if (seg->flags & FLAG_URG) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}
}

void recv_fin_wait_1(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO merge with established, can still get ACKs, receive, send ACKs, & resend data
	//if FIN, send ACK, CLOSING
	//if FIN ACK, send ACK, TIME_WAIT
	//if ACK, send -, FIN_WAIT_2

	if (seg->flags & FLAG_RST) {
		PRINT_DEBUG("todo");
	}

	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	if (seg->flags & FLAG_URG) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}
}

void recv_fin_wait_1_old(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO merge with established, can still get ACKs, receive, send ACKs, & resend data
	//if FIN, send ACK, CLOSING
	//if FIN ACK, send ACK, TIME_WAIT
	//if ACK, send -, FIN_WAIT_2

	if (seg->flags & FLAG_RST) {
		PRINT_DEBUG("todo");
	}

	if (seg->flags & FLAG_ACK) {
		if (conn->fin_sent && conn->fin_sep && conn->send_seq_num == conn->send_seq_end) {
			if (seg->ack_num == conn->fin_ack) {
				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
					if (conn->wsopt_enabled) {
						conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
					} else {
						conn->send_win = (uint32_t) seg->win_size;
					}
					conn->send_win_seq = seg->seq_num;
					conn->send_win_ack = seg->ack_num;
				}

				//TODO process ACK options

				PRINT_DEBUG("ACK, send -, FIN_WAIT_2: state=%d", conn->state);
				conn->state = TCP_FIN_WAIT_2;
			} else {
				//TODO RST?
				PRINT_DEBUG("todo");
			}
		} else {
			handle_ACK(conn, seg);

			if (conn->fin_sent && conn->send_seq_num == conn->fin_ack) {
				PRINT_DEBUG("ACK, send -, FIN_WAIT_2: state=%d", conn->state);
				conn->state = TCP_FIN_WAIT_2;
			}
		}
	}

	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}
}

void recv_fin_wait_2(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO merge with established, can still receive, send ACKs
	//if FIN, send ACK, TIME_WAIT
	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}
}

void recv_closing(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO self, can still get ACKs & resend
	//if ACK, send -, TIME_WAIT

	if (seg->flags & FLAG_RST) {
		PRINT_DEBUG("todo");
	}

	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	if (seg->flags & FLAG_URG) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}

	//seg_free(seg);
}

void recv_closing_old(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO self, can still get ACKs & resend
	//if ACK, send -, TIME_WAIT

	if (seg->flags & FLAG_RST) {
		//TODO handle
		PRINT_DEBUG("todo");
	}

	if (conn->fin_sent && conn->fin_sep && conn->send_seq_num == conn->send_seq_end) { //TODO remove, unnecessary w/handle_ACK changes
		if (seg->ack_num == conn->fin_ack) {
			//TODO process ACK options

			conn->send_seq_num = seg->ack_num;
			conn->send_seq_end = conn->send_seq_num;
			if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			}

			//if ACK, send -, TIME_WAIT
			PRINT_DEBUG("ACK, send -, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_TIME_WAIT;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/); //TODO uncomment
		} else {
			//TODO RST
			PRINT_DEBUG("todo");
		}
	} else {
		handle_ACK(conn, seg);

		if (conn->fin_sent && conn->send_seq_num == conn->fin_ack) {
			PRINT_DEBUG("ACK, send -, TIME_WAIT: state=%d conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TCP_TIME_WAIT;

			startTimer(conn->to_gbn_fd, 2 /* *DEFAULT_MSL*/);
		}
	}

	seg_free(seg);
}

void recv_time_wait(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: dropping: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//if FIN, send ACK

	if (seg->flags & FLAG_RST) {

	}

	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	if (seg->flags & FLAG_URG) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	flags = handle_data(conn, seg);

	if (flags) {
		handle_reply(conn, flags);
	}

	//seg_free(seg);
}

void recv_close_wait(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO can still send & get ACKs
	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	seg_free(seg);
}

void recv_last_ack(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO can still get ACKs & resend data
	//if ACK, send -, CLOSED

	if (seg->flags & FLAG_RST) {
		PRINT_DEBUG("todo");
	}

	if (seg->flags & FLAG_ACK) {
		handle_ACK(conn, seg);
	}

	if (seg->flags & FLAG_URG) {
		//TODO implement
		PRINT_DEBUG("todo");
	}

	flags = handle_data(conn, seg);

	if (conn->state == TCP_CLOSED) {
		if (conn->ff_close) {
			//conn_send_daemon(conn, EXEC_TCP_CLOSE, 1, 0); //TODO check move to end of last_ack/start of time_wait?
			tcp_reply_fcf(conn->ff_close, 1, 0);
			conn->ff_close = NULL;
		} else {
			PRINT_DEBUG("todo error");
			//TODO error
		}

		conn_shutdown(conn);
	}

	if (flags) {
		handle_reply(conn, flags);
	}

	//seg_free(seg);
}

void recv_last_ack_old(struct tcp_connection *conn, struct tcp_segment *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO can still get ACKs & resend data
	//if ACK, send -, CLOSED
	if (seg->flags & FLAG_ACK) {
		if (conn->fin_sent && conn->send_seq_num == conn->send_seq_end) {
			if (seg->ack_num == conn->fin_ack) {
				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
					if (conn->wsopt_enabled) {
						conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
					} else {
						conn->send_win = (uint32_t) seg->win_size;
					}
					conn->send_win_seq = seg->seq_num;
					conn->send_win_ack = seg->ack_num;
				}

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u) win=(%u/%u), rem: seqs=(%u, %u) (%u, %u) win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
				//conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//TODO process ACK options

				//if ACK, send -, CLOSED
				PRINT_DEBUG("ACK, send -, CLOSED: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSED;

				//conn_send_daemon(conn, EXEC_TCP_CLOSE, 1, 0); //TODO check move to end of last_ack/start of time_wait?
				if (conn->ff_close) {
					//conn_send_daemon(conn, EXEC_TCP_CLOSE, 1, 0); //TODO check move to end of last_ack/start of time_wait?
					tcp_reply_fcf(conn->ff_close, 1, 0);
					conn->ff_close = NULL;
				} else {
					PRINT_DEBUG("todo error");
					//TODO error
				}

				conn_shutdown(conn);
			} else {
				//TODO RST
				PRINT_DEBUG("todo");
			}
		} else {
			handle_ACK(conn, seg);

			if (conn->fin_sent && conn->send_seq_num == conn->fin_ack) {
				PRINT_DEBUG("ACK, send -, CLOSED: state=%d conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TCP_CLOSED;
			}
		}
	}

	seg_free(seg);
}

void *recv_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct tcp_segment *seg = thread_data->seg;

	uint16_t calc;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		calc = seg_checksum(seg); //TODO add alt checksum
		PRINT_DEBUG("checksum=%u, calc=%u", seg->checksum, calc);
		if (seg->checksum == 0 || calc == 0) { //TODO remove override when IP prob fixed
			if (seg->checksum == 0) {
				//ignore checksum
			}

			switch (conn->state) {
			case TCP_CLOSED:
				recv_closed(conn, seg);
				break;
			case TCP_LISTEN:
				recv_listen(conn, seg);
				break;
			case TCP_SYN_SENT:
				recv_syn_sent(conn, seg);
				break;
			case TCP_SYN_RECV:
				recv_syn_recv(conn, seg);
				break;
			case TCP_ESTABLISHED:
				recv_established(conn, seg);
				break;
			case TCP_FIN_WAIT_1:
				recv_fin_wait_1(conn, seg);
				break;
			case TCP_FIN_WAIT_2:
				recv_fin_wait_2(conn, seg);
				break;
			case TCP_CLOSING:
				recv_closing(conn, seg);
				break;
			case TCP_TIME_WAIT:
				recv_time_wait(conn, seg);
				break;
			case TCP_CLOSE_WAIT:
				recv_close_wait(conn, seg);
				break;
			case TCP_LAST_ACK:
				recv_last_ack(conn, seg);
				break;
			}
		} else {
			PRINT_ERROR("Checksum: recv=%u calc=%u\n", seg->checksum, calc);
			seg_free(seg);
		}
	} else {
		PRINT_DEBUG("not running, dropping: seg=%p", seg);
		seg_free(seg);
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

	PRINT_DEBUG("Entered: ff=%p", ff);

	seg = fdf_to_tcp(ff);
	if (seg) {
		/*#*/PRINT_DEBUG("");
		if (sem_wait(&conn_list_sem)) {
			PRINT_ERROR("conn_list_sem wait prob");
			exit(-1);
		}
		conn = conn_list_find(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
		if (conn) {
			start = (conn->threads < TCP_THREADS_MAX) ? ++conn->threads : 0;
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_list_sem);

			if (start) {
				thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
				thread_data->id = tcp_gen_thread_id();
				thread_data->conn = conn;
				thread_data->seg = seg;

				if (pthread_create(&thread, NULL, recv_thread, (void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
				pthread_detach(thread);
			} else {
				PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
			}
		} else {
			/*#*/PRINT_DEBUG("");
			sem_post(&conn_list_sem);

			if ((seg->flags & FLAG_SYN) && !(seg->flags & (FLAG_RST | FLAG_ACK | FLAG_FIN))) {
				//TODO check security, send RST if lower, etc

				//check if listening sockets
				/*#*/PRINT_DEBUG("");
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_stub_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_list_find(seg->dst_ip, seg->dst_port);
				if (conn_stub) {
					start = (conn_stub->threads < TCP_THREADS_MAX) ? ++conn_stub->threads : 0;
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);

					if (start) {
						thread_data = (struct tcp_thread_data *) malloc(sizeof(struct tcp_thread_data));
						thread_data->id = tcp_gen_thread_id();
						thread_data->conn_stub = conn_stub;
						thread_data->seg = seg;

						if (pthread_create(&thread, NULL, syn_thread, (void *) thread_data)) {
							PRINT_ERROR("ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
						pthread_detach(thread);
					} else {
						PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
					}
				} else {
					/*#*/PRINT_DEBUG("");
					sem_post(&conn_stub_list_sem);
					PRINT_DEBUG("Found no stub. Dropping...");
					seg_free(seg);
				}
			} else {
				PRINT_DEBUG("Found no connection. Dropping...");

				//TODO if ACK, send <SEQ=SEG.ACK><CTL=RST>
				//TODO else, <SEQ=0><ACK=seq+len><CTL=RST>

				seg_free(seg);
			}
		}
	} else {
		PRINT_DEBUG("Bad tcp_seg. Dropping...");
	}

	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

//################################################## Older/Not used attempts

int handle_seq_num(struct tcp_connection *conn, struct tcp_segment *seg) {
	if (in_window_overlaps(seg->seq_num, seg->seq_end, conn->recv_seq_num, conn->recv_seq_end)) {
		if (seg->seq_num == conn->recv_seq_num) {
			//continue processing
			return 1;
		} else if (seg->seq_num < conn->recv_seq_num) {
			//process but start data from RSN
			return 1;
		} else {
			//seg acceptable but out of order, buffer
			return 0;
		}
	} else {
		//out of window drop
		return -1;
	}
}

int handle_rst(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *reply_flags) {

	if (seg->flags & FLAG_RST) {
		switch (conn->state) {
		case TCP_SYN_RECV:
			if (conn->active_open) {
				//TODO if active (SYN_SENT), signal connection refused
			} else {
				//TODO if passive open (listen) do nothing
			}
			break;
		case TCP_ESTABLISHED:
		case TCP_FIN_WAIT_1:
		case TCP_FIN_WAIT_2:
		case TCP_CLOSE_WAIT:
			//TODO flush queues, send signal connection reset to core, stop send's/recv's, CLOSED, del conn
			conn->state = TCP_CLOSED;

			break;
		case TCP_CLOSING:
		case TCP_LAST_ACK:
		case TCP_TIME_WAIT:
			//TODO CLOSED, del conn
			break;
		default:
			//TODO
			break;
		}
	}

	return 1;
}
int handle_auth(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int handle_syn(struct tcp_connection *conn, struct tcp_segment *seg) {
	switch (conn->state) {
	case TCP_SYN_RECV:
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT_1:
	case TCP_FIN_WAIT_2:
	case TCP_CLOSE_WAIT:
	case TCP_CLOSING:
	case TCP_LAST_ACK:
	case TCP_TIME_WAIT:
		//TODO if SYN in win, send RST, similar to above
		break;
	default:
		//TODO
		break;
	}
	return 1;
}
int handle_ack_test(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *reply_flags) {

	if (seg->flags & FLAG_ACK) {
		switch (conn->state) {
		case TCP_SYN_RECV:
			if (seg->ack_num == conn->send_seq_num + 1) {
				conn->state = TCP_ESTABLISHED;
				//do setup stuff
			} else {
				//TODO send RST
				*reply_flags = FLAG_RST;
			}
			break;
		case TCP_ESTABLISHED:
			//stuff similar
			if (conn->send_seq_num == seg->ack_num) {
				//duplicate

				if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
					if (conn->wsopt_enabled) {
						conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
					} else {
						conn->send_win = (uint32_t) seg->win_size;
					}
					conn->send_win_seq = seg->seq_num;
					conn->send_win_ack = seg->ack_num;
				}
			} else if (conn->send_seq_end == seg->ack_num) {
				//fill with handle_ack

				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			} else if (in_window_overlaps(seg->ack_num, seg->ack_num, conn->send_seq_num, conn->send_seq_end)) {
				//remove fully ack'd seg's in send_queue

				if (conn->wsopt_enabled) {
					conn->send_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_win = (uint32_t) seg->win_size;
				}
				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			} else {
				//not in window
				//TODO if ack < SSN, ignore
				//TODO if SSE < ack, send ack
				//seg_free(seg);
				return 0;
			}
			break;
		case TCP_FIN_WAIT_1:
			//TODO ESTABLISHED process
			//TODO if fin_sent & ack it, FIN_WAIT_2
			break;
		case TCP_FIN_WAIT_2:
			//TODO ESTABLISHED process
			//TODO if SSN==SSE, ok close call
			break;
		case TCP_CLOSE_WAIT:
			//TODO ESTABLISHED process
			break;
		case TCP_CLOSING:
			//TODO ESTABLISHED process
			//TODO if fin_sent & ack it, TIME_WAIT
			break;
		case TCP_LAST_ACK:
			//TODO if fin_sent & ack it, CLOSED, conn_shutdown(conn);
			break;
		case TCP_TIME_WAIT:
			//TODO if rem fin, ack it, restart TO=2 MSL
			break;
		default:
			//TODO
			break;
		}
	}
	return 1;
}
int handle_urg(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int handle_data_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int handle_fin(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int recv_closed_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int recv_listen_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}
int recv_syn_sent_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	return 0;
}

void conn_send_ack_test(struct tcp_connection *conn) {
	struct tcp_segment *seg;

	seg = seg_create(conn);

	seg_update(seg, conn, FLAG_ACK);
	seg_send(seg);

	seg_free(seg);
}

void conn_send_reset_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	struct tcp_segment *temp_seg;

	//<SEQ=SEG.ACK><CTL=RST>
	temp_seg = seg_create(conn);
	seg_update(temp_seg, conn, FLAG_RST);

	if (seg->flags & FLAG_ACK) {
		temp_seg->seq_num = seg->ack_num;
	} else {
		temp_seg->seq_num = 0;
		temp_seg->ack_num = seg->seq_num + seg->data_len;
	}

	seg_send(temp_seg);
	seg_free(temp_seg);
}

int process_seg_test(struct tcp_connection *conn, struct tcp_segment *seg, uint16_t *reply_flags) {
	int ret;

	ret = handle_seq_num(conn, seg);
	if (ret == -1) {
		//TODO send ACK, unless RST
		//<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
		conn_send_ack_test(conn);
		return -1;
	} else if (ret == 0) {
		//TODO send ACK, unless RST
		//<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
		conn_send_ack_test(conn);
		return 0;
	} else {
		//continue processing
		if (seg->flags & FLAG_RST) {
			//check RST
			ret = handle_rst(conn, seg, reply_flags);
			if (ret) {
			} else {
			}
		}

		if (0) {
			//auth
			if (handle_auth(conn, seg)) {
			} else {
			}
		}

		if (seg->flags & FLAG_SYN) {
			//syn
			//TODO if SYN in win, send RST, similar to above
			conn_send_reset_test(conn, seg);
			//*reply_flags = FLAG_RST;
			return -1;
		}

		if (seg->flags & FLAG_ACK) {
			//ack
			ret = handle_ack_test(conn, seg, reply_flags);
			if (ret) {
			} else {
				return 0;
			}

		} else {
			//dropping
			seg_free(seg);
			return 0;
		}

		if (seg->flags & FLAG_URG) {
			//urg
			if (handle_urg(conn, seg)) {
			} else {
			}
		} else if (seg->data_len) {
			//data
			if (handle_data_test(conn, seg)) {
			} else {
			}
		} else if (seg->flags & FLAG_FIN) {
			//fin
			if (handle_fin(conn, seg)) { //TODO if may be unnecessary
			} else {
			}
		}
		return 1;
	}
}

//doesn't cover CLOSED, LISTEN, or SYN_SENT states
int recv_other_test(struct tcp_connection *conn, struct tcp_segment *seg) {
	int ret = 0;
	uint16_t reply_flags = 0;
	struct tcp_node *node;

	ret = process_seg_test(conn, seg, &reply_flags);
	if (ret == -1) {
		seg_free(seg);
	} else if (ret == 0) {
		if (conn->recv_win) {
			node = node_create((uint8_t *) seg, seg->data_len, seg->seq_num, seg->seq_end);
			ret = queue_insert(conn->recv_queue, node, conn->recv_seq_num, conn->recv_seq_end); //TODO augment for overlaps, duplicate should replace older one
			if (ret) {
				conn->recv_win = ((uint16_t) seg->data_len < conn->recv_win) ? conn->recv_win - (uint16_t) seg->data_len : 0;
			} else {
				PRINT_DEBUG("Dropping duplicate rem=(%u, %u) got=(%u, %u)\n", conn->recv_seq_num, conn->recv_seq_end, seg->seq_num, seg->seq_end);
				free(node);
				seg_free(seg);
			}
		} else {
			PRINT_DEBUG("Dropping window full host_window=%d\n", conn->recv_win);
			seg_free(seg);
		}
	} else {
		seg_free(seg);

		//TODO process others
		while (!queue_is_empty(conn->recv_queue)) {
			node = conn->recv_queue->front;
			seg = (struct tcp_segment *) node->data;

			ret = process_seg_test(conn, seg, &reply_flags);
			if (ret == -1) {
				queue_remove_front(conn->recv_queue);
				free(node);
				seg_free(seg);
			} else if (ret == 0) {
				break;
			} else {
				seg_free(seg);
			}
		}
	}

	//send reply using reply_flags

	return 0;
}

void *recv_thread_test(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	int id = thread_data->id;
	struct tcp_connection *conn = thread_data->conn;
	struct tcp_segment *seg = thread_data->seg;

	PRINT_DEBUG("Entered: id=%u", id);

	/*#*/PRINT_DEBUG("sem_wait: conn=%p", conn);
	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		uint16_t calc = seg_checksum(seg); //TODO add alt checksum
		PRINT_DEBUG("checksum=%u calc=%u %u", seg->checksum, calc, seg->checksum == calc);
		if (1 || seg->checksum == calc) { //TODO remove override when IP prob fixed
			if (conn->state == TCP_CLOSED) {
				recv_closed_test(conn, seg);
			} else if (conn->state == TCP_LISTEN) {
				recv_listen_test(conn, seg);
			} else if (conn->state == TCP_SYN_SENT) {
				recv_syn_sent_test(conn, seg);
			} else {
				recv_other_test(conn, seg);
			}
		} else {
			PRINT_ERROR("Checksum: recv=%u calc=%u\n", seg->checksum, calc);
			seg_free(seg);
		}
	} else {
		PRINT_DEBUG("not running, dropping: seg=%p", seg);
		seg_free(seg);
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

	free(thread_data);
	pthread_exit(NULL);
}

