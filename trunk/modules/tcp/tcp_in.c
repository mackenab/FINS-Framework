/*
 * @file tcp_in.c
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */
#include "tcp_internal.h"

void calcRTT(struct tcp_conn *conn) {
	struct timeval current;
	double sampRTT = 0;
	double alpha = 0.125, beta = 0.25;

	gettimeofday(&current, 0);

	PRINT_DEBUG("getting seqEndRTT=%d, stampRTT=(%d, %d)", conn->rtt_seq_end, (int)conn->rtt_stamp.tv_sec, (int)conn->rtt_stamp.tv_usec);
	PRINT_DEBUG("getting seqEndRTT=%d, current=(%d, %d)", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

	PRINT_DEBUG("old: sampleRTT=%f, estRTT=%f, devRTT=%f, timout=%f", sampRTT, conn->rtt_est, conn->rtt_dev, conn->timeout);

	conn->rtt_flag = 0;

	sampRTT = time_diff(&conn->rtt_stamp, &current);

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

	PRINT_DEBUG("new: sampleRTT=%f, estRTT=%f, devRTT=%f, timout=%f", sampRTT, conn->rtt_est, conn->rtt_dev, conn->timeout);
}

void handle_RST(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p", conn, seg);

	//sending:
	//if ACK, send <SEQ=SEG.ACK><CTL=RST> win=0
	//else, <SEQ=0><ACK=seq+len><CTL=RST> win=0

	if (tcp_in_window(seg->seq_num, seg->seq_end, conn->recv_seq_num, conn->recv_seq_end)
			|| (seg->seq_num == 0 && (seg->flags & FLAG_ACK) && tcp_in_window(seg->ack_num, seg->ack_num, conn->send_seq_num, conn->send_seq_end))) {
		//else state, aborts connection, advise user, goto CLOSED
		tcp_conn_shutdown(conn);
	} else {
		PRINT_ERROR(
				"RST out of window: conn=%p, host=%u:%u, rem=%u:%u, state=%u, seg=%p, seqs=(%u, %u) (%u, %u), recv=(%u, %u) (%u, %u), ack=%u (%u), send=(%u, %u) (%u, %u)",
				conn, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->state, seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, seg->ack_num-conn->issn, seg->ack_num, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end);
	}
}

void handle_ACK(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	PRINT_DEBUG("ack=%u, send=(%u, %u), sent=%u, sep=%u, fsse=%u (%u)",
			seg->ack_num-conn->issn, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);

	conn->stats.recv_acks++;
	__sync_add_and_fetch(&md->total_conn_stats.recv_acks, 1);

	struct tcp_node *node;
	struct tcp_node *temp_node;
	struct tcp_seg *temp_seg;

	//check if valid ACK
	if (tcp_in_window(seg->ack_num, seg->ack_num, conn->send_seq_num, conn->send_seq_end)) {
		if (seg->ack_num == conn->send_seq_num) {

			uint32_t updated = 0;
			if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
				if (conn->wsopt_enabled) {
					if (((uint32_t) seg->win_size) << conn->ws_send != conn->send_max_win) {
						updated = 1;
					}
					conn->send_max_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					if ((uint32_t) seg->win_size != conn->send_max_win) {
						updated = 1;
					}
					conn->send_max_win = (uint32_t) seg->win_size;
				}
				conn->send_win = conn->send_max_win;

				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			}

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//TODO process ACK options

			if (!updated) {
				if (conn->ack_checksum == seg->checksum) {
					//TODO should we really match this specific?
				}

				conn->duplicate++; //TODO fix, creating duplicate from ACK or FIN ACK.
				conn->stats.dup_acks++;
				__sync_add_and_fetch(&md->total_conn_stats.dup_acks, 1);

				//Cong
				PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
						conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
				switch (conn->cong_state) {
				case RENO_SLOWSTART:
				case RENO_AVOIDANCE:
					//check for FR
					if (md->fast_enabled && conn->duplicate >= md->fast_duplicates) {
						conn->duplicate = 0;

						//RTT
						conn->rtt_flag = 0;
						timer_once_start(conn->to_gbn_data->tid, conn->timeout);
						conn->to_gbn_flag = 0;

						PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
								conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
						conn->cong_state = RENO_RECOVERY;
						conn->fast_flag = 1;
						conn->restore_seq_end = conn->send_seq_end;

						conn->threshhold = fmax((conn->send_seq_end - conn->send_seq_num) / 2.0, 2.0 * conn->MSS);
						conn->cong_window = conn->threshhold + 3.0 * conn->MSS;
					} else {
						//duplicate ACK, no FR though
					}
					break;
				case RENO_RECOVERY:
					conn->cong_window += (double) conn->MSS; //in RFC but FR is sent right afterward in same code
					break;
				}
			}
		} else if (seg->ack_num == conn->send_seq_end) {
			//remove all segs
			while (!tcp_queue_is_empty(conn->send_queue)) {
				temp_node = tcp_queue_remove_front(conn->send_queue);
				temp_seg = (struct tcp_seg *) temp_node->data;

				PRINT_DEBUG( "acked: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
						temp_seg, temp_seg->seq_num-conn->issn, temp_seg->seq_end-conn->issn, temp_seg->seq_num, temp_seg->seq_end, temp_seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);

				tcp_seg_free(temp_seg);
				free(temp_node);
			}

			conn->send_seq_num = seg->ack_num;

			if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
				if (conn->wsopt_enabled) {
					conn->send_max_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_max_win = (uint32_t) seg->win_size;
				}
				conn->send_win = conn->send_max_win;

				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;
			}
			conn->ack_checksum = seg->checksum;
			conn->duplicate = 0;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			//TODO process ACK options

			//flags
			conn->fast_flag = 0;
			conn->gbn_flag = 0;

			//RTT
			if (conn->rtt_flag) {
				calcRTT(conn);
				conn->stats.rtt_dev_total += conn->rtt_dev;
				conn->stats.rtt_dev_count++;
				conn->stats.rtt_est_total += conn->rtt_est;
				conn->stats.rtt_est_count++;
				conn->stats.timeout_total += conn->timeout;
				conn->stats.timeout_count++;
				PRINT_DEBUG("dev=%f, est=%f, timeout=%f",
						conn->stats.rtt_dev_total/conn->stats.rtt_dev_count, conn->stats.rtt_est_total/conn->stats.rtt_est_count, conn->stats.timeout_total /conn->stats.timeout_count);
			}
			timer_stop(conn->to_gbn_data->tid);

			//Cong
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
			switch (conn->cong_state) {
			case RENO_SLOWSTART:
				conn->cong_window += (double) conn->MSS;
				if (conn->cong_window >= conn->threshhold) {
					conn->cong_state = RENO_AVOIDANCE;
				}
				break;
			case RENO_AVOIDANCE:
				conn->cong_window += fmax(((double) conn->MSS) * ((double) conn->MSS) / conn->cong_window, 1.0);
				break;
			case RENO_RECOVERY:
				conn->cong_state = RENO_AVOIDANCE;
				conn->cong_window = conn->threshhold;
				break;
			}
			PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
					conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
		} else {
			node = tcp_queue_find(conn->send_queue, seg->ack_num);
			if (node) {
				//remove ACK segs
				uint32_t num_nodes = 1;
				while (!tcp_queue_is_empty(conn->send_queue) && conn->send_queue->front != node) {
					temp_node = tcp_queue_remove_front(conn->send_queue);
					temp_seg = (struct tcp_seg *) temp_node->data;

					PRINT_DEBUG( "acked: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
							temp_seg, temp_seg->seq_num-conn->issn, temp_seg->seq_end-conn->issn, temp_seg->seq_num, temp_seg->seq_end, temp_seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);
					num_nodes++;

					tcp_seg_free(temp_seg); //TODO fix major problem!
					free(temp_node);
				}

				//TODO process ACK options

				//valid ACK
				conn->send_seq_num = seg->ack_num;

				if (conn->wsopt_enabled) {
					conn->send_max_win = ((uint32_t) seg->win_size) << conn->ws_send;
				} else {
					conn->send_max_win = (uint32_t) seg->win_size;
				}
				conn->send_win = conn->send_max_win;

				conn->send_win_seq = seg->seq_num;
				conn->send_win_ack = seg->ack_num;

				conn->ack_checksum = seg->checksum;
				conn->duplicate = 0;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//flags
				if (conn->gbn_flag) {
					conn->first_flag = 1;
				}

				//RTT
				if (conn->rtt_flag && !tcp_in_window(conn->rtt_seq_num, conn->rtt_seq_num, conn->send_seq_num, conn->send_seq_end)) {
					calcRTT(conn);
					conn->stats.rtt_dev_total += conn->rtt_dev;
					conn->stats.rtt_dev_count++;
					conn->stats.rtt_est_total += conn->rtt_est;
					conn->stats.rtt_est_count++;
					conn->stats.timeout_total += conn->timeout;
					conn->stats.timeout_count++;
					PRINT_DEBUG("dev=%f, est=%f, timeout=%f",
							conn->stats.rtt_dev_total/conn->stats.rtt_dev_count, conn->stats.rtt_est_total/conn->stats.rtt_est_count, conn->stats.timeout_total /conn->stats.timeout_count);
				}
				if (!conn->gbn_flag) {
					timer_once_start(conn->to_gbn_data->tid, conn->timeout);
					conn->to_gbn_flag = 0;
				}

				//Cong
				PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
						conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
				switch (conn->cong_state) {
				case RENO_SLOWSTART:
					conn->cong_window += conn->MSS;
					if (conn->cong_window >= conn->threshhold) {
						conn->cong_state = RENO_AVOIDANCE;
					}
					break;
				case RENO_AVOIDANCE:
					conn->cong_window += fmax(((double) conn->MSS) * ((double) conn->MSS) / conn->cong_window, 1.0);
					break;
				case RENO_RECOVERY:
					conn->cong_state = RENO_AVOIDANCE;
					if (conn->send_seq_num == conn->restore_seq_end) {
						conn->cong_window = conn->threshhold;
					} else {
						conn->cong_window += ((double) num_nodes) * conn->MSS;
						conn->fast_flag = 1;
					}
					break;
				}
				PRINT_DEBUG("cong_state=%u, fast=%u, window=%f, threshhold=%f, timeout=%f",
						conn->cong_state, conn->fast_flag, conn->cong_window, conn->threshhold, conn->timeout);
			} else {
				PRINT_ERROR(
						"Invalid ACK, was not sent: conn=%p, host=%u:%u, rem=%u:%u, state=%u, seg=%p, seqs=(%u, %u) (%u, %u), recv=(%u, %u) (%u, %u), ack=%u (%u), send=(%u, %u) (%u, %u)",
						conn, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->state, seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, seg->ack_num-conn->issn, seg->ack_num, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end);
			}
		}

		if (conn->main_waiting) {
			conn->main_waiting = 0;
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	} else if (conn->fin_sent && seg->ack_num == conn->fsse) {
		//remove all segs
		while (!tcp_queue_is_empty(conn->send_queue)) {
			temp_node = tcp_queue_remove_front(conn->send_queue);
			temp_seg = (struct tcp_seg *) temp_node->data;
			tcp_seg_free(temp_seg);
			free(temp_node);
		}

		conn->send_seq_num = seg->ack_num;
		conn->send_seq_end = conn->send_seq_num;

		if (conn->send_win_seq < seg->seq_num || (conn->send_win_seq == seg->seq_num && conn->send_win_ack <= seg->ack_num)) {
			if (conn->wsopt_enabled) {
				conn->send_max_win = ((uint32_t) seg->win_size) << conn->ws_send;
			} else {
				conn->send_max_win = (uint32_t) seg->win_size;
			}
			conn->send_win = conn->send_max_win;

			conn->send_win_seq = seg->seq_num;
			conn->send_win_ack = seg->ack_num;
		}

		PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
				conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
	} else {
		PRINT_ERROR(
				"Invalid ACK, out of sent window: conn=%p, host=%u:%u, rem=%u:%u, state=%u, seg=%p, seqs=(%u, %u) (%u, %u), recv=(%u, %u) (%u, %u), ack=%u (%u), send=(%u, %u) (%u, %u)",
				conn, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->state, seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, seg->ack_num-conn->issn, seg->ack_num, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end);
		conn->stats.bad_acks++;
		__sync_add_and_fetch(&md->total_conn_stats.bad_acks, 1);
	}

	if (conn->main_waiting && 0) {
		conn->main_waiting = 0;
		PRINT_DEBUG("posting to main_wait_sem");
		sem_post(&conn->main_wait_sem);
	}
}

int process_flags(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg, uint16_t *send_flags) {
	switch (conn->state) {
	case TS_ESTABLISHED:
		//can get ACKs, send/resend data, receive, send ACKs
		if (seg->flags & (FLAG_SYN)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len + 1;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			//if FIN, send ACK, CLOSE_WAIT
			PRINT_DEBUG("ESTABLISHED: FIN, send ACK, CLOSE_WAIT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TS_CLOSE_WAIT;
			conn->status &= ~TCP_STATUS_RD;
			tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_SHUTDOWN, FCF_FALSE, TCP_STATUS_RD);

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
	case TS_FIN_WAIT_1:
		//merge with established, can still get ACKs, receive, send ACKs, & resend data
		if (seg->flags & (FLAG_SYN)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len + 1;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			if ((seg->flags & FLAG_ACK) && tcp_conn_is_finished(conn)) {
				if (conn->fin_sent) {
					//if FIN ACK, send ACK, TIME_WAIT
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send ACK, TIME_WAIT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TS_TIME_WAIT;

					timer_once_start(conn->to_gbn_data->tid, 2 * TCP_MSL_TO_DEFAULT);
					conn->to_gbn_flag = 0;
				} else {
					//if FIN ACK, send FIN ACK, CLOSING (w FIN_SENT)
					PRINT_DEBUG("FIN_WAIT_1: FIN ACK, send FIN ACK, CLOSING/FIN_SENT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
					conn->state = TS_CLOSING;

					*send_flags |= FLAG_FIN;
				}
			} else {
				//if FIN, send ACK, CLOSING
				PRINT_DEBUG("FIN_WAIT_1: FIN, send ACK, CLOSING: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TS_CLOSING;
			}

			conn->status &= ~TCP_STATUS_RD;
			tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_SHUTDOWN, FCF_FALSE, TCP_STATUS_RD);

			*send_flags |= FLAG_ACK;
			return 1;
		} else if ((seg->flags & FLAG_ACK) && tcp_conn_is_finished(conn)) {
			if (conn->fin_sent) {
				//if ACK, send -, FIN_WAIT_2
				PRINT_DEBUG("FIN_WAIT_1: ACK, send -, FIN_WAIT_2: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TS_FIN_WAIT_2;

				if (seg->data_len) {
					conn->recv_seq_num += seg->data_len;
					conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
					*send_flags |= FLAG_ACK;
					return 1;
				} else {
					return 0;
				}
			} else {
				//if ACK, send -, FIN_WAIT_1 w/fin sent
				PRINT_DEBUG("FIN_WAIT_1: ACK, send FIN, FIN_WAIT_1/FIN_SENT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);

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
	case TS_FIN_WAIT_2:
		//merge with established, can still receive, send ACKs
		if (seg->flags & (FLAG_SYN)) {
			//drop
			return -1;
		} else if (seg->flags & FLAG_FIN) {
			if (seg->data_len) {
				conn->recv_seq_num += seg->data_len + 1;
			} else {
				conn->recv_seq_num++;
			}
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			//if FIN, send ACK, TIME_WAIT
			PRINT_DEBUG("FIN_WAIT_2: FIN, send ACK, TIME_WAIT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
			conn->state = TS_TIME_WAIT;
			conn->status &= ~TCP_STATUS_RD;
			tcp_conn_send_fcf(module, conn, CTRL_ALERT, TCP_ALERT_SHUTDOWN, FCF_FALSE, TCP_STATUS_RD);

			timer_once_start(conn->to_gbn_data->tid, 2 * TCP_MSL_TO_DEFAULT);
			conn->to_gbn_flag = 0;
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
	case TS_CLOSING:
		//self, can still get ACKs & resend
		if (seg->flags & (FLAG_SYN)) {
			//drop
			return -1;
		} else if ((seg->flags & FLAG_ACK) && tcp_conn_is_finished(conn)) {
			if (conn->fin_sent) {
				//if ACK, send -, TIME_WAIT
				PRINT_DEBUG("CLOSING: ACK, send -, TIME_WAIT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TS_TIME_WAIT;

				timer_once_start(conn->to_gbn_data->tid, 2 * TCP_MSL_TO_DEFAULT);
				conn->to_gbn_flag = 0;
				return 0;
			} else {
				PRINT_DEBUG("CLOSING: ACK, send FIN, CLOSING/FIN_SENT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
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
	case TS_TIME_WAIT:
		//TIMEOUT
		if (seg->flags & (FLAG_SYN)) {
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
	case TS_CLOSE_WAIT:
		//can still send & get ACKs
		if (seg->flags & (FLAG_SYN)) {
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
	case TS_LAST_ACK:
		//can still get ACKs & resend data
		if ((seg->flags & FLAG_ACK) && tcp_conn_is_finished(conn)) {
			if (conn->fin_sent) {
				//if ACK, send -, CLOSED
				PRINT_DEBUG("LAST_ACK: ACK, send -, CLOSED: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
				conn->state = TS_CLOSED;

				if (seg->data_len) {
					*send_flags |= FLAG_ACK;
					return 1;
				} else {
					return 0;
				}
			} else {
				//if ACK, send FIN, LAST_ACK
				PRINT_DEBUG("LAST_ACK: ACK, send FIN, LAST_ACK/FIN_SENT: state=%d, conn=%p, seg=%p", conn->state, conn, seg);
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

int tcp_process_options(struct tcp_conn *conn, struct tcp_seg *seg) {
	uint8_t *pt = seg->options;
	uint8_t i = 0;
	uint8_t kind;
	uint8_t len;

	while (i < seg->opt_len) {
		kind = pt[i++];
		switch (kind) {
		case TCP_OPT_EOL:
			PRINT_DEBUG("EOL: (%u/%u)", i-1, seg->opt_len);
			return 1;
		case TCP_OPT_NOP:
			PRINT_DEBUG("NOP: (%u/%u)", i-1, seg->opt_len);
			continue;
		case TCP_OPT_MSS:
			len = pt[i++];
			if (len == TCP_OPT_MSS_BYTES) {
				uint16_t mss = ntohs(*(uint16_t *) (pt + i));
				i += sizeof(uint16_t);

				PRINT_DEBUG("MSS: (%u/%u), mss=%u", i-TCP_OPT_MSS_BYTES, seg->opt_len, mss);

				if (conn->state == TS_SYN_RECV || conn->state == TS_SYN_SENT) {
					if (mss < conn->MSS) {
						conn->MSS = mss;
					}
				}
			} else {
				PRINT_ERROR("MSS: (%u/%u), len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_OPT_WS:
			len = pt[i++];
			if (len == TCP_OPT_WS_BYTES) {
				uint8_t ws = pt[i++];

				PRINT_DEBUG("WS: (%u/%u), ws=%u", i-TCP_OPT_WS_BYTES, seg->opt_len, ws);

				if (conn->state == TS_SYN_RECV || conn->state == TS_SYN_SENT) {
					if (conn->wsopt_attempt) {
						if (ws) {
							PRINT_DEBUG("WS: WS enabled");
							conn->wsopt_enabled = 1;
							if (ws < TCP_OPT_WS_MAX) {
								conn->ws_send = ws;
							} else {
								conn->ws_send = TCP_OPT_WS_MAX;
							}
						}
					}
				}
			} else {
				PRINT_ERROR("WS: (%u/%u), len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_OPT_SACK_PERM:
			len = pt[i++];
			if (len == TCP_OPT_SACK_PERM_BYTES) {
				PRINT_DEBUG("SACK Perm: (%u/%u)", i-TCP_OPT_SACK_PERM_BYTES, seg->opt_len);

				if (conn->state == TS_SYN_RECV || conn->state == TS_SYN_SENT) {
					if (conn->sack_attempt) {
						PRINT_DEBUG("SACK Perm: SACK enabled");
						conn->sack_enabled = 1;
					}
				}
			} else {
				PRINT_ERROR("SACK Perm: (%u/%u), len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_OPT_SACK:
			len = pt[i++];
			if (TCP_OPT_SACK_MIN_BYTES <= len && len <= TCP_OPT_SACK_MAX_BYTES) {
				//TODO
				PRINT_DEBUG("SACK: (%u/%u), len=%u", i-TCP_OPT_SACK_MIN_BYTES, seg->opt_len, len);
			} else {
				PRINT_ERROR("SACK: (%u/%u), len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		case TCP_OPT_TS:
			len = pt[i++];
			if (len == TCP_OPT_TS_BYTES) {
				uint32_t ts_val = ntohl(*(uint32_t *) (pt + i));
				i += sizeof(uint32_t);

				uint32_t ts_secr = ntohl(*(uint32_t *) (pt + i));
				i += sizeof(uint32_t);

				PRINT_DEBUG("TS: (%u/%u), len=%u, ts_val=%u, ts_secr=%u", i-TCP_OPT_TS_BYTES, seg->opt_len, len, ts_val, ts_secr);

				if (conn->state == TS_SYN_RECV || conn->state == TS_SYN_SENT) {
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
				PRINT_ERROR("TS: (%u/%u), len=%u PROB", i-2, seg->opt_len, len);
			}
			break;
		default:
			break;
		}
	}

	return 1;
}

int process_seg(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg, uint16_t *send_flags) {
	int ret = process_flags(module, conn, seg, send_flags);
	if (ret == -1) {
		PRINT_ERROR("problem, dropping: conn=%p, seg=%p, send_flags=%p", conn, seg, send_flags);
		//send RST etc
		return 0;
	} else if (ret == 0) {
		//don't send anything, drop data
		if (seg->opt_len) {
			tcp_process_options(conn, seg); //TODO check correct place?
		}

		return 1;
	} else {
		//send data
	}

	//conn->recv_seq_num += (uint32_t) seg->data_len;
	//conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

	PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
			conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

	if (seg->data_len) {
		//send data to daemon
		if (tcp_fdf_to_daemon(module, seg->data, seg->data_len, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port)) {
			//fine
			/*#*/PRINT_DEBUG("");
			seg->data_len = 0;
		} else {
			//TODO big error
			PRINT_WARN("todo error");
			return 0;
		}
	}

	return 1;
}

uint16_t handle_data(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_node *node;
	int ret;
	//uint16_t flags = 0;
	uint16_t send_flags = 0;

	PRINT_DEBUG( "incoming: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
			seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);

	//data handling
	if (seg->seq_num == conn->recv_seq_num) { //add check for overlapping?
		//in order seq num
		conn->stats.in_order_segs++;
		__sync_add_and_fetch(&md->total_conn_stats.in_order_segs, 1);

		if (conn->temp_count++ == 60 && conn->temp_tries < 5 && 0) {
			conn->temp_tries++;
			conn->temp_count = 0;

			PRINT_INFO( "dropping: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
					seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);

			tcp_seg_free(seg);
			return send_flags;
		}

		uint32_t data_len = seg->data_len;
		if (process_seg(module, conn, seg, &send_flags)) {
			PRINT_DEBUG("before: recv win=(%u, %u)", conn->recv_win, conn->recv_max_win);
			uint32_decrease(&conn->recv_win, data_len);
			PRINT_DEBUG("after: recv win=(%u, %u)", conn->recv_win, conn->recv_max_win);
		} else {
			PRINT_WARN("todo error");
			//TODO error
		}
		tcp_seg_free(seg);

		//remove /transfer
		while (!tcp_queue_is_empty(conn->recv_queue)) {
			node = conn->recv_queue->front;
			seg = (struct tcp_seg *) node->data;

			PRINT_DEBUG( "next stored: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
					seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);

			if (conn->recv_queue->front->seq_num < conn->recv_seq_num) {
				if (conn->recv_seq_num <= conn->recv_seq_end) {
					node = tcp_queue_remove_front(conn->recv_queue);
					seg = (struct tcp_seg *) node->data;
					uint32_increase(&conn->recv_win, seg->data_len, conn->recv_max_win);
					tcp_seg_free(seg);
					free(node);
				} else {
					if (conn->recv_queue->front->seq_num < conn->recv_seq_end) { //wrap around
						break;
					} else {
						node = tcp_queue_remove_front(conn->recv_queue);
						seg = (struct tcp_seg *) node->data;
						uint32_increase(&conn->recv_win, seg->data_len, conn->recv_max_win);
						tcp_seg_free(seg);
						free(node);
					}
				}
			} else if (conn->recv_queue->front->seq_num == conn->recv_seq_num) {
				node = tcp_queue_remove_front(conn->recv_queue);
				seg = (struct tcp_seg *) node->data;

				if (process_seg(module, conn, seg, &send_flags)) {
					PRINT_DEBUG("Connected to seqs=(%u, %u) (%u, %u), len=%d",
							seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->seq_end-seg->seq_num);
					send_flags |= FLAG_ACK_NOW;
				} else {
					PRINT_WARN("todo error");
					//TODO error
				}

				tcp_seg_free(seg);
				free(node);
			} else {
				if (conn->recv_seq_num <= conn->recv_seq_end) {
					if (conn->recv_queue->front->seq_num < conn->recv_seq_end) {
						break;
					} else {
						node = tcp_queue_remove_front(conn->recv_queue);
						seg = (struct tcp_seg *) node->data;
						uint32_increase(&conn->recv_win, seg->data_len, conn->recv_max_win);
						tcp_seg_free(seg);
						free(node);
					}
				} else {
					break;
				}
			}
		}

		if (conn->main_waiting) {
			conn->main_waiting = 0;
			PRINT_DEBUG("posting to main_wait_sem");
			sem_post(&conn->main_wait_sem);
		}
	} else {
		if (seg->data_len) {
			send_flags |= FLAG_ACK | FLAG_ACK_NOW | FLAG_ACK_SAME;
		} else if (seg->flags & FLAG_FIN) {
			send_flags |= FLAG_ACK;
		}

		//re-ordered segment
		if (conn->recv_win) {
			if (tcp_in_window(seg->seq_num, seg->seq_end, conn->recv_seq_num, conn->recv_seq_end)) {
				conn->stats.out_order_segs++;
				__sync_add_and_fetch(&md->total_conn_stats.out_order_segs, 1);

				node = tcp_node_create((uint8_t *) seg, seg->data_len, seg->seq_num, seg->seq_end);
				ret = tcp_queue_insert(conn->recv_queue, node, conn->recv_seq_num, conn->recv_seq_end);
				if (ret) {
					PRINT_DEBUG("Stored out-of-order seg");
					PRINT_DEBUG("before: recv win=(%u, %u)", conn->recv_win, conn->recv_max_win);
					uint32_decrease(&conn->recv_win, seg->data_len);
					PRINT_DEBUG("after: recv win=(%u, %u)", conn->recv_win, conn->recv_max_win);
				} else {
					PRINT_DEBUG("Dropping duplicate rem=(%u, %u) (%u, %u), got=(%u, %u) (%u, %u)",
							conn->recv_seq_num, conn->recv_seq_end, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn);
					tcp_seg_free(seg);
					free(node);
				}
			} else {
				PRINT_DEBUG("Dropping out of window rem=(%u, %u), got=(%u, %u)", conn->recv_seq_num, conn->recv_seq_end, seg->seq_num, seg->seq_end);
				if (0 /*if seg is within issn*/) {
					conn->stats.dup_segs++;
					__sync_add_and_fetch(&md->total_conn_stats.dup_segs, 1);
				} else {
					conn->stats.drop_segs++;
					__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
				}
				tcp_seg_free(seg);
			}
		} else {
			PRINT_DEBUG("Dropping window full host_window=%u", conn->recv_win);
			conn->stats.drop_segs++;
			__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
			tcp_seg_free(seg);
		}
	}

	return send_flags;
}

void handle_reply(struct fins_module *module, struct tcp_conn *conn, uint16_t flags) {
	PRINT_DEBUG("Entered: conn=%p, flags=0x%x", conn, flags);

	struct tcp_seg *seg;

	if (flags & FLAG_RST) { //TODO fix?
		PRINT_WARN("todo fix");
		/*
		 PRINT_DEBUG("Sending RST");
		 if (seg->flags & FLAG_ACK) {
		 seg = seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, seg->ack_num, seg->ack_num + 1);
		 seg->flags |= (FLAG_RST & (FLAG_CONTROL | FLAG_ECN));
		 } else {
		 seg = seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, 0, 1); //0, data_len
		 seg->flags |= ((FLAG_RST | FLAG_ACK) & (FLAG_CONTROL | FLAG_ECN));
		 seg->ack_num = seg->seq_end; //seq+data_len
		 }
		 seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
		 seg_send(module, seg);
		 seg_free(seg);
		 */

		seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
		tcp_seg_update(seg, conn, flags);
		tcp_seg_send(module, seg);
		tcp_seg_free(seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	} else if (flags & FLAG_FIN) { //TODO fix?
		PRINT_WARN("todo fix");
		if (conn->fin_sent) {
			//TODO prob
			PRINT_WARN("todo error");
			PRINT_DEBUG("removing fin");
			flags &= ~FLAG_FIN;
		} else {
			conn->fin_sent = 1;
			conn->fin_sep = 1;
			conn->fsse = conn->send_seq_end + 1;
			PRINT_DEBUG("setting: fin_sent=%u, fin_sep=%u, fsse=%u (%u)", conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);
		}

		timer_stop(conn->to_delayed_data->tid);
		conn->delayed_flag = 0;
		conn->to_delayed_flag = 0;

		seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
		tcp_seg_update(seg, conn, flags);
		tcp_seg_send(module, seg);
		tcp_seg_free(seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	} else if (flags & FLAG_ACK) {
		PRINT_DEBUG("delayed=%u, now=%u, same=%u", conn->delayed_flag, flags & FLAG_ACK_NOW, flags & FLAG_ACK_SAME);
		if ((flags & FLAG_ACK_NOW) || conn->delayed_flag) {
			PRINT_DEBUG("ACKing now");
			timer_stop(conn->to_delayed_data->tid);
			conn->to_delayed_flag = 0;

			if (flags & FLAG_ACK_SAME) {
				if (conn->delayed_flag) {
					conn->ack_seg->seq_num = conn->send_seq_end;
					conn->ack_seg->seq_end = conn->send_seq_end;
					tcp_seg_update(conn->ack_seg, conn, flags);
				}
				conn->delayed_flag = 0;
			} else {
				conn->ack_seg->seq_num = conn->send_seq_end;
				conn->ack_seg->seq_end = conn->send_seq_end;
				tcp_seg_update(conn->ack_seg, conn, flags);
			}
			tcp_seg_send(module, conn->ack_seg);

			if (conn->recv_win == 0) {
				conn->flow_stopped = 1;
			}
		} else {
			conn->delayed_flag = 1;
			conn->delayed_ack_flags = flags; //TODO only FLAG_ACK?
			timer_once_start(conn->to_delayed_data->tid, TCP_DELAYED_TO_DEFAULT);
			conn->to_delayed_flag = 0;
		}
	} else {
		//error? shouldn't really reach here unless haven't implemented other flags
		PRINT_WARN("shouldn't reach here: flags=0x%x", flags);
		seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
		tcp_seg_update(seg, conn, flags);
		tcp_seg_send(module, seg);
		tcp_seg_free(seg);

		if (conn->recv_win == 0) {
			conn->flow_stopped = 1;
		}
	}
}

void tcp_recv_closed(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: dropping: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	//TODO if RST, -, -
	//TODO if ACK, <SEQ=SEG.ACK><CTL=RST>
	//TODO else, <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

	if (seg->flags & FLAG_RST) {
	} else if (seg->flags & FLAG_SYN) {
	} else if (seg->flags & FLAG_FIN) {
	} else {
	}

	conn->stats.drop_segs++;
	__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
	tcp_seg_free(seg);
}

void tcp_recv_listen(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	//TODO if RST, -, -
	//TODO if ACK, <SEQ=SEG.ACK><CTL=RST>
	//TODO if SYN, check sec,

	struct tcp_conn *child_conn;
	struct tcp_seg *temp_seg;

	if (seg->flags & FLAG_RST) {
	} else if (seg->flags & FLAG_SYN) {
		if (conn->listening) {
			if (list_has_space(conn->backlog_list)) {
				PRINT_DEBUG("conn_list wait***************");
				secure_sem_wait(&md->conn_list_sem);
				child_conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &seg->dst_ip, &seg->dst_port, &seg->src_ip, &seg->src_port);
				if (child_conn == NULL) { //shouldn't ever occur otherwise push to other conn already
					if (list_has_space(md->conn_list)) {
						child_conn = tcp_conn_create(module, seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port);
						list_append(md->conn_list, child_conn);

						child_conn->threads++;
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_wait: conn=%p", child_conn);
						secure_sem_wait(&child_conn->sem);
						if (child_conn->running_flag) { //LISTENING state
							//if SYN, send SYN ACK, SYN_RECV
							PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
							child_conn->state = TS_SYN_RECV;
							child_conn->active_open = 0;
							child_conn->parent_conn = conn;

							child_conn->poll_events = conn->poll_events; //TODO specify more

							//if (flags & (1)) {
							//	//TODO do specific flags/settings
							//}

							child_conn->issn = tcp_rand();
							child_conn->send_seq_num = child_conn->issn;
							child_conn->send_seq_end = child_conn->send_seq_num;
							child_conn->send_max_win = (uint32_t) seg->win_size;
							child_conn->send_win = child_conn->send_max_win;

							child_conn->irsn = seg->seq_num;
							child_conn->recv_seq_num = seg->seq_num + 1;
							child_conn->recv_seq_end = child_conn->recv_seq_num + child_conn->recv_max_win;

							PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
									child_conn->send_seq_num-child_conn->issn, child_conn->send_seq_end-child_conn->issn, child_conn->send_seq_num, child_conn->send_seq_end, child_conn->recv_win, child_conn->recv_max_win, child_conn->recv_seq_num-child_conn->irsn, child_conn->recv_seq_end-child_conn->irsn, child_conn->recv_seq_num, child_conn->recv_seq_end, child_conn->send_win, child_conn->send_max_win);

							//TODO process options, decide: MSS, max window size!!
							//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

							if (seg->opt_len) {
								tcp_process_options(child_conn, seg);
							}

							//conn_change_options(conn, tcp->options, SYN);

							//send SYN ACK
							temp_seg = tcp_seg_create(child_conn->host_ip, child_conn->host_port, child_conn->rem_ip, child_conn->rem_port,
									child_conn->send_seq_end, child_conn->send_seq_end);
							tcp_seg_update(temp_seg, child_conn, FLAG_SYN | FLAG_ACK);
							tcp_seg_send(module, temp_seg);
							tcp_seg_free(temp_seg);

							//timer_once_start(conn_child->to_gbn_data->tid, TCP_MSL_TO_DEFAULT);
							child_conn->timeout = TCP_GBN_TO_MIN;
							timer_once_start(child_conn->to_gbn_data->tid, TCP_GBN_TO_MIN); //TODO figure out to's
							child_conn->to_gbn_flag = 0;

							list_append(conn->backlog_list, child_conn);
						} else {
							PRINT_WARN("todo error");
							//TODO error
						}

						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						child_conn->threads--;
						PRINT_DEBUG("leaving thread: conn=%p, threads=%d", child_conn, child_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_post: conn=%p", child_conn);
						sem_post(&child_conn->sem);
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
			} else {
				//TODO throw RST? or just drop?
			}
		} else {
			PRINT_WARN("todo error");
			//TODO error???
		}
	} else if (seg->flags & FLAG_FIN) {
	} else {
	}

	//conn->stats.drop_segs++;
	//__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
	tcp_seg_free(seg);
}

void tcp_recv_syn_sent(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_seg *temp_seg;

	//TODO ACK, If SEG.ACK =< ISS, or SEG.ACK > SND.NXT, send a reset <SEQ=SEG.ACK><CTL=RST>
	//TODO ACK, If SND.UNA =< SEG.ACK =< SND.NXT

	if (seg->flags & FLAG_RST) {
		//acceptable if the ACK field acknowledges the SYN
		PRINT_WARN("todo");
	} else if (seg->flags & FLAG_FIN) {
		PRINT_WARN("todo");
	} else if (seg->flags & FLAG_SYN) {
		if (seg->flags & FLAG_ACK) {
			if (seg->ack_num == conn->send_seq_num + 1) {
				if (seg->opt_len) {
					tcp_process_options(conn, seg); //TODO check if right place
				}

				//if SYN ACK, send ACK, ESTABLISHED
				PRINT_DEBUG("SYN ACK, send ACK, ESTABLISHED: state=%d", conn->state);
				conn->state = TS_ESTABLISHED;

				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				conn->send_max_win = (uint32_t) seg->win_size;
				conn->send_win = conn->send_max_win;

				conn->irsn = seg->seq_num;
				conn->recv_seq_num = seg->seq_num + 1;
				conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//flags
				conn->first_flag = 1;
				conn->duplicate = 0;
				conn->fast_flag = 0;
				conn->gbn_flag = 0;

				//RTT
				timer_stop(conn->to_gbn_data->tid);
				conn->timeout = TCP_GBN_TO_DEFAULT;

				//Cong
				conn->cong_state = RENO_SLOWSTART;
				conn->cong_window = (double) conn->MSS;
				conn->threshhold = conn->send_max_win / 2.0;

				//TODO piggy back data? release to established with delayed TO on
				//send ACK
				temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
				tcp_seg_update(temp_seg, conn, FLAG_ACK);
				tcp_seg_send(module, temp_seg);
				tcp_seg_free(temp_seg);

				//send ACK to handler, prob connect
				if (conn->ff) {
					conn->signaled = 1;
					if (conn->active_open) {
						module_reply_fcf(module, conn->ff, FCF_TRUE, 0); //connect
					} else {
						//shouldn't occur
						tcp_conn_reply_fcf(module, conn, conn->ff, FCF_TRUE, 0); //accept needs rem ip/port
					}
					conn->ff = NULL;
				} else {
					if (conn->active_open) {
						PRINT_WARN("todo error");
					} else {
						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads++;
						PRINT_DEBUG("entering thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_wait: conn=%p", conn->parent_conn);
						secure_sem_wait(&conn->parent_conn->sem);
						if (conn->parent_conn->running_flag) {
							if (conn->parent_conn->state == TS_LISTEN) {
								if (conn->parent_conn->ff) {
									list_remove(conn->parent_conn->backlog_list, conn);

									conn->signaled = 1;
									tcp_conn_reply_fcf(module, conn, conn->parent_conn->ff, FCF_TRUE, 0);
									conn->parent_conn->ff = NULL;
								} else {
									//do nothing
									PRINT_DEBUG("No ff, just wait");
								}
							} else {
								PRINT_WARN("todo error");
							}
						}

						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads--;
						PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_post: conn=%p", conn->parent_conn);
						sem_post(&conn->parent_conn->sem);
					}
				}
			} else {
				PRINT_DEBUG("Invalid SYN ACK: was not sent: ack=%u, host_seq_num=%u", seg->ack_num, conn->send_seq_num);

				//SYN ACK for dup SYN, send RST, resend SYN

				//TODO finish, search send_queue & only RST if old SYN

				//TODO remove dup SYN packet from send_queue

				//send RST
				PRINT_DEBUG("Sending RST");
				temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, seg->ack_num, seg->ack_num + 1);
				temp_seg->flags |= (FLAG_RST & (FLAG_CONTROL | FLAG_ECN));
				temp_seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
				tcp_seg_send(module, temp_seg);
				tcp_seg_free(temp_seg);

				//TODO WAIT then send SYN
			}
		} else {
			//TODO process options, decide: MSS, max window size!!
			if (seg->opt_len) {
				tcp_process_options(conn, seg);
			}

			//if SYN, send SYN ACK, SYN_RECV (simultaneous)
			PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);
			conn->state = TS_SYN_RECV;

			conn->send_max_win = (uint32_t) seg->win_size;
			conn->send_win = conn->send_max_win;

			conn->irsn = seg->seq_num;
			conn->recv_seq_num = seg->seq_num + 1;
			conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;

			PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

			temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
			tcp_seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
			tcp_seg_send(module, temp_seg);
			tcp_seg_free(temp_seg);

			//timer_once_start(conn->to_gbn_data->tid, TCP_MSL_TO_DEFAULT); //TODO figure out to's
			conn->timeout = TCP_GBN_TO_MIN;
			timer_once_start(conn->to_gbn_data->tid, TCP_GBN_TO_MIN); //TODO figure out to's
			conn->to_gbn_flag = 0;
		}
	} else {
		PRINT_DEBUG("Invalid Seg: SYN_SENT & not SYN.");

		PRINT_DEBUG("Sending RST");
		if (seg->flags & FLAG_ACK) {
			temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, seg->ack_num, seg->ack_num + 1);
			temp_seg->flags |= (FLAG_RST & (FLAG_CONTROL | FLAG_ECN));
		} else {
			temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, 0, seg->data_len);
			temp_seg->flags |= ((FLAG_RST | FLAG_ACK) & (FLAG_CONTROL | FLAG_ECN));
			temp_seg->ack_num = seg->seq_end;
		}
		temp_seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
		tcp_seg_send(module, temp_seg);
		tcp_seg_free(temp_seg);
	}

	tcp_seg_free(seg);
}

void tcp_recv_syn_recv(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_seg *temp_seg;
	uint16_t flags;
	//uint8_t reply;

	if (seg->flags & FLAG_RST) {
		//if RST, send -, LISTEN

		PRINT_WARN("todo");
	} else if (seg->flags & FLAG_FIN) {
		//drop
		PRINT_WARN("todo");

	} else if (seg->flags & FLAG_SYN) {
		if (seg->flags & FLAG_ACK) {
			if (seg->ack_num == conn->send_seq_num + 1) {
				//TODO process options
				if (seg->opt_len) {
					tcp_process_options(conn, seg);
				}

				//if SYN ACK, send -, ESTABLISHED
				PRINT_DEBUG("SYN ACK, send -, ESTABLISHED: state=%d", conn->state);
				conn->state = TS_ESTABLISHED;

				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				conn->recv_seq_num = seg->seq_num;
				conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
				conn->send_max_win = (uint32_t) seg->win_size;
				conn->send_win = conn->send_max_win;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//flags
				conn->first_flag = 1;
				conn->fast_flag = 0;
				conn->gbn_flag = 0;

				//RTT
				timer_stop(conn->to_gbn_data->tid);
				conn->timeout = TCP_GBN_TO_DEFAULT;
				conn->stats.timeout_total += conn->timeout;
				conn->stats.timeout_count++;

				//Cong
				conn->cong_state = RENO_SLOWSTART;

				conn->cong_window = (double) conn->MSS;
				conn->stats.cong_window_total += conn->cong_window;
				conn->stats.cong_window_count++;

				conn->threshhold = conn->send_max_win / 2.0;
				conn->stats.threshhold_total += conn->threshhold;
				conn->stats.threshhold_count++;

				if (!(seg->flags & FLAG_ACK)) {
					flags = handle_data(module, conn, seg);

					if (flags) {
						handle_reply(module, conn, flags);
					}
				}

				//send ACK to handler, prob accept
				if (conn->ff) {
					conn->signaled = 1;
					if (conn->active_open) {
						module_reply_fcf(module, conn->ff, FCF_TRUE, 0); //connect
					} else {
						//shouldn't occur
						tcp_conn_reply_fcf(module, conn, conn->ff, FCF_TRUE, 0); //accept needs rem ip/port
					}
					conn->ff = NULL;
				} else {
					if (conn->active_open) {
						PRINT_WARN("todo error");
					} else {
						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads++;
						PRINT_DEBUG("entering thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_wait: conn=%p", conn->parent_conn);
						secure_sem_wait(&conn->parent_conn->sem);
						if (conn->parent_conn->running_flag) {
							if (conn->parent_conn->state == TS_LISTEN) {
								if (conn->parent_conn->ff) {
									list_remove(conn->parent_conn->backlog_list, conn);

									conn->signaled = 1;
									tcp_conn_reply_fcf(module, conn, conn->parent_conn->ff, FCF_TRUE, 0);
									conn->parent_conn->ff = NULL;
								} else {
									//do nothing
									PRINT_DEBUG("No ff, just wait");
								}
							} else {
								PRINT_WARN("todo error");
							}
						}

						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads--;
						PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_post: conn=%p", conn->parent_conn);
						sem_post(&conn->parent_conn->sem);
					}
				}
			} else {
				PRINT_DEBUG("Invalid ACK: was not sent.");
				//TODO send RST?
				PRINT_WARN("todo error");
			}
		} else {
			if (seg->opt_len) {
				tcp_process_options(conn, seg);
			}

			//if SYN, send SYN ACK, SYN_RECV
			PRINT_DEBUG("SYN, send SYN ACK, SYN_RECV: state=%d", conn->state);

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

			//conn_change_options(conn, tcp->options, SYN); //?

			//send SYN ACK
			temp_seg = tcp_seg_create(conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->send_seq_end, conn->send_seq_end);
			tcp_seg_update(temp_seg, conn, FLAG_SYN | FLAG_ACK);
			tcp_seg_send(module, temp_seg);
			tcp_seg_free(temp_seg);

			timer_once_start(conn->to_gbn_data->tid, TCP_MSL_TO_DEFAULT);
			conn->to_gbn_flag = 0;
		}
	} else {
		if (seg->flags & FLAG_ACK) {
			if (seg->ack_num == conn->send_seq_num + 1) {
				//TODO process options
				if (seg->opt_len) {
					tcp_process_options(conn, seg);
				}

				//if ACK, send -, ESTABLISHED
				PRINT_DEBUG("ACK, send -, ESTABLISHED: state=%d", conn->state);
				conn->state = TS_ESTABLISHED;

				conn->send_seq_num = seg->ack_num;
				conn->send_seq_end = conn->send_seq_num;
				conn->recv_seq_num = seg->seq_num;
				conn->recv_seq_end = conn->recv_seq_num + conn->recv_max_win;
				conn->send_max_win = (uint32_t) seg->win_size;
				conn->send_win = conn->send_max_win;

				PRINT_DEBUG( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
						conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);

				//flags
				conn->first_flag = 1;
				conn->fast_flag = 0;
				conn->gbn_flag = 0;

				//RTT
				timer_stop(conn->to_gbn_data->tid);
				conn->timeout = TCP_GBN_TO_DEFAULT;

				//Cong
				conn->cong_state = RENO_SLOWSTART;
				conn->cong_window = (double) conn->MSS;
				conn->threshhold = conn->send_max_win / 2.0;

				if (!(seg->flags & FLAG_ACK)) {
					flags = handle_data(module, conn, seg);

					if (flags) {
						handle_reply(module, conn, flags);
					}
				}

				//send ACK to handler, prob accept
				if (conn->ff) {
					conn->signaled = 1;
					if (conn->active_open) {
						module_reply_fcf(module, conn->ff, FCF_TRUE, 0); //connect
					} else {
						//shouldn't occur
						tcp_conn_reply_fcf(module, conn, conn->ff, FCF_TRUE, 0); //accept needs rem ip/port
					}
					conn->ff = NULL;
				} else {
					if (conn->active_open) {
						PRINT_WARN("todo error");
					} else {
						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads++;
						PRINT_DEBUG("entering thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_wait: conn=%p", conn->parent_conn);
						secure_sem_wait(&conn->parent_conn->sem);
						if (conn->parent_conn->running_flag) {
							if (conn->parent_conn->state == TS_LISTEN) {
								if (conn->parent_conn->ff) {
									list_remove(conn->parent_conn->backlog_list, conn);

									conn->signaled = 1;
									tcp_conn_reply_fcf(module, conn, conn->parent_conn->ff, FCF_TRUE, 0);
									conn->parent_conn->ff = NULL;
								} else {
									//do nothing
									PRINT_DEBUG("No ff, just wait");
								}
							} else {
								PRINT_WARN("todo error");
							}
						}

						PRINT_DEBUG("conn_list wait***************");
						secure_sem_wait(&md->conn_list_sem);
						conn->parent_conn->threads--;
						PRINT_DEBUG("leaving thread: conn=%p, threads=%d", conn->parent_conn, conn->parent_conn->threads);
						PRINT_DEBUG("conn_list post***************");
						sem_post(&md->conn_list_sem);

						PRINT_DEBUG("sem_post: conn=%p", conn->parent_conn);
						sem_post(&conn->parent_conn->sem);
					}
				}
			} else {
				PRINT_DEBUG("Invalid ACK: was not sent.");
				//TODO send RST?
				PRINT_WARN("todo error");
			}
		} else {
			PRINT_DEBUG("Invalid Seg: SYN_RECV & not ACK.");

			PRINT_DEBUG("Sending RST");
			if (seg->flags & FLAG_ACK) {
				temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, seg->ack_num, seg->ack_num + 1);
				temp_seg->flags |= (FLAG_RST & (FLAG_CONTROL | FLAG_ECN));
			} else {
				temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, 0, seg->data_len);
				temp_seg->flags |= ((FLAG_RST | FLAG_ACK) & (FLAG_CONTROL | FLAG_ECN));
				temp_seg->ack_num = seg->seq_end;
			}
			temp_seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
			tcp_seg_send(module, temp_seg);
			tcp_seg_free(temp_seg);
		}
	}

	tcp_seg_free(seg);
}

void tcp_recv_established(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	//TODO send or resend data / get ACKs, & receive data / send ACKs

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		if (seg->flags & FLAG_URG) {
			PRINT_WARN("todo");
		}

		uint16_t flags = handle_data(module, conn, seg);

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv_fin_wait_1(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO send or resend data / get ACKs, & receive data / send ACKs
	//if FIN, send ACK, CLOSING
	//if FIN ACK, send ACK, TIME_WAIT
	//if ACK, send -, FIN_WAIT_2

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		if (seg->flags & FLAG_URG) {
			//TODO implement
			PRINT_WARN("todo");
		}

		flags = handle_data(module, conn, seg);

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv_fin_wait_2(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO receive data / send ACKs
	//if FIN, send ACK, TIME_WAIT

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		flags = handle_data(module, conn, seg);

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv_closing(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO send or resend data / get ACKs
	//if ACK, send -, TIME_WAIT

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		if (seg->flags & FLAG_URG) {
			//TODO implement
			PRINT_WARN("todo");
		}

		flags = handle_data(module, conn, seg); //change to process of some sort, since no data & only flags

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv_time_wait(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: dropping: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO do nothing, send RSTs
	//if FIN, send ACK

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		if (seg->flags & FLAG_URG) {
			//TODO implement
			PRINT_WARN("todo");
		}

		flags = handle_data(module, conn, seg); //change to process of some sort, since no data & only flags

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv_close_wait(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);

	//TODO send or resend data / get ACKs

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		tcp_seg_free(seg);
	}
}

void tcp_recv_last_ack(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p, state=%d", conn, seg, conn->state);
	uint16_t flags;

	//TODO send or resend data / get ACKs
	//if ACK, send -, CLOSED

	if (seg->flags & FLAG_RST) {
		handle_RST(module, conn, seg);
	} else {
		if (seg->flags & FLAG_ACK) {
			handle_ACK(module, conn, seg);
		}

		if (seg->flags & FLAG_URG) {
			//TODO implement
			PRINT_WARN("todo");
		}

		flags = handle_data(module, conn, seg); //change to process of some sort, since no data & only flags

		if (conn->state == TS_CLOSED) {
			tcp_conn_shutdown(conn);
		}

		if (flags) {
			handle_reply(module, conn, flags);
		}
	}
}

void tcp_recv(struct fins_module *module, struct tcp_conn *conn, struct tcp_seg *seg) {
	PRINT_DEBUG("Entered: conn=%p, seg=%p", conn, seg);
	struct tcp_data *md = (struct tcp_data *) module->data;

	uint16_t calc;

	PRINT_DEBUG("sem_wait: conn=%p", conn);
	secure_sem_wait(&conn->sem);
	if (conn->running_flag) {
		conn->stats.recv_segs++;
		__sync_add_and_fetch(&md->total_conn_stats.recv_segs, 1);

		calc = tcp_seg_checksum(seg); //TODO add alt checksum
		PRINT_DEBUG("checksum=%u, calc=%u", seg->checksum, calc);
		if (seg->checksum == 0 || calc == 0) { //TODO remove override when IP prob fixed
			if (seg->checksum == 0) {
				//ignore checksum
				conn->stats.no_checksum++;
				__sync_add_and_fetch(&md->total_conn_stats.no_checksum, 1);
			}

			switch (conn->state) {
			case TS_CLOSED:
				tcp_recv_closed(module, conn, seg);
				break;
			case TS_LISTEN:
				tcp_recv_listen(module, conn, seg);
				break;
			case TS_SYN_SENT:
				tcp_recv_syn_sent(module, conn, seg);
				break;
			case TS_SYN_RECV:
				tcp_recv_syn_recv(module, conn, seg);
				break;
			case TS_ESTABLISHED:
				tcp_recv_established(module, conn, seg);
				break;
			case TS_FIN_WAIT_1:
				tcp_recv_fin_wait_1(module, conn, seg);
				break;
			case TS_FIN_WAIT_2:
				tcp_recv_fin_wait_2(module, conn, seg);
				break;
			case TS_CLOSING:
				tcp_recv_closing(module, conn, seg);
				break;
			case TS_TIME_WAIT:
				tcp_recv_time_wait(module, conn, seg);
				break;
			case TS_CLOSE_WAIT:
				tcp_recv_close_wait(module, conn, seg);
				break;
			case TS_LAST_ACK:
				tcp_recv_last_ack(module, conn, seg);
				break;
			default:
				PRINT_ERROR( "Incorrect state: conn=%p, host=%u:%u, rem=%u:%u, state=%u, seg=%p",
						conn, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->state, seg);
				PRINT_WARN("todo error");
				conn->stats.drop_segs++;
				__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
				tcp_seg_free(seg);
				break;
			}
		} else {
			PRINT_WARN( "Incorrect Checksum: conn=%p, host=%u:%u, rem=%u:%u, state=%u, seg=%p, recv checksum=%u, calc checksum=%u",
					conn, conn->host_ip, conn->host_port, conn->rem_ip, conn->rem_port, conn->state, seg, seg->checksum, calc);
			PRINT_WARN("ack=%u, send=(%u, %u), sent=%u, sep=%u, fsse=%u (%u)",
					seg->ack_num-conn->issn, conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->fin_sent, conn->fin_sep, conn->fsse-conn->issn, conn->fsse);
			PRINT_WARN( "host: seqs=(%u, %u) (%u, %u), win=(%u/%u), rem: seqs=(%u, %u) (%u, %u), win=(%u/%u)",
					conn->send_seq_num-conn->issn, conn->send_seq_end-conn->issn, conn->send_seq_num, conn->send_seq_end, conn->recv_win, conn->recv_max_win, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end, conn->send_win, conn->send_max_win);
			PRINT_WARN( "incoming: seg=%p, seqs=(%u, %u) (%u, %u), len=%d, rem: seqs=(%u, %u) (%u, %u)",
					seg, seg->seq_num-conn->irsn, seg->seq_end-conn->irsn, seg->seq_num, seg->seq_end, seg->data_len, conn->recv_seq_num-conn->irsn, conn->recv_seq_end-conn->irsn, conn->recv_seq_num, conn->recv_seq_end);
			conn->stats.bad_checksum++;
			__sync_add_and_fetch(&md->total_conn_stats.bad_checksum, 1);
			tcp_seg_free(seg);
		}
	} else {
		PRINT_DEBUG("not running, dropping: seg=%p", seg);
		conn->stats.drop_segs++;
		__sync_add_and_fetch(&md->total_conn_stats.drop_segs, 1);
		tcp_seg_free(seg);
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

void tcp_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct tcp_data *md = (struct tcp_data *) module->data;

	struct tcp_seg *seg;
	struct tcp_conn *conn;
	struct tcp_seg *temp_seg;

	seg = fdf_to_tcp(ff);
	if (seg) {
		PRINT_DEBUG("conn_list wait***************");
		secure_sem_wait(&md->conn_list_sem);
		conn = (struct tcp_conn *) list_find4(md->conn_list, tcp_conn_addr_test, &seg->dst_ip, &seg->dst_port, &seg->src_ip, &seg->src_port);
		if (conn) {
			conn->threads++;
			PRINT_DEBUG("conn_list post***************");
			sem_post(&md->conn_list_sem);

			tcp_recv(module, conn, seg);
		} else {
			if ((seg->flags & FLAG_SYN) && !(seg->flags & (FLAG_RST | FLAG_ACK | FLAG_FIN))) {
				//TODO check security, send RST if lower, etc

				//check if listening sockets
				conn = (struct tcp_conn *) list_find2(md->conn_stub_list, tcp_conn_host_test, &seg->dst_ip, &seg->dst_port);
				if (conn) {
					conn->threads++;
					PRINT_DEBUG("conn_list post***************");
					sem_post(&md->conn_list_sem);

					tcp_recv(module, conn, seg);
				} else {
					PRINT_DEBUG("conn_list post***************");
					sem_post(&md->conn_list_sem);
					PRINT_DEBUG("Found no stub. Dropping...");

					PRINT_DEBUG("Sending RST");
					//<SEQ=0><ACK=seq+len><CTL=RST> win=0
					temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, 0, seg->data_len);
					temp_seg->flags |= ((FLAG_RST | FLAG_ACK) & (FLAG_CONTROL | FLAG_ECN));
					temp_seg->ack_num = seg->seq_end;

					temp_seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
					tcp_seg_send(module, temp_seg);
					tcp_seg_free(temp_seg);

					tcp_seg_free(seg);
				}
			} else {
				PRINT_DEBUG("conn_list post***************");
				sem_post(&md->conn_list_sem);

				PRINT_DEBUG("Found no connection. Dropping...");

				if (seg->flags & FLAG_RST) {
					//drop
				} else {
					PRINT_DEBUG("Sending RST");

					//if ACK, send <SEQ=SEG.ACK><CTL=RST> win=0
					//else, <SEQ=0><ACK=seq+len><CTL=RST> win=0

					if (seg->flags & FLAG_ACK) {
						temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, seg->ack_num, seg->ack_num + 1);
						temp_seg->flags |= (FLAG_RST & (FLAG_CONTROL | FLAG_ECN));
					} else {
						temp_seg = tcp_seg_create(seg->dst_ip, seg->dst_port, seg->src_ip, seg->src_port, 0, seg->data_len);
						temp_seg->flags |= ((FLAG_RST | FLAG_ACK) & (FLAG_CONTROL | FLAG_ECN));
						temp_seg->ack_num = seg->seq_end;
					}
					temp_seg->flags |= ((MIN_TCP_HEADER_WORDS + 0) << 12) & FLAG_DATAOFFSET;
					tcp_seg_send(module, temp_seg);
					tcp_seg_free(temp_seg);
				}

				tcp_seg_free(seg);
			}
		}
	} else {
		PRINT_ERROR("Bad tcp_seg. Dropping...");
	}

	freeFinsFrame(ff);
}
