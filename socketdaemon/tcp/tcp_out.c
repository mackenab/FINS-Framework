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
	struct tcp_connection *conn = thread_data->conn;
	uint8_t *called_data = thread_data->data_raw;
	uint32_t called_len = thread_data->data_len;

	uint8_t *pt = called_data;
	int index = 0;
	int len;
	int space;
	uint8_t *buf;
	struct tcp_node *node;

	if (sem_wait(&conn->write_sem)) { //func depends on write_sem, write op can't be interrupted
		PRINT_ERROR("conn->write_sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (sem_wait(&conn->sem)) {
			PRINT_ERROR("conn->write_sem wait prob");
			exit(-1);
		}
		if (conn->state == ESTABLISHED || conn->state == CLOSE_WAIT) {
			while (index < called_len) {
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
					sem_post(&conn->sem);
				} else {
					sem_post(&conn->sem);

					if (sem_wait(&conn->write_wait_sem)) {
						PRINT_ERROR("conn->send_wait_sem prod");
						exit(-1);
					}
					sem_init(&conn->write_wait_sem, 0, 0);
					PRINT_DEBUG("left conn->send_wait_sem\n");
				}
				if (sem_wait(&conn->sem)) {
					PRINT_ERROR("conn->sem prod");
					exit(-1);
				}
			}
		} else {
			//TODO error, send/write'ing when conn sending is closed
		}
	}

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn->threads--;
	sem_post(&conn_list_sem);

	//send ACK to send handler - reusing some vars
	len = 2 * sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(uint8_t);
	buf = (uint8_t *) malloc(len * sizeof(uint8_t));
	pt = buf;

	*(uint32_t *) pt = conn->host_addr;
	pt += sizeof(uint32_t);

	*(uint16_t *) pt = conn->host_port;
	pt += sizeof(uint16_t);

	*(uint32_t *) pt = conn->rem_addr;
	pt += sizeof(uint32_t);

	*(uint16_t *) pt = conn->rem_port;
	pt += sizeof(uint16_t);

	*(uint8_t *) pt = 1;
	pt += sizeof(uint8_t);

	sem_post(&conn->write_sem);

	if (pt - buf != len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - buf, len);
		free(buf);
	}
	fins_to_jinni_TCP_cntrl(EXEC_TCP_SEND, buf, len);

	free(buf);
	free(called_data);
	free(thread_data);
	pthread_exit(NULL);
}

void tcp_out_fdf(struct finsFrame *ff) {
	//receiving straight data from the APP layer, process/package into segment
	uint32_t src_ip;
	uint32_t dst_ip;
	uint32_t src_port_buf;
	uint32_t dst_port_buf;
	uint16_t src_port;
	uint16_t dst_port;
	struct tcp_connection *conn;
	int start;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	metadata* meta = (ff->dataFrame).metaData;
	metadata_readFromElement(meta, "srcip", &src_ip); //host
	metadata_readFromElement(meta, "dstip", &dst_ip); //remote
	metadata_readFromElement(meta, "srcport", &src_port_buf);
	metadata_readFromElement(meta, "dstport", &dst_port_buf);
	/** fixing the values because of the conflict between uint16 type and
	 * the 32 bit META_INT_TYPE
	 */
	src_port = (uint16_t) src_port_buf;
	dst_port = (uint16_t) dst_port_buf;

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port); //TODO check if right
	start = (conn->threads < MAX_THREADS) ? conn->threads++ : 0;
	sem_post(&conn_list_sem);

	if (conn) {
		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			thread_data->conn = conn;
			thread_data->data_raw = ff->dataFrame.pdu;
			thread_data->data_len = ff->dataFrame.pduLength;

			//spin off thread to handle
			if (pthread_create(&thread, NULL, write_thread,
					(void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create write_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		//TODO error

		//TODO LISTEN: if SEND, SYN, SYN_SENT
	}

	freeFinsFrame(ff);
}

void *close_stub_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t send_ack = thread_data->flags;

	struct tcp_segment *temp_seg;
	struct tcp_node *temp_node;

	uint32_t len;
	uint8_t *buf;
	uint8_t *pt;

	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	if (conn_stub->running_flag) {
		conn_stub_shutdown(conn_stub);
	}

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub->threads--;
	sem_post(&conn_stub_list_sem);

	//TODO if send_ack, send ACK to close(_stub) handler
	if (send_ack) {
		//send ACK to send handler - reusing some vars
		len = 2 * sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(uint8_t);
		buf = (uint8_t *) malloc(len * sizeof(uint8_t));
		pt = buf;

		*(uint32_t *) pt = conn_stub->host_addr;
		pt += sizeof(uint32_t);

		*(uint16_t *) pt = conn_stub->host_port;
		pt += sizeof(uint16_t);

		*(uint8_t *) pt = 1;
		pt += sizeof(uint8_t);

		sem_post(&conn->write_sem);

		if (pt - buf != len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - buf, len);
		} else {
			fins_to_jinni_TCP_cntrl(EXEC_TCP_CLOSE_STUB, buf, len);
		}
		free(buf);
	}

	sem_post(&conn_stub->sem);

	free(thread_data);
	pthread_exit(NULL);
}

void tcp_exec_close_stub(uint32_t src_ip, uint16_t src_port) {
	struct tcp_connection_stub *conn_stub;
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(src_ip, src_port);
	if (conn_stub) {
		conn_stub_remove(conn_stub);
		start = (conn_stub->threads < MAX_THREADS) ? conn_stub->threads++ : 0;
		sem_post(&conn_stub_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			thread_data->conn_stub = conn_stub;
			thread_data->flags = 1;

			if (pthread_create(&thread, NULL, close_stub_thread,
					(void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn_stub->threads);
		}
	} else {
		sem_post(&conn_stub_list_sem);
		//TODO error
	}
}

void *connect_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;

	struct tcp_segment *temp_seg;

	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		//if CONNECT, send SYN, SYN_SENT
		conn->state = SYN_SENT;
		conn->host_seq_num = 0; //tcp_rand(); //TODO uncomment
		conn->host_seq_end = conn->host_seq_num;

		//TODO add options, for: MSS, max window size!!
		//TODO MSS (2), Window scale (3), SACK (4), alt checksum (14)

		//conn_change_options(conn, tcp->options, SYN);

		//send SYN
		temp_seg = tcp_create(conn);
		tcp_update(temp_seg, conn, FLAG_SYN);
		tcp_send_seg(temp_seg);
		tcp_free(temp_seg);

		conn->timeout = DEFAULT_GBN_TIMEOUT;
		startTimer(conn->to_gbn_fd, conn->timeout);
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

void tcp_exec_connect(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
		uint16_t dst_port) {
	struct tcp_connection *conn;
	int start;
	struct tcp_connection_stub *conn_stub;
	struct tcp_thread_data *stub_thread_data;
	pthread_t stub_thread;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port);
	if (conn == NULL) {
		if (conn_has_space(1)) {
			conn = conn_create(src_ip, src_port, dst_ip, dst_port);
			if (conn_insert(conn)) {
				conn->threads++;
				sem_post(&conn_list_sem);

				//if listening stub remove
				if (sem_wait(&conn_stub_list_sem)) {
					PRINT_ERROR("conn_list_sem wait prob");
					exit(-1);
				}
				conn_stub = conn_stub_find(src_ip, src_port);
				if (conn_stub) {
					conn_stub_remove(conn_stub);
					start = (conn_stub->threads < MAX_THREADS) ?
							conn_stub->threads++ : 0;
					sem_post(&conn_stub_list_sem);

					if (start) {
						stub_thread_data = (struct tcp_thread_data *) malloc(
								sizeof(struct tcp_thread_data));
						stub_thread_data->conn_stub = conn_stub;
						stub_thread_data->flags = 0;

						if (pthread_create(&stub_thread, NULL,
								close_stub_thread, (void *) stub_thread_data)) {
							PRINT_ERROR(
									"ERROR: unable to create recv_thread thread.");
							exit(-1);
						}
					}
				} else {
					sem_post(&conn_stub_list_sem);
				}

				thread_data = (struct tcp_thread_data *) malloc(
						sizeof(struct tcp_thread_data));
				thread_data->conn = conn;

				if (pthread_create(&thread, NULL, connect_thread,
						(void *) thread_data)) {
					PRINT_ERROR("ERROR: unable to create recv_thread thread.");
					exit(-1);
				}
			} else {
				sem_post(&conn_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_insert fail");
				conn_shutdown(conn);
			}
		} else {
			sem_post(&conn_list_sem);

			//TODO throw minor error, list full
		}
	} else {
		sem_post(&conn_list_sem);

		//TODO error, existing connection already connected there
	}
}

void tcp_exec_listen(uint32_t src_ip, uint16_t src_port, uint32_t backlog) {
	struct tcp_connection_stub *conn_stub;

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(src_ip, src_port);
	if (conn_stub == NULL) {
		if (conn_stub_has_space(1)) {
			conn_stub = conn_stub_create(src_ip, src_port, backlog);
			if (conn_stub_insert(conn_stub)) {
				sem_post(&conn_stub_list_sem);
			} else {
				sem_post(&conn_stub_list_sem);

				//error - shouldn't happen
				PRINT_ERROR("conn_stub_insert fail");
				conn_stub_free(conn_stub);
			}
		} else {
			sem_post(&conn_stub_list_sem);
			//TODO throw minor error
		}
	} else {
		sem_post(&conn_stub_list_sem);
		//TODO error
	}

	//TODO send ACK to listen handler - don't? have nonblocking
}

void *accept_thread(void *local) {
	//this will need to be changed
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection_stub *conn_stub = thread_data->conn_stub;
	uint32_t flags = thread_data->flags;

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	int start;
	struct tcp_segment *temp_seg;

	if (sem_wait(&conn_stub->sem)) {
		PRINT_ERROR("conn_stub->sem wait prob");
		exit(-1);
	}
	while (conn_stub->running_flag) {
		if (!queue_is_empty(conn_stub->syn_queue)) {
			node = queue_remove_front(conn_stub->syn_queue);
			sem_post(&conn_stub->sem);

			seg = (struct tcp_segment *) node->data;

			if (sem_wait(&conn_list_sem)) {
				PRINT_ERROR("conn_list_sem wait prob");
				exit(-1);
			}
			conn = conn_find(seg->dst_ip, seg->dst_port, seg->src_ip,
					seg->src_port);
			if (conn == NULL) {
				if (conn_has_space(1)) {
					conn = conn_create(seg->dst_ip, seg->dst_port, seg->src_ip,
							seg->src_port);
					if (conn_insert(conn)) {
						conn->threads++;
						sem_post(&conn_list_sem);

						if (sem_wait(&conn->sem)) {
							PRINT_ERROR("conn->sem wait prob");
							exit(-1);
						}
						if (conn->running_flag) {
							//if SYN, send SYN ACK, SYN_RECV
							conn->state = SYN_RECV;
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
						}

						if (sem_wait(&conn_list_sem)) {
							PRINT_ERROR("conn_list_sem wait prob");
							exit(-1);
						}
						conn->threads--;
						sem_post(&conn_list_sem);

						sem_post(&conn->sem);

						tcp_free(seg);
						break;
					} else {
						sem_post(&conn_list_sem);

						//error - shouldn't happen
						PRINT_ERROR("conn_insert fail");
						conn_shutdown(conn);
					}
				} else {
					sem_post(&conn_list_sem);
					//TODO throw minor error
				}
			} else {
				sem_post(&conn_list_sem);
				//TODO error
			}

			tcp_free(seg);
		} else {
			sem_post(&conn_stub->sem);

			if (sem_wait(&conn_stub->accept_wait_sem)) {
				PRINT_ERROR("conn_stub->accept_wait_sem prod");
				exit(-1);
			}
			sem_init(&conn_stub->accept_wait_sem, 0, 0);
			PRINT_DEBUG("left conn_stub->accept_wait_sem\n");
		}

		if (sem_wait(&conn_stub->sem)) {
			PRINT_ERROR("conn_stub->sem prod");
			exit(-1);
		}
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

void tcp_exec_accept(uint32_t src_ip, uint16_t src_port, uint32_t flags) {
	struct tcp_connection_stub *conn_stub;
	int start;
	struct tcp_thread_data *thread_data;
	pthread_t thread;

	struct tcp_node *node;
	struct tcp_segment *seg;
	struct tcp_connection *conn;
	struct tcp_segment *temp_seg;

	if (sem_wait(&conn_stub_list_sem)) {
		PRINT_ERROR("conn_stub_list_sem wait prob");
		exit(-1);
	}
	conn_stub = conn_stub_find(src_ip, src_port);
	if (conn_stub) {
		start = (conn_stub->threads < MAX_THREADS) ? conn_stub->threads++ : 0;
		sem_post(&conn_stub_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			thread_data->conn_stub = conn_stub;
			thread_data->flags = flags;

			if (pthread_create(&thread, NULL, accept_thread,
					(void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		sem_post(&conn_stub_list_sem);
		//TODO error
	}
}

void *close_thread(void *local) {
	struct tcp_thread_data *thread_data = (struct tcp_thread_data *) local;
	struct tcp_connection *conn = thread_data->conn;

	struct tcp_segment *temp_seg;
	struct tcp_node *temp_node;

	if (sem_wait(&conn->sem)) {
		PRINT_ERROR("conn->sem wait prob");
		exit(-1);
	}
	if (conn->running_flag) {
		if (conn->state == ESTABLISHED) {
			sem_post(&conn->sem);

			if (sem_wait(&conn->write_sem)) {
				PRINT_ERROR("conn->write_sem wait prob");
				exit(-1);
			}

			if (sem_wait(&conn->sem)) {
				PRINT_ERROR("conn->sem wait prob");
				exit(-1);
			}
			if (conn->running_flag) {
				if (conn->state == ESTABLISHED) {
					conn->state = FIN_WAIT_1;

					//if CLOSE, send FIN, FIN_WAIT_1
					if (queue_is_empty(conn->write_queue)
							&& conn->host_seq_num == conn->host_seq_end) {
						//send FIN
						temp_seg = tcp_create(conn);
						tcp_update(temp_seg, conn, FLAG_FIN);

						temp_node = node_create((uint8_t *) temp_seg, 1,
								temp_seg->seq_num, temp_seg->seq_num);
						queue_append(conn->send_queue, temp_node);

						tcp_send_seg(temp_seg);
					} //else piggy back it
				} else {
					//TODO figure out:
				}
			} else {
				//TODO figure out: conn shutting down already?
			}
		} else {
			//TODO figure out close call on non-establisehd conn
		}
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
void tcp_exec_close(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip,
		uint16_t dst_port) {
	struct tcp_connection *conn;
	int start;
	pthread_t thread;
	struct tcp_thread_data *thread_data;

	if (sem_wait(&conn_list_sem)) {
		PRINT_ERROR("conn_list_sem wait prob");
		exit(-1);
	}
	conn = conn_find(src_ip, src_port, dst_ip, dst_port);
	if (conn) {
		start = (conn->threads < MAX_THREADS) ? conn->threads++ : 0;
		sem_post(&conn_list_sem);

		if (start) {
			thread_data = (struct tcp_thread_data *) malloc(
					sizeof(struct tcp_thread_data));
			thread_data->conn = conn;

			if (pthread_create(&thread, NULL, close_thread,
					(void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create recv_thread thread.");
				exit(-1);
			}
		} else {
			PRINT_DEBUG("Too many threads=%d. Dropping...", conn->threads);
		}
	} else {
		sem_post(&conn_list_sem);
		//TODO error trying to close closed connection
	}
}

void tcp_exec(struct finsFrame *ff) {
	uint8_t *pt;

	switch (ff->ctrlFrame.paramterID) {
	case EXEC_TCP_CONNECT:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			uint32_t dst_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t dst_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_connect(src_ip, src_port, dst_ip, dst_port);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_TCP_LISTEN:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t backlog = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_listen(src_ip, src_port, backlog);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_TCP_ACCEPT:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t flags = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_accept(src_ip, src_port, flags);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_TCP_CLOSE:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			uint32_t dst_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t dst_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_close(src_ip, src_port, dst_ip, dst_port);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_TCP_CLOSE_STUB:
		if (ff->ctrlFrame.paramterValue && ff->ctrlFrame.paramterLen) {
			pt = ff->ctrlFrame.paramterValue;

			uint32_t src_ip = *(uint32_t *) pt;
			pt += sizeof(uint32_t);

			uint16_t src_port = *(uint16_t *) pt;
			pt += sizeof(uint16_t);

			if (pt - (uint8_t *) ff->ctrlFrame.paramterValue
					!= ff->ctrlFrame.paramterLen) {
				PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d",
						pt - (uint8_t *) ff->ctrlFrame.paramterValue,
						ff->ctrlFrame.paramterLen);
				//TODO error
				break;
			}

			tcp_exec_close_stub(src_ip, src_port);

			free(ff->ctrlFrame.paramterValue);
		} else {
			//TODO error
		}
		break;
	case EXEC_TCP_OPT:
		//TODO finish
		break;
	default:
		break;
	}
}

void tcp_out_fcf(struct finsFrame *ff) {

//TODO fill out

	switch ((ff->ctrlFrame).opcode) {
	case CTRL_ALERT:
		break;
	case CTRL_READ_PARAM:
		break;
	case CTRL_READ_PARAM_REPLY:
		break;
	case CTRL_SET_PARAM:
		break;
	case CTRL_EXEC:
		tcp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		break;
	case CTRL_ERROR:
		break;
	default:
		break;
	}

	freeFinsFrame(ff);
}
