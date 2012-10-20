/**
 * icmp.c
 *
 *  Created on: Mar 15, 2011 - June 22, 2011
 *      Author: Abdallah Abdallah & Mark Hutcheson
 */

#include <sys/time.h>
#include <math.h>
#include <string.h>
#include "icmp.h"
#include <ipv4.h>

int icmp_running;
pthread_t switch_to_icmp_thread;

sem_t ICMP_to_Switch_Qsem;
finsQueue ICMP_to_Switch_Queue;

sem_t Switch_to_ICMP_Qsem;
finsQueue Switch_to_ICMP_Queue;

struct icmp_sent_list *sent_packet_list;

double icmp_time_diff(struct timeval *time1, struct timeval *time2) { //time2 - time1
	double decimal = 0, diff = 0;

	PRINT_DEBUG("Entered: time1=%p, time2=%p", time1, time2);

	//PRINT_DEBUG("getting seqEndRTT=%d current=(%d, %d)\n", conn->rtt_seq_end, (int) current.tv_sec, (int)current.tv_usec);

	if (time1->tv_usec > time2->tv_usec) {
		decimal = (1000000.0 + time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec - 1.0;
	} else {
		decimal = (time2->tv_usec - time1->tv_usec) / 1000000.0;
		diff = time2->tv_sec - time1->tv_sec;
	}
	diff += decimal;

	diff *= 1000.0;

	PRINT_DEBUG("diff=%f", diff);
	return diff;
}

struct icmp_sent *sent_create(uint32_t src_ip, uint32_t dst_ip, u_char *data, uint32_t data_len) {
	PRINT_DEBUG("Entered: src_ip=%u, dst_ip=%u, data=%p, data_len=%u", src_ip, dst_ip, data, data_len);

	struct icmp_sent *sent = (struct icmp_sent *) malloc(sizeof(struct icmp_sent));
	if (sent == NULL) {
		PRINT_ERROR("icmp_sent alloc fail");
		exit(-1);
	}

	sent->next = NULL;

	sent->src_ip = src_ip;
	sent->dst_ip = dst_ip;

	sent->data = data;
	sent->data_len = data_len;

	memset(&sent->stamp, 0, sizeof(struct timeval));

	PRINT_DEBUG("Exited: src_ip=%u, dst_ip=%u, data=%p, data_len=%u, sent=%p", src_ip, dst_ip, data, data_len, sent);
	return sent;
}

void sent_free(struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent=%p", sent);

	if (sent->data) {
		free(sent->data);
	}

	free(sent);
}

struct icmp_sent_list *sent_list_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct icmp_sent_list *sent_list = (struct icmp_sent_list *) malloc(sizeof(struct icmp_sent_list));
	if (sent_list == NULL) {
		PRINT_ERROR("sent_list alloc fail");
		exit(-1);
	}

	sent_list->max = max;
	sent_list->len = 0;

	sent_list->front = NULL;
	sent_list->end = NULL;

	PRINT_DEBUG("Entered: max=%u, sent_list=%p", max, sent_list);
	return sent_list;
}

void sent_list_append(struct icmp_sent_list *sent_list, struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	sent->next = NULL;
	if (sent_list_is_empty(sent_list)) {
		//queue empty
		sent_list->front = sent;
	} else {
		//node after end
		sent_list->end->next = sent;
	}
	sent_list->end = sent;
	sent_list->len++;
}

struct icmp_sent *sent_list_find(struct icmp_sent_list *sent_list, u_char *data, uint32_t data_len) {
	PRINT_DEBUG("Entered: sent_list=%p, data=%p, data_len=%u", sent_list, data, data_len);

	struct icmp_sent *sent = sent_list->front;

	while (sent != NULL) {
		if (sent->data_len >= data_len) { //TODO change? always assume that frag is smaller
			if (strncmp((char *) sent->data, (char *) data, data_len) == 0) {
				break;
			}
		}

		sent = sent->next;
	}

	PRINT_DEBUG("Exited: sent_list=%p, data=%p, data_len=%u, sent=%p", sent_list, data, data_len, sent);
	return sent;
}

struct icmp_sent *sent_list_remove_front(struct icmp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct icmp_sent *sent = sent_list->front;
	if (sent) {
		sent_list->front = sent->next;
		sent_list->len--;
	} else {
		PRINT_ERROR("reseting len: len=%d", sent_list->len);
		sent_list->len = 0;
	}

	PRINT_DEBUG("Exited: sent_list=%p sent=%p", sent_list, sent);
	return sent;
}

void sent_list_remove(struct icmp_sent_list *sent_list, struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	if (sent_list->len == 0) {
		return;
	}

	if (sent_list->front == sent) {
		sent_list->front = sent_list->front->next;
		sent_list->len--;
		return;
	}

	struct icmp_sent *temp = sent_list->front;
	while (temp->next != NULL) {
		if (temp->next == sent) {
			if (sent_list->end == sent) {
				sent_list->end = temp;
				temp->next = NULL;
			} else {
				temp->next = sent->next;
			}

			sent_list->len--;
			return;
		}
		temp = temp->next;
	}
}

int sent_list_is_empty(struct icmp_sent_list *sent_list) {
	return sent_list->len == 0;
}

int sent_list_has_space(struct icmp_sent_list *sent_list) {
	return sent_list->len < sent_list->max;
}

void sent_list_free(struct icmp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct icmp_sent *sent;
	while (!sent_list_is_empty(sent_list)) {
		sent = sent_list_remove_front(sent_list);
		sent_free(sent);
	}

	free(sent_list);
}

//--------------------------------------------
// We're getting an ICMP packet in. Process it
//--------------------------------------------
void icmp_in(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	struct ip4_packet *ipv4_pkt = (struct ip4_packet *) ff->dataFrame.pdu;
	uint16_t ipv4_len = ntohs(ipv4_pkt->ip_len);

	struct icmp_packet *icmp_pkt = (struct icmp_packet *) ipv4_pkt->ip_data;
	uint32_t icmp_len = ipv4_len - IP4_HLEN(ipv4_pkt);

	PRINT_DEBUG("pdu_len=%u, ipv4_len=%u, icmp_len=%u, hlen=%u", ff->dataFrame.pduLength, ipv4_len, icmp_len, IP4_HLEN(ipv4_pkt));

	if (icmp_len < ICMP_HEADER_SIZE) {
		PRINT_DEBUG("packet too small: icmp_len=%u, icmp_req=%u", icmp_len, ICMP_HEADER_SIZE);

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	metadata *params = ff->metaData;
	if (params == NULL) {
		PRINT_ERROR("todo error");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	uint8_t protocol;

	int ret = 0;
	ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;
	if (ret) {
		PRINT_ERROR("todo error");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	if (protocol != ICMP_PROTOCOL) { //TODO remove this check?
		PRINT_ERROR("Protocol =/= ICMP! Discarding frame...");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	if (icmp_pkt->checksum == 0) {
		PRINT_DEBUG("checksum==0");
	} else {
		if (icmp_checksum(ipv4_pkt->ip_data, icmp_len) != 0) {
			PRINT_ERROR("Error in checksum of packet. Discarding...");

			//free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
			return;
		} else {

		}
	}

	uint32_t data_len = icmp_len - ICMP_HEADER_SIZE;

	//icmp_create_control_error(ff, icmp_pkt->type, icmp_pkt->code);

	PRINT_DEBUG("ff=%p, type=%u, code=%u, data_len=%u", ff, icmp_pkt->type, icmp_pkt->code, data_len);
	switch (icmp_pkt->type) {
	case TYPE_ECHOREPLY:
		if (icmp_pkt->code == CODE_ECHO) {
			//ff->dataOrCtrl = DATA;
			ff->destinationID.id = DAEMON_ID;
			ff->destinationID.next = NULL;
			//ff->metaData = params;

			//ff->dataFrame.directionFlag = UP;
			//ff->dataFrame.pduLength = len;
			//ff->dataFrame.pdu = dataLocal;

			icmp_to_switch(ff);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			//free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}
		break;
	case TYPE_DESTUNREACH:
		PRINT_DEBUG("Destination unreachable");

		if (icmp_pkt->code == CODE_NETUNREACH) {
			PRINT_DEBUG("todo");
		} else if (icmp_pkt->code == CODE_HOSTUNREACH) {
			PRINT_DEBUG("todo");
		} else if (icmp_pkt->code == CODE_PROTOUNREACH) {
			PRINT_DEBUG("todo");
		} else if (icmp_pkt->code == CODE_PORTUNREACH) {
			if (data_len < IP4_MIN_HLEN) {
				PRINT_ERROR("data too small: data_len=%u, ipv4_req=%u", data_len, IP4_MIN_HLEN);
				//stats.badhlen++;
				//stats.droppedtotal++;

				//free(ff->dataFrame.pdu);
				freeFinsFrame(ff);
				return;
			}

			struct ip4_packet *ipv4_pkt_sent = (struct ip4_packet *) icmp_pkt->data;
			uint16_t sent_data_len = data_len - IP4_HLEN(ipv4_pkt_sent);

			uint16_t src_port;
			uint16_t dst_port;
			metadata *params_err;
			struct finsFrame *ff_err;

			switch (ipv4_pkt_sent->ip_proto) {
			case ICMP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < ICMP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, ICMP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				if (sent_list_is_empty(sent_packet_list)) {
					PRINT_ERROR("todo error");
					//TODO drop
				} else {
					struct icmp_sent *sent = sent_list_find(sent_packet_list, ipv4_pkt_sent->ip_data, sent_data_len);
					if (sent) {
						//cast first 8 bytes of ip->data to TCP frag, store in metadata
						params_err = (metadata *) malloc(sizeof(metadata));
						if (params_err == NULL) {
							PRINT_ERROR("metadata creation failed");
							exit(-1);
						}
						metadata_create(params_err);

						metadata_writeToElement(params_err, "protocol", &ipv4_pkt_sent->ip_proto, META_TYPE_INT);
						metadata_writeToElement(params_err, "src_ip", &sent->src_ip, META_TYPE_INT);
						metadata_writeToElement(params_err, "dst_ip", &sent->dst_ip, META_TYPE_INT);

						ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
						if (ff_err == NULL) {
							PRINT_ERROR("ff_err alloc error");
							exit(-1);
						}

						ff_err->dataOrCtrl = CONTROL;
						ff_err->destinationID.id = DAEMON_ID;
						ff_err->destinationID.next = NULL;
						ff_err->metaData = params_err;

						ff_err->ctrlFrame.senderID = ICMP_ID;
						ff_err->ctrlFrame.serial_num = gen_control_serial_num();
						ff_err->ctrlFrame.opcode = CTRL_ERROR;
						ff_err->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code

						ff_err->ctrlFrame.data_len = sent->data_len;
						ff_err->ctrlFrame.data = sent->data;
						sent->data = NULL;

						icmp_to_switch(ff_err);

						sent_list_remove(sent_packet_list, sent);
						sent_free(sent);
					} else {
						PRINT_ERROR("todo error");
						//TODO drop?
					}
				}
				break;
			case TCP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < TCP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, TCP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				params_err = (metadata *) malloc(sizeof(metadata));
				if (params_err == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_err);

				struct tcp_header_frag *tcp_hdr = (struct tcp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(tcp_hdr->src_port);
				dst_port = ntohs(tcp_hdr->dst_port);
				uint32_t seq_num = ntohl(tcp_hdr->seq_num);

				//TODO src/dst_ip should already be in from IPv4 mod
				metadata_writeToElement(params_err, "src_port", &src_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "dst_port", &dst_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "seq_num", &seq_num, META_TYPE_INT);

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = TCP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params_err;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code

				icmp_to_switch(ff_err);
				break;
			case UDP_PROTOCOL:
				//cast first 8 bytes of ip->data to udp frag, store in metadata
				if (sent_data_len < UDP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				params_err = (metadata *) malloc(sizeof(metadata));
				if (params_err == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_err);

				struct udp_header_frag *udp_hdr = (struct udp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(udp_hdr->src_port);
				dst_port = ntohs(udp_hdr->dst_port);
				uint16_t udp_len = ntohs(udp_hdr->len);
				uint16_t checksum = ntohs(udp_hdr->checksum);

				metadata_writeToElement(params_err, "src_port", &src_port, META_TYPE_INT); //TODO remove? should already be in from IPv4 mod
				metadata_writeToElement(params_err, "dst_port", &dst_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "udp_len", &udp_len, META_TYPE_INT);
				metadata_writeToElement(params_err, "checksum", &checksum, META_TYPE_INT);

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = UDP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params_err;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code

				icmp_to_switch(ff_err);
				break;
			default:
				PRINT_ERROR("todo error");
				break;
			}
		} else if (icmp_pkt->code == CODE_FRAGNEEDED) {
			PRINT_DEBUG("todo");

			//TODO use icmp_pkt->param_2 as Next-Hop MTU

		} else if (icmp_pkt->code == CODE_SRCROUTEFAIL) {
			PRINT_DEBUG("todo");
		} else {
			PRINT_ERROR("Unrecognized code. Dropping...");
			return;
		}
		break;
	case TYPE_ECHOREQUEST:
		if (icmp_pkt->code == CODE_ECHO) {
			//Create an echo reply packet and send it out
			icmp_ping_reply(ff, icmp_pkt, data_len);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			//free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}
		break;
	case TYPE_TTLEXCEED:
		PRINT_DEBUG("TTL Exceeded");
		if (icmp_pkt->code == CODE_TTLEXCEEDED) {
			if (data_len < IP4_MIN_HLEN) {
				PRINT_ERROR("data too small: data_len=%u, ipv4_req=%u", data_len, IP4_MIN_HLEN);
				//stats.badhlen++;
				//stats.droppedtotal++;

				//free(ff->dataFrame.pdu);
				freeFinsFrame(ff);
				return;
			}

			struct ip4_packet *ipv4_pkt_sent = (struct ip4_packet *) icmp_pkt->data;
			uint16_t sent_data_len = data_len - IP4_HLEN(ipv4_pkt_sent);

			uint16_t src_port;
			uint16_t dst_port;
			metadata *params_err;
			struct finsFrame *ff_err;

			switch (ipv4_pkt_sent->ip_proto) {
			case ICMP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < ICMP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, ICMP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				if (sent_list_is_empty(sent_packet_list)) {
					PRINT_ERROR("todo error");
					//TODO drop
				} else {
					struct icmp_sent *sent = sent_list_find(sent_packet_list, ipv4_pkt_sent->ip_data, sent_data_len);
					if (sent) {
						//cast first 8 bytes of ip->data to TCP frag, store in metadata
						params_err = (metadata *) malloc(sizeof(metadata));
						if (params_err == NULL) {
							PRINT_ERROR("metadata creation failed");
							exit(-1);
						}
						metadata_create(params_err);

						metadata_writeToElement(params_err, "protocol", &ipv4_pkt_sent->ip_proto, META_TYPE_INT);
						metadata_writeToElement(params_err, "src_ip", &sent->src_ip, META_TYPE_INT);
						metadata_writeToElement(params_err, "dst_ip", &sent->dst_ip, META_TYPE_INT);

						ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
						if (ff_err == NULL) {
							PRINT_ERROR("ff_err alloc error");
							exit(-1);
						}

						ff_err->dataOrCtrl = CONTROL;
						ff_err->destinationID.id = DAEMON_ID;
						ff_err->destinationID.next = NULL;
						ff_err->metaData = params_err;

						ff_err->ctrlFrame.senderID = ICMP_ID;
						ff_err->ctrlFrame.serial_num = gen_control_serial_num();
						ff_err->ctrlFrame.opcode = CTRL_ERROR;
						ff_err->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code

						ff_err->ctrlFrame.data_len = sent->data_len;
						ff_err->ctrlFrame.data = sent->data;
						sent->data = NULL;

						icmp_to_switch(ff_err);

						sent_list_remove(sent_packet_list, sent);
						sent_free(sent);
					} else {
						PRINT_ERROR("todo error");
						//TODO drop?
					}
				}
				break;
			case TCP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < TCP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, TCP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				params_err = (metadata *) malloc(sizeof(metadata));
				if (params_err == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_err);

				struct tcp_header_frag *tcp_hdr = (struct tcp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(tcp_hdr->src_port);
				dst_port = ntohs(tcp_hdr->dst_port);
				uint32_t seq_num = ntohl(tcp_hdr->seq_num);

				//TODO src/dst_ip should already be in from IPv4 mod
				metadata_writeToElement(params_err, "src_port", &src_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "dst_port", &dst_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "seq_num", &seq_num, META_TYPE_INT);

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = TCP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params_err;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code

				icmp_to_switch(ff_err);
				break;
			case UDP_PROTOCOL:
				//cast first 8 bytes of ip->data to udp frag, store in metadata
				if (sent_data_len < UDP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);

					//free(ff->dataFrame.pdu);
					freeFinsFrame(ff);
					return;
				}

				params_err = (metadata *) malloc(sizeof(metadata));
				if (params_err == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_err);

				struct udp_header_frag *udp_hdr = (struct udp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(udp_hdr->src_port);
				dst_port = ntohs(udp_hdr->dst_port);
				uint16_t udp_len = ntohs(udp_hdr->len);
				uint16_t checksum = ntohs(udp_hdr->checksum);

				metadata_writeToElement(params_err, "src_port", &src_port, META_TYPE_INT); //TODO remove? should already be in from IPv4 mod
				metadata_writeToElement(params_err, "dst_port", &dst_port, META_TYPE_INT);
				metadata_writeToElement(params_err, "udp_len", &udp_len, META_TYPE_INT);
				metadata_writeToElement(params_err, "checksum", &checksum, META_TYPE_INT);

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = UDP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params_err;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code

				icmp_to_switch(ff_err);
				break;
			default:
				PRINT_ERROR("todo error");
				break;
			}
		} else if (icmp_pkt->code == CODE_DEFRAGTIMEEXCEEDED) {
			PRINT_DEBUG("todo");
			//icmp_create_control_error(ff, icmp_pkt->type, icmp_pkt->code);

			//cName = (unsigned char*) malloc(strlen("TTLfragtime") + 1);
			//strcpy((char *) cName, "TTLfragtime");
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			//free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_DEBUG("default: type=%u", icmp_pkt->type);
		//Simply pass up the stack,

		//ff->dataOrCtrl = DATA;
		ff->destinationID.id = DAEMON_ID;
		ff->destinationID.next = NULL;
		//ff->metaData = params;

		//ff->dataFrame.directionFlag = UP;
		//ff->dataFrame.pduLength = len;
		//ff->dataFrame.pdu = dataLocal;

		icmp_to_switch(ff);
		break;
	}
}

void icmp_sent_gc(void) {
	PRINT_DEBUG("Entered");

	struct timeval current;
	gettimeofday(&current, 0);

	struct icmp_sent *old;

	struct icmp_sent *temp = sent_packet_list->front;
	while (temp) {
		if (icmp_time_diff(&temp->stamp, &current) >= ICMP_MSL_TO_DEFAULT) {
			old = temp;
			temp = temp->next;

			sent_list_remove(sent_packet_list, old);
			sent_free(old);
		} else {
			temp = temp->next;
		}
	}
}

//-------------------------------------------------------
// We're sending an ICMP packet out. Process it and send.
//-------------------------------------------------------
void icmp_out(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	if (ff->metaData == NULL) {
		PRINT_ERROR("Metadata null, dropping: ff=%p", ff);

		freeFinsFrame(ff);
		return;
	}

	uint32_t src_ip;
	uint32_t dst_ip;

	metadata *params = ff->metaData;
	int ret = 0;
	ret += metadata_readFromElement(params, "src_ip", &src_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(params, "dst_ip", &dst_ip) == CONFIG_FALSE;

	if (ret) {
		PRINT_ERROR("todo error");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	uint8_t protocol = ICMP_PROTOCOL;
	metadata_writeToElement(params, "protocol", &protocol, META_TYPE_INT);
	//metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT);
	//metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);

	//struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = IPV4_ID; // destination module ID
	ff->destinationID.next = NULL;
	//ff->metaData = params;

	//ff->dataFrame.directionFlag = DOWN; // ingress or egress network data; see above
	//ff->dataFrame.pduLength = data_len; //Add in the header size for this, too
	//ff->dataFrame.pdu = (u_char *) malloc(ff->dataFrame.pduLength);

	uint32_t pdu_len = ff->dataFrame.pduLength;
	u_char *pdu = (u_char *) malloc(pdu_len);
	if (pdu == NULL) {
		PRINT_ERROR("pdu alloc fail");
		exit(-1);
	}
	memcpy(pdu, ff->dataFrame.pdu, pdu_len);

	if (icmp_to_switch(ff)) {
		struct icmp_sent *sent = sent_create(src_ip, dst_ip, pdu, pdu_len);

		if (sent_list_has_space(sent_packet_list)) {
			sent_list_append(sent_packet_list, sent);
			PRINT_DEBUG("sent_packet_list=%p, len=%u, max=%u", sent_packet_list, sent_packet_list->len, sent_packet_list->max)

			gettimeofday(&sent->stamp, 0);
		} else {
			PRINT_DEBUG("Clearing sent_packet_list");
			icmp_sent_gc();

			if (sent_list_has_space(sent_packet_list)) {
				sent_list_append(sent_packet_list, sent);
				PRINT_DEBUG("sent_packet_list=%p, len=%u, max=%u", sent_packet_list, sent_packet_list->len, sent_packet_list->max)

				gettimeofday(&sent->stamp, 0);
			} else {
				PRINT_ERROR("todo error");
			}
		}
	} else {
		PRINT_ERROR("todo error");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
	}
}

//---------------------------------------------------
// Retrieve a finsFrame from the queue and process it
//---------------------------------------------------
void icmp_get_ff(void) {
	struct finsFrame *ff;

	do {
		sem_wait(&Switch_to_ICMP_Qsem);
		ff = read_queue(Switch_to_ICMP_Queue);
		sem_post(&Switch_to_ICMP_Qsem);
	} while (icmp_running && ff == NULL);

	if (!icmp_running) {
		return;
	}

	if (ff->dataOrCtrl == CONTROL) { // send to the control frame handler
		icmp_fcf(ff);
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == UP) { //Incoming ICMP packet (coming in from teh internets)
			icmp_in(ff);
		} else if (ff->dataFrame.directionFlag == DOWN) { //Outgoing ICMP packet (going out from us to teh internets)
			icmp_out(ff);
		}
	} else {
		PRINT_ERROR("todo error");
	}
}

int icmp_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);
	if (sem_wait(&ICMP_to_Switch_Qsem)) {
		PRINT_ERROR("ICMP_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, ICMP_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&ICMP_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&ICMP_to_Switch_Qsem);

	return 0;
}

//-------------------------------------------
// Calculate the checksum of this ICMP packet
//-------------------------------------------
uint16_t icmp_checksum(uint8_t *pt, uint32_t len) {
	PRINT_DEBUG("Entered: pt=%p, len=%u", pt, len);
	uint32_t sum = 0;
	uint32_t i;

	for (i = 1; i < len; i += 2, pt += 2) {
		//PRINT_DEBUG("%u=%2x (%u), %u=%2x (%u)", i-1, *(pt), *(pt), i, *(pt+1), *(pt+1));
		sum += (*pt << 8) + *(pt + 1);
	}
	if (len & 0x1) {
		//PRINT_DEBUG("%u=%2x (%u), uneven", len-1, *(pt), *(pt));
		sum += *pt << 8;
	}

	while ((sum >> 16)) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;

//hdr->checksum = htons((uint16_t) sum);

	PRINT_DEBUG("checksum=%x", (uint16_t) sum);
	return (uint16_t) sum;
}

//------------------------------------------------------------------------------
// Create a ping reply message (from the ping request message) when we're pinged
//------------------------------------------------------------------------------
void icmp_ping_reply(struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);

	uint32_t pdu_len_reply = data_len + ICMP_HEADER_SIZE;
	u_char *pdu_reply = (u_char *) malloc(pdu_len_reply);
	if (pdu_reply == NULL) {
		PRINT_ERROR("pdu alloc fail");
		exit(-1);
	}

	struct icmp_packet *icmp_pkt_reply = (struct icmp_packet *) pdu_reply;
	icmp_pkt_reply->type = TYPE_ECHOREPLY;
	icmp_pkt_reply->code = CODE_ECHO;
	icmp_pkt_reply->checksum = 0;
	icmp_pkt_reply->param_1 = icmp_pkt->param_1; //id
	icmp_pkt_reply->param_2 = icmp_pkt->param_2; //seq num

	memcpy(icmp_pkt_reply->data, icmp_pkt->data, data_len);

	icmp_pkt_reply->checksum = htons(icmp_checksum(pdu_reply, pdu_len_reply));
	PRINT_DEBUG("checksum=0x%x", icmp_pkt_reply->checksum);

	uint32_t src_ip;
	uint32_t dst_ip;

	metadata *params = ff->metaData;
	int ret = 0;
	ret += metadata_readFromElement(params, "src_ip", &src_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(params, "dst_ip", &dst_ip) == CONFIG_FALSE;
	if (ret) {
		PRINT_ERROR("todo error");

		//free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	metadata *params_reply = (metadata *) malloc(sizeof(metadata));
	if (params_reply == NULL) {
		PRINT_ERROR("failed to create matadata: ff=%p", ff);
		//free(ff->dataFrame.pdu);
		//freeFinsFrame(ff);
		exit(-1);
	}
	metadata_create(params_reply);

	uint8_t protocol = ICMP_PROTOCOL;
	metadata_writeToElement(params_reply, "protocol", &protocol, META_TYPE_INT);
	metadata_writeToElement(params_reply, "src_ip", &dst_ip, META_TYPE_INT);
	metadata_writeToElement(params_reply, "dst_ip", &src_ip, META_TYPE_INT);

	struct finsFrame *ff_reply = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff_reply == NULL) {
		PRINT_ERROR("ff alloc failed");
		//metadata_destroy(params_reply);
		exit(-1);
	}

	ff_reply->dataOrCtrl = DATA;
	ff_reply->destinationID.id = IPV4_ID;
	ff_reply->destinationID.next = NULL;
	ff_reply->metaData = params_reply;

	ff_reply->dataFrame.directionFlag = DOWN;
	ff_reply->dataFrame.pduLength = pdu_len_reply;
	ff_reply->dataFrame.pdu = pdu_reply;

	icmp_to_switch(ff_reply);

	//free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

void icmp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		//arp_read_param(ff);
		//TODO read interface_mac?
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		//arp_set_param(ff);
		//TODO set interface_mac?
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		//arp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		break;
	}
}

//-----------------------------------------------------------------------------------------------------
// Handles what we do when we receive a control frame. We'll probably create some kind of error message
//-----------------------------------------------------------------------------------------------------
void icmp_control_handler(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	uint8_t Type, Code;
//Figure out what message we've received and create the appropriate message accordingly.
	if (strncmp((char *) ff->ctrlFrame.name, "DU", 2) == 0) //Destination unreachable
			{
		ff->ctrlFrame.name = &(ff->ctrlFrame.name[2]); //Pass along only the "protounreach" or whatever
		PRINT_DEBUG("");
		Type = TYPE_DESTUNREACH; //Set the error type
		//And find the right error code
		if (strcmp((char *) ff->ctrlFrame.name, "netunreach") == 0) {
			Code = CODE_NETUNREACH;
		} else if (strcmp((char *) ff->ctrlFrame.name, "hostunreach") == 0) {
			Code = CODE_HOSTUNREACH;
		} else if (strcmp((char *) ff->ctrlFrame.name, "protounreach") == 0) {
			Code = CODE_PROTOUNREACH;
		} else if (strcmp((char *) ff->ctrlFrame.name, "portunreach") == 0) {
			Code = CODE_PORTUNREACH;
		} else if (strcmp((char *) ff->ctrlFrame.name, "fragneeded") == 0) {
			Code = CODE_FRAGNEEDED;
		} else if (strcmp((char *) ff->ctrlFrame.name, "srcroute") == 0) {
			Code = CODE_SRCROUTEFAIL;
		} else {
			PRINT_DEBUG("Error: Unsupported code. Dropping...");
			return;
		}
	} else if (strncmp((char *) ff->ctrlFrame.name, "TTL", 3) == 0) //Time to live exceeded
			{
		ff->ctrlFrame.name = &(ff->ctrlFrame.name[3]); //Pass along only the "exceeded" or "fragtime"
		PRINT_DEBUG("");
		Type = TYPE_TTLEXCEED; //Set the error type
		//And find the right error code
		if (strcmp((char *) ff->ctrlFrame.name, "exceeded") == 0) {
			Code = CODE_TTLEXCEEDED;
		} else if (strcmp((char *) ff->ctrlFrame.name, "fragtime") == 0) {
			Code = CODE_DEFRAGTIMEEXCEEDED;
		} else {
			PRINT_DEBUG("Error: Unsupported code. Dropping...");
			return;
		}
	} else {
		PRINT_DEBUG("Unsupported ICMP control frame type. Dropping...");
		return;
	}
	icmp_create_error(ff, Type, Code); //Create an error message from this type & code & send it out
}

//--------------------------------------------------------------------------------------------------------
// Create an ICMP error message from the specified error type and code and control frame. Also send it out
//--------------------------------------------------------------------------------------------------------
void icmp_create_error(struct finsFrame *ff, uint8_t Type, uint8_t Code) {
	struct finsFrame* ffout = (struct finsFrame*) (malloc(sizeof(struct finsFrame)));
	int totallen = 0; //How many bytes we want our ICMP message to be
	int checksum = 0;

//Manually grab an int value from the first four bytes of this data
	int i;
	for (i = 0; i < sizeof(int); i++) {
		totallen += ((int) (ff->ctrlFrame.data_old) << (8 * i));
		(ff->ctrlFrame.data_old)++; //increment pointer
	}

//How many bytes is all this?
	totallen += ICMP_HEADER_SIZE; //The length we want is the length of the IP data we want to include + the 8 byte ICMP header
//Now that we have the total length, we can create the finsFrame that has the PDU length we want

	ffout->dataOrCtrl = DATA; //We're sending a data packet here
	ffout->destinationID.id = IPV4_ID; //Go out across the wire
	ffout->destinationID.next = NULL;
	ffout->dataFrame.directionFlag = DOWN; //Out
	ffout->dataFrame.pduLength = totallen; //Make the total length correct
	ffout->dataFrame.pdu = (unsigned char *) malloc(totallen); //Allocate memory for the data we'll be sticking in
	metadata_create(ffout->metaData);
//Fill the metadata with dest IP.
	metadata_writeToElement(ffout->metaData, "dst_ip", &(((struct ip4_packet*) ff->ctrlFrame.data_old)->ip_src), META_TYPE_INT);
//I treat all the ICMP stuff as raw data, rather than encapsulating it in structs, due to working with such structs earlier this summer
//and running into a ton of little-vs-big-endian issues. Handling the raw data this way is easier for me than remembering to htons()
//everything, especially because most ICMP headers contain variable-sized data anyway.

	PRINT_DEBUG("");
//Fill in the ICMP header data.
	ffout->dataFrame.pdu[0] = Type; //Fill in the correct type and code
	ffout->dataFrame.pdu[1] = Code;
//Clear the checksum and "unused" fields
	memset(&(ffout->dataFrame.pdu[2]), 0, ICMP_HEADER_SIZE - 2);

//Copy the rest of the data over
	memcpy(&(ffout->dataFrame.pdu[ICMP_HEADER_SIZE]), ff->ctrlFrame.data_old, totallen - ICMP_HEADER_SIZE);

//Compute the checksum
//checksum = icmp_checksum(ffout); //TODO uncomment
//And set the checksum field(s)
	ffout->dataFrame.pdu[2] = checksum >> 8;
	ffout->dataFrame.pdu[3] = (checksum & 0xFF);

//Done! Send out the frame
//icmp_send_FF(ffout);
}

//----------------------------------------------------------------------
// Create an error control frame from an ICMP error message that came in
//----------------------------------------------------------------------
void icmp_create_control_error(struct finsFrame* ff, uint8_t Type, uint8_t Code) {
	struct finsFrame* ffout = (struct finsFrame*) (malloc(sizeof(struct finsFrame)));
//int checksum = 0;
	unsigned char* cName = NULL;
	unsigned char* cData = NULL;
	int iLen = 0;

	ffout->dataOrCtrl = CONTROL; //We're sending a control here
	ffout->destinationID.id = UDP_ID; //Go to the UDP stub. TODO: Should probably also send one to TCP whenever TCP is finished
	ffout->destinationID.next = NULL;
	ffout->ctrlFrame.senderID = ICMP_ID; //Coming from the ICMP module
	ffout->ctrlFrame.opcode = CTRL_ERROR; //Error code comin' through!
	ffout->ctrlFrame.serial_num = 0; //No use for this currently. Probably should use for some kind of tracking later.
//Figure out the name from the passed type and code
	if (Type == TYPE_DESTUNREACH) {
		if (Code == CODE_NETUNREACH) {
			cName = (unsigned char*) malloc(strlen("DUnetunreach") + 1);
			strcpy((char *) cName, "DUnetunreach");
		} else if (Code == CODE_HOSTUNREACH) {
			cName = (unsigned char*) malloc(strlen("DUhostunreach") + 1);
			strcpy((char *) cName, "DUhostunreach");
		} else if (Code == CODE_PROTOUNREACH) {
			cName = (unsigned char*) malloc(strlen("DUprotounreach") + 1);
			strcpy((char *) cName, "DUprotounreach");
		} else if (Code == CODE_PORTUNREACH) {
			cName = (unsigned char*) malloc(strlen("DUportunreach") + 1);
			strcpy((char *) cName, "DUportunreach");
		} else if (Code == CODE_FRAGNEEDED) {
			cName = (unsigned char*) malloc(strlen("DUfragneeded") + 1);
			strcpy((char *) cName, "DUfragneeded");
		} else if (Code == CODE_SRCROUTEFAIL) {
			cName = (unsigned char*) malloc(strlen("DUsrcroute") + 1);
			strcpy((char *) cName, "DUsrcroute");
		} else {
			PRINT_DEBUG("Unrecognized code. Dropping...");
			return;
		}
	} else if (Type == TYPE_TTLEXCEED) {
		if (Code == CODE_TTLEXCEEDED) {
			cName = (unsigned char*) malloc(strlen("TTLexceeded") + 1);
			strcpy((char *) cName, "TTLexceeded");
		} else if (Code == CODE_DEFRAGTIMEEXCEEDED) {
			cName = (unsigned char*) malloc(strlen("TTLfragtime") + 1);
			strcpy((char *) cName, "TTLfragtime");
		} else {
			PRINT_DEBUG("Unrecognized code. Dropping...");
			return;
		}
	} else {
		PRINT_DEBUG("Unrecognized type. Dropping...");
		return;
	}

//Stick the right stuff into the data
//Start by ripping off the ICMP header from the original data
	ff->dataFrame.pdu += ICMP_HEADER_SIZE;
	ff->dataFrame.pduLength -= ICMP_HEADER_SIZE;

//Get the total length of the data we're sending inside the control frame's data field
	iLen = ff->dataFrame.pduLength;

//Now create the data
	cData = (unsigned char*) malloc(iLen + sizeof(int)); //With enough room for the size at the beginning

//Stick in the size of the data
	int i;
	for (i = 0; i < sizeof(int); i++) {
		cData[i] = (iLen >> (sizeof(int) - (8 * i + 1))) & 0xFF;
	}

//Now copy this data into cData
	memcpy(&(cData[4]), ff->dataFrame.pdu, iLen);

//Now copy the name and data fields into the final finsFrame
	ffout->ctrlFrame.data_old = cData;
	ffout->ctrlFrame.name = cName;

//Done! Send out the frame
//icmp_send_FF(ffout);
}

//-----------------------------------------------------------------------------
// Create a "Destination Unreachable" ICMP message with data given from the UDP
//-----------------------------------------------------------------------------
void icmp_create_unreach(struct finsFrame* ff) {
	int totallen = 0; //How many bytes we want our ICMP message to be
	struct finsFrame* ffout; //The final "destination unreachable" finsFrame that we'll send out
	int checksum = 0;

//So this finsFrame has the IP header and UDP stuff. As per RFC 792 spec, we need the IP header + 64 bits of the UDP datagram.
//How many bytes is all this?
	totallen = (ff->dataFrame.pdu[0]) & 0x0F; //Grab the first 8 bits. Header length is in bits 4-7 of this.
	totallen *= 4; //Since this length is the number of 32-bit words in the header, we multiply by 4 to get the number of bytes
	totallen += 8 + ICMP_HEADER_SIZE; //The length we want is the length of the IP header + (64 bits = 8 bytes) + 8 byte ICMP header
//Now that we have the total length, we can create the finsFrame that has the PDU length we want

	ffout = (struct finsFrame *) malloc(sizeof(struct finsFrame)); //Allocate memory for the frame
	ffout->dataOrCtrl = DATA; //We're sending a data packet here
	ffout->destinationID.id = DAEMON_ID; //Go to the socket stub
	ffout->destinationID.next = NULL; //TODO: Still no idea what this does
	ffout->dataFrame.directionFlag = DOWN; //Out
	ffout->dataFrame.pduLength = totallen; //Make the total length correct
	ffout->dataFrame.pdu = (u_char *) malloc(totallen); //Allocate memory for the data we'll be sticking in
	metadata_create(ffout->metaData); //TODO: Right?

//I treat all the ICMP stuff as raw data, rather than encapsulating it in structs, due to working with such structs earlier this summer
//and running into a ton of little-vs-big-endian issues. Handling the raw data this way is easier for me than remembering to htons()
//everything, especially because most ICMP headers contain variably-sized data.

//Fill in the ICMP header data.
	ffout->dataFrame.pdu[0] = TYPE_DESTUNREACH; //set to destination unreachable message
	ffout->dataFrame.pdu[1] = CODE_PORTUNREACH; //MAYBE. TODO: get info about what unreachable code we should here, from the metadata.
//Clear the checksum and "unused" fields
//memset(ffout->dataFrame.pdu[2], 0, ICMP_HEADER_SIZE - 2);
	memset(&ffout->dataFrame.pdu[2], 0, ICMP_HEADER_SIZE - 2);

//Copy the rest of the data over
//memcpy(ffout->dataFrame.pdu[ICMP_HEADER_SIZE], ff->dataFrame.pdu, totallen - ICMP_HEADER_SIZE);
	memcpy(&ffout->dataFrame.pdu[ICMP_HEADER_SIZE], ff->dataFrame.pdu, totallen - ICMP_HEADER_SIZE);

//Compute the checksum
//checksum = icmp_checksum(ffout); //TODO uncomment
//And set the checksum field(s)
	ffout->dataFrame.pdu[2] = checksum >> 8;
	ffout->dataFrame.pdu[3] = (checksum & 0xFF);

//Done! Send out the frame
//icmp_send_FF(ffout);
}

void *switch_to_icmp(void *local) {
	PRINT_DEBUG("Entered");

	while (icmp_running) {
		icmp_get_ff();
		PRINT_DEBUG("");
		//Note that we always clean up the frame, no matter what we do with it. If the frame needs to go somewhere else also, we make a copy.
	}

	PRINT_DEBUG("Exited");
	pthread_exit(NULL);
}

void icmp_init(void) {
	PRINT_DEBUG("Entered");
	icmp_running = 1;

	sent_packet_list = sent_list_create(ICMP_SENT_LIST_MAX);
}

void icmp_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Entered");

	pthread_create(&switch_to_icmp_thread, fins_pthread_attr, switch_to_icmp, fins_pthread_attr);
}

void icmp_shutdown(void) {
	PRINT_DEBUG("Entered");
	icmp_running = 0;

	//TODO expand this

	pthread_join(switch_to_icmp_thread, NULL);
}

void icmp_release(void) {
	PRINT_DEBUG("Entered");

	sent_list_free(sent_packet_list);

	//TODO free all module related mem

	term_queue(ICMP_to_Switch_Queue);
	term_queue(Switch_to_ICMP_Queue);
}
