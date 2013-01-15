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
#include <finstime.h>

#include <switch.h>
static struct fins_proto_module icmp_proto = { .module_id = ICMP_ID, .name = "icmp", .running_flag = 1, };

pthread_t switch_to_icmp_thread;

struct icmp_sent_list *icmp_sent_packet_list;

struct icmp_sent *icmp_sent_create(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	struct icmp_sent *sent = (struct icmp_sent *) malloc(sizeof(struct icmp_sent));
	if (sent == NULL) {
		PRINT_ERROR("icmp_sent alloc fail");
		exit(-1);
	}

	sent->next = NULL;

	sent->ff = ff;

	memset(&sent->stamp, 0, sizeof(struct timeval));

	PRINT_DEBUG("Exited: ff=%p, sent=%p", ff, sent);
	return sent;
}

void icmp_sent_free(struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent=%p", sent);

	if (sent->ff) {
		freeFinsFrame(sent->ff);
	}

	free(sent);
}

struct icmp_sent_list *icmp_sent_list_create(uint32_t max) {
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

	PRINT_DEBUG("Exited: max=%u, sent_list=%p", max, sent_list);
	return sent_list;
}

void icmp_sent_list_append(struct icmp_sent_list *sent_list, struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	sent->next = NULL;
	if (icmp_sent_list_is_empty(sent_list)) {
		//queue empty
		sent_list->front = sent;
	} else {
		//node after end
		sent_list->end->next = sent;
	}
	sent_list->end = sent;
	sent_list->len++;
}

struct icmp_sent *icmp_sent_list_find(struct icmp_sent_list *sent_list, uint8_t *data, uint32_t data_len) {
	PRINT_DEBUG("Entered: sent_list=%p, data=%p, data_len=%u", sent_list, data, data_len);

	struct icmp_sent *sent = sent_list->front;

	while (sent != NULL) {
		if (sent->ff && sent->ff->dataOrCtrl == DATA && sent->ff->dataFrame.pdu) {
			PRINT_DEBUG("ff=%p, meta=%p, pduLen=%u, pdu=%p", sent->ff, sent->ff->metaData, sent->ff->dataFrame.pduLength, sent->ff->dataFrame.pdu);
			if (sent->ff->dataFrame.pduLength >= data_len) { //TODO check if this logic is sound
				if (strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, data_len) == 0) {
					break;
				}
			} else {
				if (strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, sent->ff->dataFrame.pduLength) == 0) {
					break;
				}
			}
		} else {
			if (sent->ff) {
				if (sent->ff->dataOrCtrl == DATA) {
					PRINT_ERROR("todo error, ff=%p, meta=%p, pdu=%p", sent->ff, sent->ff->metaData, sent->ff->dataFrame.pdu);
				} else {
					PRINT_ERROR("todo error, ff=%p, meta=%p, CONTROL", sent->ff, sent->ff->metaData);
				}
			} else {
				PRINT_ERROR("todo error, ff=%p", sent->ff);
			}
		}
		sent = sent->next;
	}

	PRINT_DEBUG("Exited: sent_list=%p, data=%p, data_len=%u, sent=%p", sent_list, data, data_len, sent);
	return sent;
}

struct icmp_sent *icmp_sent_list_remove_front(struct icmp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct icmp_sent *sent = sent_list->front;
	if (sent) {
		sent_list->front = sent->next;
		sent_list->len--;
	} else {
		PRINT_ERROR("reseting len: len=%d", sent_list->len);
		sent_list->len = 0;
	}

	PRINT_DEBUG("Exited: sent_list=%p, sent=%p", sent_list, sent);
	return sent;
}

void icmp_sent_list_remove(struct icmp_sent_list *sent_list, struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	if (icmp_sent_list_is_empty(sent_list)) {
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

int icmp_sent_list_is_empty(struct icmp_sent_list *sent_list) {
	return sent_list->len == 0;
}

int icmp_sent_list_has_space(struct icmp_sent_list *sent_list) {
	return sent_list->len < sent_list->max;
}

void icmp_sent_list_free(struct icmp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct icmp_sent *sent;
	while (!icmp_sent_list_is_empty(sent_list)) {
		sent = icmp_sent_list_remove_front(sent_list);
		icmp_sent_free(sent);
	}

	free(sent_list);
}

void icmp_in_fdf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	struct ip4_packet *ipv4_pkt = (struct ip4_packet *) ff->dataFrame.pdu;
	uint16_t ipv4_len = ntohs(ipv4_pkt->ip_len);

	struct icmp_packet *icmp_pkt = (struct icmp_packet *) ipv4_pkt->ip_data;
	uint32_t icmp_len = ipv4_len - IP4_HLEN(ipv4_pkt);

	PRINT_DEBUG("pdu_len=%u, ipv4_len=%u, icmp_len=%u, hlen=%u", ff->dataFrame.pduLength, ipv4_len, icmp_len, IP4_HLEN(ipv4_pkt));

	if (icmp_len < ICMP_HEADER_SIZE) {
		PRINT_DEBUG("packet too small: icmp_len=%u, icmp_req=%u", icmp_len, ICMP_HEADER_SIZE);

		freeFinsFrame(ff);
		return;
	}

	metadata *params = ff->metaData;
	if (params == NULL) {
		PRINT_ERROR("todo error");

		freeFinsFrame(ff);
		return;
	}

	uint32_t protocol;

	int ret = 0;
	ret += metadata_readFromElement(params, "recv_protocol", &protocol) == META_FALSE;
	if (ret) {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		return;
	}

	if (protocol != ICMP_PROTOCOL) { //TODO remove this check?
		PRINT_ERROR("Protocol =/= ICMP! Discarding frame...");
		freeFinsFrame(ff);
		return;
	}

	if (icmp_pkt->checksum == 0) {
		PRINT_DEBUG("checksum==0");
	} else {
		if (icmp_checksum(ipv4_pkt->ip_data, icmp_len) != 0) {
			PRINT_ERROR("Error in checksum of packet. Discarding...");
			freeFinsFrame(ff);
			return;
		} else {

		}
	}

	uint32_t data_len = icmp_len - ICMP_HEADER_SIZE;

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
			freeFinsFrame(ff);
		}
		break;
	case TYPE_DESTUNREACH:
		PRINT_DEBUG("Destination unreachable")
		;
		if (icmp_pkt->code == CODE_NETUNREACH) {
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_HOSTUNREACH) {
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_PROTOUNREACH) {
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_PORTUNREACH) {
			if (data_len < IP4_MIN_HLEN) {
				PRINT_ERROR("data too small: data_len=%u, ipv4_req=%u", data_len, IP4_MIN_HLEN);
				//stats.badhlen++;
				//stats.droppedtotal++;
				freeFinsFrame(ff);
				return;
			}

			struct ip4_packet *ipv4_pkt_sent = (struct ip4_packet *) icmp_pkt->data;
			uint16_t sent_data_len = data_len - IP4_HLEN(ipv4_pkt_sent);

			uint32_t type = icmp_pkt->type;
			metadata_writeToElement(params, "recv_icmp_type", &type, META_TYPE_INT32);
			uint32_t code = icmp_pkt->code;
			metadata_writeToElement(params, "recv_icmp_code", &code, META_TYPE_INT32);

			uint32_t src_port;
			uint32_t dst_port;
			metadata *params_err;
			struct finsFrame *ff_err;

			PRINT_DEBUG("sent: proto=%u, data_len=%u", ipv4_pkt_sent->ip_proto, sent_data_len);
			switch (ipv4_pkt_sent->ip_proto) {
			case ICMP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < ICMP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, ICMP_FRAG_SIZE);
					freeFinsFrame(ff);
					return;
				}

				if (icmp_sent_list_is_empty(icmp_sent_packet_list)) {
					PRINT_ERROR("todo error");
					//TODO drop
				} else {
					struct icmp_sent *sent = icmp_sent_list_find(icmp_sent_packet_list, ipv4_pkt_sent->ip_data, sent_data_len);
					if (sent) {
						metadata *params_err = sent->ff->metaData;
						metadata_copy(params, params_err);

						ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
						if (ff_err == NULL) {
							PRINT_ERROR("ff_err alloc error");
							exit(-1);
						}

						ff_err->dataOrCtrl = CONTROL;
						ff_err->destinationID.id = DAEMON_ID;
						ff_err->destinationID.next = NULL;
						ff_err->metaData = params_err;
						sent->ff->metaData = NULL;

						ff_err->ctrlFrame.senderID = ICMP_ID;
						ff_err->ctrlFrame.serial_num = gen_control_serial_num();
						ff_err->ctrlFrame.opcode = CTRL_ERROR;
						ff_err->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code

						ff_err->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
						ff_err->ctrlFrame.data = sent->ff->dataFrame.pdu;
						sent->ff->dataFrame.pdu = NULL;

						icmp_to_switch(ff_err);

						icmp_sent_list_remove(icmp_sent_packet_list, sent);
						icmp_sent_free(sent);
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
					freeFinsFrame(ff);
					return;
				}

				params_err = params;
				ff->metaData = NULL;

				struct tcp_header_frag *tcp_hdr = (struct tcp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(tcp_hdr->src_port);
				dst_port = ntohs(tcp_hdr->dst_port);
				uint32_t seq_num = ntohl(tcp_hdr->seq_num);

				//TODO src/dst_ip should already be in from IPv4 mod
				metadata_writeToElement(params_err, "recv_src_port", &src_port, META_TYPE_INT32); //TODO figure out if recv_, send_, or what
				metadata_writeToElement(params_err, "recv_dst_port", &dst_port, META_TYPE_INT32);
				metadata_writeToElement(params_err, "recv_seq_num", &seq_num, META_TYPE_INT32);

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

				ff_err->ctrlFrame.data_len = sent_data_len;
				ff_err->ctrlFrame.data = (uint8_t *) malloc(ff_err->ctrlFrame.data_len);
				if (ff_err->ctrlFrame.data == NULL) {
					PRINT_ERROR("data alloc error");
					exit(-1);
				}
				memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

				icmp_to_switch(ff_err);
				break;
			case UDP_PROTOCOL:
				//cast first 8 bytes of ip->data to udp frag, store in metadata
				if (sent_data_len < UDP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);
					freeFinsFrame(ff);
					return;
				}

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = UDP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params;
				ff->metaData = NULL;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code

				ff_err->ctrlFrame.data_len = sent_data_len;
				ff_err->ctrlFrame.data = (uint8_t *) malloc(ff_err->ctrlFrame.data_len);
				if (ff_err->ctrlFrame.data == NULL) {
					PRINT_ERROR("data alloc error");
					exit(-1);
				}
				memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

				icmp_to_switch(ff_err);
				break;
			default:
				PRINT_ERROR("todo error")
				;
				break;
			}
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_FRAGNEEDED) {
			PRINT_ERROR("todo");

			//TODO use icmp_pkt->param_2 as Next-Hop MTU
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_SRCROUTEFAIL) {
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("Unrecognized code. Dropping...");
			freeFinsFrame(ff);
			return;
		}
		break;
	case TYPE_ECHOREQUEST:
		if (icmp_pkt->code == CODE_ECHO) {
			//Create an echo reply packet and send it out
			icmp_ping_reply(ff, icmp_pkt, data_len);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			freeFinsFrame(ff);
		}
		break;
	case TYPE_TTLEXCEED:
		PRINT_DEBUG("TTL Exceeded")
		;
		if (icmp_pkt->code == CODE_TTLEXCEEDED) {
			if (data_len < IP4_MIN_HLEN) {
				PRINT_ERROR("data too small: data_len=%u, ipv4_req=%u", data_len, IP4_MIN_HLEN);
				//stats.badhlen++;
				//stats.droppedtotal++;
				freeFinsFrame(ff);
				return;
			}

			struct ip4_packet *ipv4_pkt_sent = (struct ip4_packet *) icmp_pkt->data;
			uint16_t sent_data_len = data_len - IP4_HLEN(ipv4_pkt_sent);

			uint32_t type = icmp_pkt->type;
			metadata_writeToElement(params, "recv_icmp_type", &type, META_TYPE_INT32);
			uint32_t code = icmp_pkt->code;
			metadata_writeToElement(params, "recv_icmp_code", &code, META_TYPE_INT32);

			uint32_t src_port;
			uint32_t dst_port;
			metadata *params_err;
			struct finsFrame *ff_err;

			PRINT_DEBUG("sent: proto=%u, data_len=%u", ipv4_pkt_sent->ip_proto, sent_data_len);
			switch (ipv4_pkt_sent->ip_proto) {
			case ICMP_PROTOCOL:
				//cast first 8 bytes of ip->data to TCP frag, store in metadata
				if (sent_data_len < ICMP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, ICMP_FRAG_SIZE);
					freeFinsFrame(ff);
					return;
				}

				if (icmp_sent_list_is_empty(icmp_sent_packet_list)) {
					PRINT_ERROR("todo error");
					//TODO drop
				} else {
					struct icmp_sent *sent = icmp_sent_list_find(icmp_sent_packet_list, ipv4_pkt_sent->ip_data, sent_data_len);
					if (sent) {
						metadata *params_err = sent->ff->metaData;
						metadata_copy(params, params_err);

						ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
						if (ff_err == NULL) {
							PRINT_ERROR("ff_err alloc error");
							exit(-1);
						}

						ff_err->dataOrCtrl = CONTROL;
						ff_err->destinationID.id = DAEMON_ID;
						ff_err->destinationID.next = NULL;
						ff_err->metaData = params_err;
						sent->ff->metaData = NULL;

						ff_err->ctrlFrame.senderID = ICMP_ID;
						ff_err->ctrlFrame.serial_num = gen_control_serial_num();
						ff_err->ctrlFrame.opcode = CTRL_ERROR;
						ff_err->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code

						ff_err->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
						ff_err->ctrlFrame.data = sent->ff->dataFrame.pdu;
						sent->ff->dataFrame.pdu = NULL;

						icmp_to_switch(ff_err);

						icmp_sent_list_remove(icmp_sent_packet_list, sent);
						icmp_sent_free(sent);
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
					freeFinsFrame(ff);
					return;
				}

				params_err = params;
				ff->metaData = NULL;

				struct tcp_header_frag *tcp_hdr = (struct tcp_header_frag *) ipv4_pkt_sent->ip_data;
				src_port = ntohs(tcp_hdr->src_port);
				dst_port = ntohs(tcp_hdr->dst_port);
				uint32_t seq_num = ntohl(tcp_hdr->seq_num);

				//TODO src/dst_ip should already be in from IPv4 mod
				metadata_writeToElement(params_err, "recv_src_port", &src_port, META_TYPE_INT32); //TODO figure out if recv_, send_, or what
				metadata_writeToElement(params_err, "recv_dst_port", &dst_port, META_TYPE_INT32);
				metadata_writeToElement(params_err, "recv_seq_num", &seq_num, META_TYPE_INT32);
				//TODO err_src_ip/port, recv_ttl, stamp

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

				ff_err->ctrlFrame.data_len = sent_data_len;
				ff_err->ctrlFrame.data = (uint8_t *) malloc(ff_err->ctrlFrame.data_len);
				if (ff_err->ctrlFrame.data == NULL) {
					PRINT_ERROR("data alloc error");
					exit(-1);
				}
				memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

				icmp_to_switch(ff_err);
				break;
			case UDP_PROTOCOL:
				//cast first 8 bytes of ip->data to udp frag, store in metadata
				if (sent_data_len < UDP_FRAG_SIZE) {
					PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);
					freeFinsFrame(ff);
					return;
				}

				ff_err = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_err == NULL) {
					PRINT_ERROR("ff_err alloc error");
					exit(-1);
				}

				ff_err->dataOrCtrl = CONTROL;
				ff_err->destinationID.id = UDP_ID;
				ff_err->destinationID.next = NULL;
				ff_err->metaData = params;
				ff->metaData = NULL;

				ff_err->ctrlFrame.senderID = ICMP_ID;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code

				ff_err->ctrlFrame.data_len = sent_data_len;
				ff_err->ctrlFrame.data = (uint8_t *) malloc(ff_err->ctrlFrame.data_len);
				if (ff_err->ctrlFrame.data == NULL) {
					PRINT_ERROR("data alloc error");
					exit(-1);
				}
				memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

				icmp_to_switch(ff_err);
				break;
			default:
				PRINT_ERROR("todo error")
				;
				break;
			}
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_DEFRAGTIMEEXCEEDED) {
			PRINT_ERROR("todo");
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_DEBUG("default: type=%u", icmp_pkt->type)
		;
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

void icmp_sent_list_gc(struct icmp_sent_list *sent_list, double timeout) {
	PRINT_DEBUG("Entered");

	struct timeval current;
	gettimeofday(&current, 0);

	struct icmp_sent *old;

	struct icmp_sent *temp = sent_list->front;
	while (temp) {
		if (time_diff(&temp->stamp, &current) >= timeout) {
			old = temp;
			temp = temp->next;

			icmp_sent_list_remove(sent_list, old);
			icmp_sent_free(old);
		} else {
			temp = temp->next;
		}
	}
}

void icmp_out_fdf(struct finsFrame *ff) {
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
	ret += metadata_readFromElement(params, "send_src_ip", &src_ip) == META_FALSE;
	ret += metadata_readFromElement(params, "send_dst_ip", &dst_ip) == META_FALSE;

	if (ret) {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		return;
	}

	uint32_t protocol = ICMP_PROTOCOL;
	metadata_writeToElement(params, "send_protocol", &protocol, META_TYPE_INT32);
	//metadata_writeToElement(params, "src_ip", &src_ip, META_TYPE_INT32);
	//metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT32);

	//struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	//ff->dataOrCtrl = DATA;
	ff->destinationID.id = IPV4_ID; // destination module ID
	ff->destinationID.next = NULL;
	//ff->metaData = params;

	//ff->dataFrame.directionFlag = DOWN; // ingress or egress network data; see above
	//ff->dataFrame.pduLength = data_len; //Add in the header size for this, too
	//ff->dataFrame.pdu = (uint8_t *) malloc(ff->dataFrame.pduLength);

	struct finsFrame *ff_clone = cloneFinsFrame(ff);

	if (icmp_to_switch(ff)) {
		struct icmp_sent *sent = icmp_sent_create(ff_clone);

		if (icmp_sent_list_has_space(icmp_sent_packet_list)) {
			icmp_sent_list_append(icmp_sent_packet_list, sent);
			PRINT_DEBUG("sent_packet_list=%p, len=%u, max=%u", icmp_sent_packet_list, icmp_sent_packet_list->len, icmp_sent_packet_list->max)

			gettimeofday(&sent->stamp, 0);
		} else {
			PRINT_DEBUG("Clearing sent_packet_list");
			icmp_sent_list_gc(icmp_sent_packet_list, ICMP_MSL_TO_DEFAULT);

			if (icmp_sent_list_has_space(icmp_sent_packet_list)) {
				icmp_sent_list_append(icmp_sent_packet_list, sent);
				PRINT_DEBUG("sent_packet_list=%p, len=%u, max=%u", icmp_sent_packet_list, icmp_sent_packet_list->len, icmp_sent_packet_list->max)

				gettimeofday(&sent->stamp, 0);
			} else {
				PRINT_ERROR("todo error");
				icmp_sent_free(sent);
			}
		}
	} else {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff_clone);
		freeFinsFrame(ff);
	}
}

void icmp_get_ff(void) {
	struct finsFrame *ff;

	do {
		sem_wait(icmp_proto.event_sem);
		sem_wait(icmp_proto.input_sem);
		ff = read_queue(icmp_proto.input_queue);
		sem_post(icmp_proto.input_sem);
	} while (icmp_proto.running_flag && ff == NULL);

	if (!icmp_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->dataOrCtrl == CONTROL) { // send to the control frame handler
		icmp_fcf(ff);
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == UP) { //Incoming ICMP packet (coming in from teh internets)
			icmp_in_fdf(ff);
		} else if (ff->dataFrame.directionFlag == DOWN) { //Outgoing ICMP packet (going out from us to teh internets)
			icmp_out_fdf(ff);
		}
	} else {
		PRINT_ERROR("todo error");
	}
}

int icmp_to_switch(struct finsFrame *ff) {
	return module_to_switch(&icmp_proto, ff);
}

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

	PRINT_DEBUG("checksum=0x%x", (uint16_t) sum);
	return (uint16_t) sum;
}

void icmp_ping_reply(struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);

	uint32_t pdu_len_reply = data_len + ICMP_HEADER_SIZE;
	uint8_t *pdu_reply = (uint8_t *) malloc(pdu_len_reply);
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
	ret += metadata_readFromElement(params, "recv_src_ip", &src_ip) == META_FALSE;
	ret += metadata_readFromElement(params, "recv_dst_ip", &dst_ip) == META_FALSE;
	if (ret) {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		return;
	}

	metadata *params_reply = (metadata *) malloc(sizeof(metadata));
	if (params_reply == NULL) {
		PRINT_ERROR("failed to create matadata: ff=%p", ff);
		exit(-1);
	}
	metadata_create(params_reply);

	uint32_t protocol = ICMP_PROTOCOL;
	metadata_writeToElement(params_reply, "send_protocol", &protocol, META_TYPE_INT32);
	metadata_writeToElement(params_reply, "send_src_ip", &dst_ip, META_TYPE_INT32);
	metadata_writeToElement(params_reply, "send_dst_ip", &src_ip, META_TYPE_INT32);

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

	freeFinsFrame(ff);
}

void icmp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT)
		;
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY)
		;
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM)
		;
		//arp_read_param(ff);
		//TODO read interface_mac?
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY)
		;
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM)
		;
		//arp_set_param(ff);
		//TODO set interface_mac?
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY)
		;
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC)
		;
		//arp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY)
		;
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR)
		;
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode)
		;
		break;
	}
}

void *switch_to_icmp(void *local) {
	PRINT_DEBUG("Entered");

	while (icmp_proto.running_flag) {
		icmp_get_ff();
		PRINT_DEBUG("");
		//Note that we always clean up the frame, no matter what we do with it. If the frame needs to go somewhere else also, we make a copy.
	}

	PRINT_DEBUG("Exited");
	pthread_exit(NULL);
}

void icmp_init(void) {
	PRINT_CRITICAL("Entered");
	icmp_proto.running_flag = 1;

	module_create_ops(&icmp_proto);
	module_register(&icmp_proto);

	icmp_sent_packet_list = icmp_sent_list_create(ICMP_SENT_LIST_MAX);
}

void icmp_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	pthread_create(&switch_to_icmp_thread, fins_pthread_attr, switch_to_icmp, fins_pthread_attr);
}

void icmp_shutdown(void) {
	PRINT_CRITICAL("Entered");
	icmp_proto.running_flag = 0;
	sem_post(icmp_proto.event_sem);

	//TODO expand this

	PRINT_CRITICAL("Joining switch_to_icmp_thread");
	pthread_join(switch_to_icmp_thread, NULL);
}

void icmp_release(void) {
	PRINT_CRITICAL("Entered");
	module_unregister(icmp_proto.module_id);

	icmp_sent_list_free(icmp_sent_packet_list);

	//TODO free all module related mem

	module_destroy_ops(&icmp_proto);
}
