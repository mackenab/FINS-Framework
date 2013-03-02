/**
 * 	UDP test.c
 *
 *  Created on: Jun 30, 2010
 *      Author: Abdallah Abdallah
 */

//Kevin added some debugging code in this file to print out the received control frames and send back a response
//The control frames were never updated to the new types
#include "udp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <finstime.h>

#define DUMMYA 123
#define DUMMYB 456
#define DUMMYC 789

#include <switch.h>
static struct fins_proto_module udp_proto = { .module_id = UDP_ID, .name = "udp", .running_flag = 1, };

pthread_t switch_to_udp_thread;

struct udp_statistics udpStat;

struct udp_sent_list *udp_sent_packet_list;

struct udp_sent *udp_sent_create(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, host=%u/%u, rem=%u/%u", ff, ff->metaData, host_ip, host_port, rem_ip, rem_port);

	struct udp_sent *sent = (struct udp_sent *) secure_malloc(sizeof(struct udp_sent));
	sent->next = NULL;

	sent->ff = ff;
	sent->host_ip = host_ip;
	sent->host_port = host_port;
	sent->rem_ip = rem_ip;
	sent->rem_port = rem_port;

	memset(&sent->stamp, 0, sizeof(struct timeval));

	PRINT_DEBUG("Exited: ff=%p, sent=%p", ff, sent);
	return sent;
}

void udp_sent_free(struct udp_sent *sent) {
	PRINT_DEBUG("Entered: sent=%p", sent);

	if (sent->ff) {
		freeFinsFrame(sent->ff);
	}

	free(sent);
}

struct udp_sent_list *udp_sent_list_create(uint32_t max) {
	PRINT_DEBUG("Entered: max=%u", max);

	struct udp_sent_list *sent_list = (struct udp_sent_list *) secure_malloc(sizeof(struct udp_sent_list));
	sent_list->max = max;
	sent_list->len = 0;

	sent_list->front = NULL;
	sent_list->end = NULL;

	PRINT_DEBUG("Exited: max=%u, sent_list=%p", max, sent_list);
	return sent_list;
}

void udp_sent_list_append(struct udp_sent_list *sent_list, struct udp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	sent->next = NULL;
	if (udp_sent_list_is_empty(sent_list)) {
		//queue empty
		sent_list->front = sent;
	} else {
		//node after end
		sent_list->end->next = sent;
	}
	sent_list->end = sent;
	sent_list->len++;
}

struct udp_sent *udp_sent_list_find(struct udp_sent_list *sent_list, uint8_t *data, uint32_t data_len) {
	PRINT_DEBUG("Entered: sent_list=%p, data=%p, data_len=%u", sent_list, data, data_len);

	struct udp_sent *sent = sent_list->front;

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

struct udp_sent *udp_sent_list_remove_front(struct udp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct udp_sent *sent = sent_list->front;
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

void udp_sent_list_remove(struct udp_sent_list *sent_list, struct udp_sent *sent) {
	PRINT_DEBUG("Entered: sent_list=%p, sent=%p", sent_list, sent);

	if (udp_sent_list_is_empty(sent_list)) {
		return;
	}

	if (sent_list->front == sent) {
		sent_list->front = sent_list->front->next;
		sent_list->len--;
		return;
	}

	struct udp_sent *temp = sent_list->front;
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

int udp_sent_list_is_empty(struct udp_sent_list *sent_list) {
	return sent_list->len == 0;
}

int udp_sent_list_has_space(struct udp_sent_list *sent_list) {
	return sent_list->len < sent_list->max;
}

void udp_sent_list_free(struct udp_sent_list *sent_list) {
	PRINT_DEBUG("Entered: sent_list=%p", sent_list);

	struct udp_sent *sent;
	while (!udp_sent_list_is_empty(sent_list)) {
		sent = udp_sent_list_remove_front(sent_list);
		udp_sent_free(sent);
	}

	free(sent_list);
}

void udp_sent_list_gc(struct udp_sent_list *sent_list, double timeout) {
	PRINT_DEBUG("Entered");

	struct timeval current;
	gettimeofday(&current, 0);

	struct udp_sent *old;

	struct udp_sent *temp = sent_list->front;
	while (temp) {
		if (time_diff(&temp->stamp, &current) >= timeout) {
			old = temp;
			temp = temp->next;

			udp_sent_list_remove(sent_list, old);
			udp_sent_free(old);
		} else {
			temp = temp->next;
		}
	}
}

int udp_to_switch(struct finsFrame *ff) {
	return module_to_switch(&udp_proto, ff);
}

void udp_get_ff(void) {

	struct finsFrame *ff;
	do {
		secure_sem_wait(udp_proto.event_sem);
		secure_sem_wait(udp_proto.input_sem);
		ff = read_queue(udp_proto.input_queue);
		sem_post(udp_proto.input_sem);
	} while (udp_proto.running_flag && ff == NULL);

	if (!udp_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	udpStat.totalRecieved++;
	PRINT_DEBUG("UDP Total %d, ff=%p, meta=%p", udpStat.totalRecieved, ff, ff->metaData);
	if (ff->dataOrCtrl == CONTROL) {
		udp_fcf(ff);
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			udp_in_fdf(ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			udp_out_fdf(ff);
			PRINT_DEBUG("");
		}
	} else {
		PRINT_ERROR("todo error");
	}
}

void udp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		//daemon_read_param_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		//daemon_set_param_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		udp_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		//daemon_exec_reply(ff);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		udp_error(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void udp_exec(struct finsFrame *ff) {
	uint32_t host_ip = 0;
	uint32_t host_port = 0;
	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;

	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	metadata *meta = ff->metaData;
	switch (ff->ctrlFrame.param_id) {
	case EXEC_UDP_CLEAR_SENT:
		PRINT_DEBUG("param_id=EXEC_UDP_CLEAR_SENT (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(meta, "host_ip", &host_ip);
		secure_metadata_readFromElement(meta, "host_port", &host_port);
		secure_metadata_readFromElement(meta, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(meta, "rem_port", &rem_port);

		udp_exec_clear_sent(ff, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?

		ff->destinationID.id = ff->ctrlFrame.senderID;

		ff->ctrlFrame.senderID = UDP_ID;
		ff->ctrlFrame.opcode = CTRL_EXEC_REPLY;
		ff->ctrlFrame.ret_val = 0;

		udp_to_switch(ff);
		break;
	}
}

void udp_exec_clear_sent(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: ff=%p, host=%u/%u, rem=%u/%u", ff, host_ip, host_port, rem_ip, rem_port);
	if (!udp_sent_list_is_empty(udp_sent_packet_list)) {
		struct udp_sent *old;

		struct udp_sent *temp = udp_sent_packet_list->front;
		while (temp) {
			if (temp->host_ip == host_ip && temp->host_port == host_port) {
				old = temp;
				temp = temp->next;

				udp_sent_list_remove(udp_sent_packet_list, old);
				udp_sent_free(old);
			} else {
				temp = temp->next;
			}
		}
	}

	freeFinsFrame(ff);
}

struct udp_header_frag {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t data[1];
};

void udp_error(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//uint32_t src_ip;
	//uint32_t src_port;
	//uint32_t dst_ip;
	//uint32_t dst_port;

	//uint32_t udp_len;
	//uint32_t checksum;

	//metadata *meta = ff->metaData;
	switch (ff->ctrlFrame.param_id) {
	case ERROR_ICMP_TTL:
		PRINT_DEBUG("param_id=ERROR_ICMP_TTL (%d)", ff->ctrlFrame.param_id);

		/*
		 struct udp_packet *udp_hdr = (struct udp_packet *) ff->ctrlFrame.data;
		 struct udp_header hdr;

		 hdr.u_src = ntohs(udp_hdr->u_src);
		 hdr.u_dst = ntohs(udp_hdr->u_dst);
		 hdr.u_len = ntohs(udp_hdr->u_len);
		 hdr.u_cksum = ntohs(udp_hdr->u_cksum);
		 */

		//if recv_dst_ip==send_src_ip, recv_dst_port==send_src_port, recv_udp_len==, recv_checksum==,  \\should be unique!

		if (udp_sent_list_is_empty(udp_sent_packet_list)) {
			PRINT_ERROR("todo error");
			//TODO drop
			freeFinsFrame(ff);
		} else {
			uint8_t *data = ff->ctrlFrame.data;
			if (data) {
				struct udp_sent *sent = udp_sent_list_find(udp_sent_packet_list, data, ff->ctrlFrame.data_len);
				if (sent) {
					metadata_copy(sent->ff->metaData, ff->metaData);

					//ff->dataOrCtrl = CONTROL;
					ff->destinationID.id = DAEMON_ID;
					ff->destinationID.next = NULL;
					//ff->metaData = meta_err;

					ff->ctrlFrame.senderID = UDP_ID;
					//ff->ctrlFrame.serial_num = gen_control_serial_num();
					//ff->ctrlFrame.opcode = CTRL_ERROR;
					//ff->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code //ERROR_UDP_TTL?

					ff->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
					ff->ctrlFrame.data = sent->ff->dataFrame.pdu;
					sent->ff->dataFrame.pdu = NULL;

					udp_to_switch(ff);

					udp_sent_list_remove(udp_sent_packet_list, sent);
					udp_sent_free(sent);
					free(data);
				} else {
					PRINT_ERROR("todo error");
					freeFinsFrame(ff);
					//TODO drop?
				}
			} else {
				PRINT_ERROR("todo");
				freeFinsFrame(ff);
			}
		}
		break;
	case ERROR_ICMP_DEST_UNREACH:
		PRINT_DEBUG("param_id=ERROR_ICMP_DEST_UNREACH (%d)", ff->ctrlFrame.param_id);

		if (udp_sent_list_is_empty(udp_sent_packet_list)) {
			PRINT_ERROR("todo error");
			//TODO drop
			freeFinsFrame(ff);
		} else {
			uint8_t *data = ff->ctrlFrame.data;
			if (data) {
				struct udp_sent *sent = udp_sent_list_find(udp_sent_packet_list, data, ff->ctrlFrame.data_len);
				if (sent) {
					metadata_copy(sent->ff->metaData, ff->metaData);

					//ff->dataOrCtrl = CONTROL;
					ff->destinationID.id = DAEMON_ID;
					ff->destinationID.next = NULL;
					//ff->metaData = meta_err;

					ff->ctrlFrame.senderID = UDP_ID;
					//ff->ctrlFrame.serial_num = gen_control_serial_num();
					//ff->ctrlFrame.opcode = CTRL_ERROR;
					//ff->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code //ERROR_UDP_TTL?

					ff->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
					ff->ctrlFrame.data = sent->ff->dataFrame.pdu;
					sent->ff->dataFrame.pdu = NULL;

					udp_to_switch(ff);

					udp_sent_list_remove(udp_sent_packet_list, sent);
					udp_sent_free(sent);
					free(data);
				} else {
					PRINT_ERROR("todo error");
					//TODO drop?
					freeFinsFrame(ff);
				}
			} else {
				PRINT_ERROR("todo");
				freeFinsFrame(ff);
			}
		}
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		//TODO implement?
		freeFinsFrame(ff);
		break;
	}
}

void *switch_to_udp(void *local) {
	PRINT_IMPORTANT("Entered");

	while (udp_proto.running_flag) {
		udp_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited");
	//pthread_exit(NULL);
	return NULL;
}

void udp_dummy(void) {

}

void udp_init(void) {
	PRINT_IMPORTANT("Entered");
	udp_proto.running_flag = 1;

	module_create_ops(&udp_proto);
	module_register(&udp_proto);

	udp_sent_packet_list = udp_sent_list_create(UDP_SENT_LIST_MAX);
}

void udp_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_IMPORTANT("Entered");

	secure_pthread_create(&switch_to_udp_thread, fins_pthread_attr, switch_to_udp, fins_pthread_attr);
}

void udp_shutdown(void) {
	PRINT_IMPORTANT("Entered");
	udp_proto.running_flag = 0;
	sem_post(udp_proto.event_sem);

	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_udp_thread");
	pthread_join(switch_to_udp_thread, NULL);
}

void udp_release(void) {
	PRINT_IMPORTANT("Entered");
	module_unregister(udp_proto.module_id);

	PRINT_IMPORTANT("udp_sent_packet_list->len=%u", udp_sent_packet_list->len);
	udp_sent_list_free(udp_sent_packet_list);

	//TODO free all module related mem

	module_destroy_ops(&udp_proto);
}
