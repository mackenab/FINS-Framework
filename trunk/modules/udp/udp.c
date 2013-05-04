/**
 * 	UDP test.c
 *
 *  Created on: Jun 30, 2010
 *      Author: Abdallah Abdallah
 */

#include "udp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include <finstime.h>

struct udp_sent *udp_sent_create(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p, host=%u/%u, rem=%u/%u", ff, ff->metaData, host_ip, host_port, rem_ip, rem_port);

	struct udp_sent *sent = (struct udp_sent *) secure_malloc(sizeof(struct udp_sent));
	sent->ff = ff;
	sent->host_ip = host_ip;
	sent->host_port = host_port;
	sent->rem_ip = rem_ip;
	sent->rem_port = rem_port;

	PRINT_DEBUG("Exited: ff=%p, sent=%p", ff, sent);
	return sent;
}

int udp_sent_host_test(struct udp_sent *sent, uint32_t *host_ip, uint16_t *host_port) {
	return sent->host_ip == *host_ip && sent->host_port == *host_port;
}

int udp_sent_data_test(struct udp_sent *sent, uint8_t *data, uint32_t *data_len) {
	if (sent->ff->dataFrame.pduLength >= *data_len) { //TODO check if this logic is sound
		return strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, *data_len) == 0;
	} else {
		return strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, sent->ff->dataFrame.pduLength) == 0;
	}
}

void udp_sent_free(struct udp_sent *sent) {
	PRINT_DEBUG("Entered: sent=%p", sent);

	if (sent->ff != NULL) {
		freeFinsFrame(sent->ff);
	}

	free(sent);
}

/*
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
 */

void *switch_to_udp(void *local) {
	struct fins_module *module = (struct fins_module *) local;

	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		udp_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void udp_get_ff(struct fins_module *module) {
	struct udp_data *md = (struct udp_data *) module->data;

	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL); //TODO change logic here, combine with switch_to_logger?

	if (module->state != FMS_RUNNING) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	md->udpStat.totalRecieved++;
	PRINT_DEBUG("UDP Total %d, ff=%p, meta=%p", md->udpStat.totalRecieved, ff, ff->metaData);
	if (ff->dataOrCtrl == FF_CONTROL) {
		udp_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) {
			udp_in_fdf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			udp_out_fdf(module, ff);
			PRINT_DEBUG("");
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else {
		PRINT_ERROR("todo error: dataOrCtrl=%u", ff->dataOrCtrl);
		exit(-1);
	}
}

void udp_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		PRINT_ERROR("todo");
		module_reply_fcf(module, ff, 0, 0);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		udp_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		//daemon_read_param_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		udp_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		udp_exec(module, ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		udp_error(module, ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void udp_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_ERROR("todo");
	module_reply_fcf(module, ff, 0, 0);
}

void udp_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case MOD_SET_PARAM_FLOWS:
		PRINT_DEBUG("PARAM_FLOWS");
		module_set_param_flows(module, ff);
		break;
	case MOD_SET_PARAM_LINKS:
		PRINT_DEBUG("PARAM_LINKS");
		module_set_param_links(module, ff);
		break;
	case MOD_SET_PARAM_DUAL:
		PRINT_DEBUG("PARAM_DUAL");
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		module_reply_fcf(module, ff, 0, 0);
		break;
	}
}

void udp_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	uint32_t host_ip = 0;
	uint32_t host_port = 0;
	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;

	metadata *meta = ff->metaData;
	switch (ff->ctrlFrame.param_id) {
	case EXEC_UDP_CLEAR_SENT:
		PRINT_DEBUG("param_id=EXEC_UDP_CLEAR_SENT (%d)", ff->ctrlFrame.param_id);

		secure_metadata_readFromElement(meta, "host_ip", &host_ip);
		secure_metadata_readFromElement(meta, "host_port", &host_port);
		secure_metadata_readFromElement(meta, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(meta, "rem_port", &rem_port);

		udp_exec_clear_sent(module, ff, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		module_reply_fcf(module, ff, 0, 0);
		break;
	}
}

void udp_exec_clear_sent(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, host=%u/%u, rem=%u/%u", module, ff, host_ip, host_port, rem_ip, rem_port);
	struct udp_data *md = (struct udp_data *) module->data;

	if (!list_is_empty(md->sent_packet_list)) {
		struct linked_list *old_list = list_remove_all2(md->sent_packet_list, udp_sent_host_test, &host_ip, &host_port);
		list_free(old_list, udp_sent_free);
	}

	freeFinsFrame(ff);
}

void udp_error(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct udp_data *md = (struct udp_data *) module->data;

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
		if (list_is_empty(md->sent_packet_list)) {
			PRINT_ERROR("todo error");
			//TODO drop
			freeFinsFrame(ff);
		} else {
			uint8_t *pdu = ff->ctrlFrame.data;
			if (pdu != NULL) { //TODO make func!!
				struct udp_sent *sent = (struct udp_sent *) list_find2(md->sent_packet_list, udp_sent_data_test,md,&ff->ctrlFrame.data_len);
				if (sent != NULL) {
					metadata_copy(sent->ff->metaData, ff->metaData);

					ff->ctrlFrame.sender_id = module->index;
					//ff->ctrlFrame.param_id = ERROR_ICMP_TTL; //TODO error msg code //ERROR_UDP_TTL?

					ff->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
					ff->ctrlFrame.data = sent->ff->dataFrame.pdu;
					sent->ff->dataFrame.pdu = NULL;

					if (!module_send_flow(module, ff, UDP_FLOW_DAEMON)) {
						PRINT_ERROR("todo error");
						freeFinsFrame(ff);
					}

					list_remove(md->sent_packet_list, sent);
					udp_sent_free(sent);
					PRINT_DEBUG("Freeing: pdu=%p", pdu);
					free(pdu);
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

		if (list_is_empty(md->sent_packet_list)) {
			PRINT_ERROR("todo error");
			//TODO drop
			freeFinsFrame(ff);
		} else {
			uint8_t *pdu = ff->ctrlFrame.data;
			if (pdu != NULL) {
				struct udp_sent *sent = (struct udp_sent *) list_find2(md->sent_packet_list, udp_sent_data_test, md, &ff->ctrlFrame.data_len);
				if (sent != NULL) {
					metadata_copy(sent->ff->metaData, ff->metaData);

					ff->ctrlFrame.sender_id = module->index;
					//ff->ctrlFrame.param_id = ERROR_ICMP_DEST_UNREACH; //TODO error msg code //ERROR_UDP_TTL?

					ff->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
					ff->ctrlFrame.data = sent->ff->dataFrame.pdu;
					sent->ff->dataFrame.pdu = NULL;

					if (!module_send_flow(module, ff, UDP_FLOW_DAEMON)) {
						PRINT_ERROR("todo error");
						freeFinsFrame(ff);
					}

					list_remove(md->sent_packet_list, sent);
					udp_sent_free(sent);
					PRINT_DEBUG("Freeing: pdu=%p", pdu);
					free(md);
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
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		break;
	}
}

void udp_init_params(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->params);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, "exec", CONFIG_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, "get", CONFIG_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(get_elem, UDP_GET_INTERVAL__str, UDP_GET_INTERVAL__id, UDP_GET_INTERVAL__type);
	//elem_add_param(get_elem, UDP_GET_REPEATS__str, UDP_GET_REPEATS__id, UDP_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, "set", CONFIG_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_DEBUG("todo error");
		exit(-1);
	}
	//elem_add_param(set_elem, UDP_SET_INTERVAL__str, UDP_SET_INTERVAL__id, UDP_SET_INTERVAL__type);
	//elem_add_param(set_elem, UDP_SET_REPEATS__str, UDP_SET_REPEATS__id, UDP_SET_REPEATS__type);
}

int udp_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	udp_init_params(module);

	module->data = secure_malloc(sizeof(struct udp_data));
	struct udp_data *md = (struct udp_data *) module->data;

	if (module->flows_max < flows_num) {
		PRINT_ERROR("todo error");
		return 0;
	}
	md->flows_num = flows_num;

	int i;
	for (i = 0; i < flows_num; i++) {
		md->flows[i] = flows[i];
	}

	//TODO extract this from meta?
	md->sent_packet_list = list_create(UDP_SENT_LIST_MAX);

	return 1;
}

int udp_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	struct udp_data *md = (struct udp_data *) module->data;
	secure_pthread_create(&md->switch_to_udp_thread, attr, switch_to_udp, module);

	return 1;
}

int udp_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int udp_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int udp_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct udp_data *md = (struct udp_data *) module->data;
	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_udp_thread");
	pthread_join(md->switch_to_udp_thread, NULL);

	return 1;
}

int udp_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct udp_data *md = (struct udp_data *) module->data;
	//TODO free all module related mem

	//delete threads
	PRINT_IMPORTANT("sent_packet_list->len=%u", md->sent_packet_list->len);
	list_free(md->sent_packet_list, udp_sent_free);

	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void udp_dummy(void) {

}

static struct fins_module_ops udp_ops = { .init = udp_init, .run = udp_run, .pause = udp_pause, .unpause = udp_unpause, .shutdown = udp_shutdown, .release =
		udp_release, };

struct fins_module *udp_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, UDP_LIB);
	module->flows_max = UDP_MAX_FLOWS;
	module->ops = &udp_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
