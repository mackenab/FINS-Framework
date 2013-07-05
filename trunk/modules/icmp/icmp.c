/**
 * icmp.c
 *
 *  Created on: Mar 15, 2011 - June 22, 2011
 *      Author: Abdallah Abdallah & Mark Hutcheson
 */
#include "icmp_internal.h"

#include <sys/time.h>
#include <math.h>
#include <string.h>

#include <finstime.h>

int icmp_sent_match_test(struct icmp_sent *sent, uint32_t *data_len, uint8_t *data) {
	if (sent->ff->dataFrame.pduLength >= *data_len) { //TODO check if this logic is sound
		return strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, *data_len) == 0;
	} else {
		return strncmp((char *) sent->ff->dataFrame.pdu, (char *) data, sent->ff->dataFrame.pduLength) == 0;
	}
}

void icmp_sent_free(struct icmp_sent *sent) {
	PRINT_DEBUG("Entered: sent=%p", sent);

	if (sent->ff) {
		freeFinsFrame(sent->ff);
	}

	free(sent);
}

void icmp_sent_list_gc(struct linked_list *sent_list, double timeout) {
	PRINT_DEBUG("Entered");

	struct timeval current;
	gettimeofday(&current, 0);

	//struct icmp_sent *old;

	/*
	 struct icmp_sent *temp = sent_list->front;
	 while (temp) {
	 if (time_diff(&temp->stamp, &current) >= timeout) {
	 old = temp;
	 temp = temp->next;

	 list_remove(sent_list, old);
	 icmp_sent_free(old);
	 } else {
	 temp = temp->next;
	 }
	 }
	 */
}

void *switch_to_icmp(void *local) {
	struct fins_module *module = (struct fins_module *) local;
	PRINT_IMPORTANT("Entered: module=%p", module);

	while (module->state == FMS_RUNNING) {
		icmp_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Exited: module=%p", module);
	return NULL;
}

void icmp_get_ff(struct fins_module *module) {
	struct finsFrame *ff;
	do {
		secure_sem_wait(module->event_sem);
		secure_sem_wait(module->input_sem);
		ff = read_queue(module->input_queue);
		sem_post(module->input_sem);
	} while (module->state == FMS_RUNNING && ff == NULL); //TODO change logic here, combine with switch_to_icmp?

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

	if (ff->dataOrCtrl == FF_CONTROL) { // send to the control frame handler
		icmp_fcf(module, ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == FF_DATA) {
		if (ff->dataFrame.directionFlag == DIR_UP) { //Incoming ICMP packet (coming in from teh internets)
			icmp_in_fdf(module, ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DIR_DOWN) { //Outgoing ICMP packet (going out from us to teh internets)
			icmp_out_fdf(module, ff);
			PRINT_DEBUG("");
		} else {
			PRINT_ERROR("todo error");
			exit(-1);
		}
	} else {
		PRINT_ERROR("todo error");
		exit(-1);
	}
}

void icmp_fcf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		icmp_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		icmp_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		icmp_exec(module, ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		exit(-1);
		break;
	}
}

void icmp_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_WARN("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void icmp_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case ICMP_SET_PARAM_FLOWS:
		PRINT_DEBUG("ICMP_SET_PARAM_FLOWS");
		module_set_param_flows(module, ff);
		break;
	case ICMP_SET_PARAM_LINKS:
		PRINT_DEBUG("ICMP_SET_PARAM_LINKS");
		module_set_param_links(module, ff);
		break;
	case ICMP_SET_PARAM_DUAL:
		PRINT_DEBUG("ICMP_SET_PARAM_DUAL");
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_ERROR("param_id=default (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void icmp_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_WARN("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void icmp_in_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);

	struct ipv4_packet *ipv4_pkt = (struct ipv4_packet *) ff->dataFrame.pdu;
	uint16_t ipv4_len = ntohs(ipv4_pkt->ip_len);

	struct icmp_packet *icmp_pkt = (struct icmp_packet *) ipv4_pkt->ip_data;
	uint32_t icmp_len = ipv4_len - IPV4_HLEN(ipv4_pkt);

	PRINT_DEBUG("pdu_len=%u, ipv4_len=%u, icmp_len=%u, hlen=%u", ff->dataFrame.pduLength, ipv4_len, icmp_len, IPV4_HLEN(ipv4_pkt));

	if (icmp_len < ICMP_HEADER_SIZE) {
		PRINT_DEBUG("packet too small: icmp_len=%u, icmp_req=%u", icmp_len, ICMP_HEADER_SIZE);

		freeFinsFrame(ff);
		return;
	}

	uint32_t protocol;
	secure_metadata_readFromElement(ff->metaData, "recv_protocol", &protocol);

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
			//pass through to daemon
			PRINT_DEBUG("id=%u, seq_num=%u", ntohs(icmp_pkt->param_1), ntohs(icmp_pkt->param_2));
			if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
				PRINT_WARN("todo error");
				freeFinsFrame(ff);
			}
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			freeFinsFrame(ff);
		}
		break;
	case TYPE_DESTUNREACH:
		PRINT_DEBUG("Destination unreachable");
		if (icmp_pkt->code == CODE_NETUNREACH) {
			PRINT_WARN("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_HOSTUNREACH) {
			PRINT_WARN("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_PROTOUNREACH) {
			PRINT_WARN("todo");
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_PORTUNREACH) {
			icmp_handle_error(module, ff, icmp_pkt, data_len, ERROR_ICMP_DEST_UNREACH);
		} else if (icmp_pkt->code == CODE_FRAGNEEDED) {
			PRINT_WARN("todo");
			//TODO use icmp_pkt->param_2 as Next-Hop MTU
			freeFinsFrame(ff);
		} else if (icmp_pkt->code == CODE_SRCROUTEFAIL) {
			PRINT_WARN("todo");
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("Unrecognized code. Dropping...");
			freeFinsFrame(ff);
			return;
		}
		break;
	case TYPE_ECHOREQUEST:
		if (icmp_pkt->code == CODE_ECHO) {
			PRINT_DEBUG("id=%u, seq_num=%u", ntohs(icmp_pkt->param_1), ntohs(icmp_pkt->param_2));
			icmp_ping_reply(module, ff, icmp_pkt, data_len);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			freeFinsFrame(ff);
		}
		break;
	case TYPE_TTLEXCEED:
		PRINT_DEBUG("TTL Exceeded");
		if (icmp_pkt->code == CODE_TTLEXCEEDED) {
			icmp_handle_error(module, ff, icmp_pkt, data_len, ERROR_ICMP_TTL);
		} else if (icmp_pkt->code == CODE_DEFRAGTIMEEXCEEDED) {
			PRINT_WARN("todo");
			freeFinsFrame(ff);
		} else {
			PRINT_ERROR("Error in ICMP packet code. Dropping...");
			freeFinsFrame(ff);
		}
		break;
	default:
		PRINT_DEBUG("default: type=%u", icmp_pkt->type);
		//Simply pass up the stack,
		if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
			PRINT_WARN("todo error");
			freeFinsFrame(ff);
		}
		break;
	}
}

void icmp_handle_error(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len, uint32_t param_id) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);
	struct icmp_data *md = (struct icmp_data *) module->data;

	if (data_len < IPV4_MIN_HLEN) {
		PRINT_ERROR("data too small: data_len=%u, ipv4_req=%u", data_len, IPV4_MIN_HLEN);
		//stats.badhlen++;
		//stats.droppedtotal++;
		freeFinsFrame(ff);
		return;
	}

	struct ipv4_packet *ipv4_pkt_sent = (struct ipv4_packet *) icmp_pkt->data;
	uint16_t sent_data_len = data_len - IPV4_HLEN(ipv4_pkt_sent);

	uint32_t type = icmp_pkt->type;
	secure_metadata_writeToElement(ff->metaData, "recv_icmp_type", &type, META_TYPE_INT32);
	uint32_t code = icmp_pkt->code;
	secure_metadata_writeToElement(ff->metaData, "recv_icmp_code", &code, META_TYPE_INT32);

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

		if (list_is_empty(md->sent_list)) {
			PRINT_WARN("todo error");
			//TODO drop
		} else {
			//TODO fix here
			struct icmp_sent *sent = (struct icmp_sent *) list_find2(md->sent_list, icmp_sent_match_test, &sent_data_len, ipv4_pkt_sent->ip_data);
			if (sent != NULL) {
				metadata_copy(ff->metaData, sent->ff->metaData);

				ff_err = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
				ff_err->dataOrCtrl = FF_CONTROL;
				ff_err->metaData = sent->ff->metaData;
				sent->ff->metaData = NULL;

				ff_err->ctrlFrame.sender_id = module->index;
				ff_err->ctrlFrame.serial_num = gen_control_serial_num();
				ff_err->ctrlFrame.opcode = CTRL_ERROR;
				ff_err->ctrlFrame.param_id = param_id; //TODO error msg code

				ff_err->ctrlFrame.data_len = sent->ff->dataFrame.pduLength;
				ff_err->ctrlFrame.data = sent->ff->dataFrame.pdu;
				sent->ff->dataFrame.pdu = NULL;

				if (!module_send_flow(module, ff_err, ICMP_FLOW_DAEMON)) {
					PRINT_WARN("todo error");
					freeFinsFrame(ff_err);
				}

				list_remove(md->sent_list, sent);
				icmp_sent_free(sent);
			} else {
				PRINT_WARN("todo error");
				//TODO drop?
			}
		}
		break;
	case UDP_PROTOCOL:
		//cast first 8 bytes of ip->data to udp frag, store in metadata
		if (sent_data_len < UDP_FRAG_SIZE) {
			PRINT_ERROR("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);
			freeFinsFrame(ff);
			return;
		}

		ff_err = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff_err->dataOrCtrl = FF_CONTROL;
		ff_err->metaData = ff->metaData;
		ff->metaData = NULL;

		ff_err->ctrlFrame.sender_id = module->index;
		ff_err->ctrlFrame.serial_num = gen_control_serial_num();
		ff_err->ctrlFrame.opcode = CTRL_ERROR;
		ff_err->ctrlFrame.param_id = param_id; //TODO error msg code

		ff_err->ctrlFrame.data_len = sent_data_len;
		ff_err->ctrlFrame.data = (uint8_t *) secure_malloc(ff_err->ctrlFrame.data_len);
		memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

		if (!module_send_flow(module, ff_err, ICMP_FLOW_UDP)) {
			PRINT_WARN("todo error");
			freeFinsFrame(ff_err);
		}
		break;
	default:
		PRINT_WARN("todo error");
		break;
	}
	freeFinsFrame(ff);
}

void icmp_ping_reply(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);

	uint32_t pdu_len_reply = data_len + ICMP_HEADER_SIZE;
	uint8_t *pdu_reply = (uint8_t *) secure_malloc(pdu_len_reply);

	struct icmp_packet *icmp_pkt_reply = (struct icmp_packet *) pdu_reply;
	icmp_pkt_reply->type = TYPE_ECHOREPLY;
	icmp_pkt_reply->code = CODE_ECHO;
	icmp_pkt_reply->checksum = 0;
	icmp_pkt_reply->param_1 = icmp_pkt->param_1; //id
	icmp_pkt_reply->param_2 = icmp_pkt->param_2; //seq num

	memcpy(icmp_pkt_reply->data, icmp_pkt->data, data_len);

	icmp_pkt_reply->checksum = htons(icmp_checksum(pdu_reply, pdu_len_reply));
	PRINT_DEBUG("netw: id=%u, seq_num=%u, checksum=0x%x", icmp_pkt_reply->param_1, icmp_pkt_reply->param_2, icmp_pkt_reply->checksum);

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "recv_family", &family);
	uint32_t src_ip;
	secure_metadata_readFromElement(ff->metaData, "recv_src_ipv4", &src_ip);
	uint32_t dst_ip;
	secure_metadata_readFromElement(ff->metaData, "recv_dst_ipv4", &dst_ip);

	metadata *meta_reply = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_reply);

	uint32_t protocol = ICMP_PROTOCOL;
	secure_metadata_writeToElement(meta_reply, "send_protocol", &protocol, META_TYPE_INT32);
	secure_metadata_writeToElement(meta_reply, "send_family", &family, META_TYPE_INT32);
	secure_metadata_writeToElement(meta_reply, "send_src_ipv4", &dst_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(meta_reply, "send_dst_ipv4", &src_ip, META_TYPE_INT32);

	struct finsFrame *ff_reply = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	ff_reply->dataOrCtrl = FF_DATA;
	ff_reply->metaData = meta_reply;

	ff_reply->dataFrame.directionFlag = DIR_DOWN;
	ff_reply->dataFrame.pduLength = pdu_len_reply;
	ff_reply->dataFrame.pdu = pdu_reply;

	if (!module_send_flow(module, ff_reply, ICMP_FLOW_IPV4)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff_reply);
	}

	freeFinsFrame(ff);
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

void icmp_out_fdf(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct icmp_data *md = (struct icmp_data *) module->data;

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "send_family", &family);
	uint32_t src_ip;
	secure_metadata_readFromElement(ff->metaData, "send_src_ipv4", &src_ip);
	uint32_t dst_ip;
	secure_metadata_readFromElement(ff->metaData, "send_dst_ipv4", &dst_ip);
	uint32_t protocol = ICMP_PROTOCOL;
	secure_metadata_writeToElement(ff->metaData, "send_protocol", &protocol, META_TYPE_INT32);

	struct finsFrame *ff_clone = cloneFinsFrame(ff);
	if (module_send_flow(module, ff, ICMP_FLOW_IPV4)) {
		struct icmp_sent *sent = (struct icmp_sent *) secure_malloc(sizeof(struct icmp_sent));
		sent->ff = ff_clone;

		//PRINT_DEBUG("Clearing sent_list");
		//icmp_sent_list_gc(md->sent_list, ICMP_MSL_TO_DEFAULT); //TODO shift this to separate thread on TO, when full this slows sending down

		if (!list_has_space(md->sent_list)) {
			PRINT_DEBUG("Dropping front of sent_list");
			struct icmp_sent *old = (struct icmp_sent *) list_remove_front(md->sent_list);
			icmp_sent_free(old);
		}
		list_append(md->sent_list, sent);
		PRINT_DEBUG("sent_list=%p, len=%u, max=%u", md->sent_list, md->sent_list->len, md->sent_list->max);

		gettimeofday(&sent->stamp, 0);
	} else {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}
}

void icmp_init_knobs(struct fins_module *module) {
	metadata_element *root = config_root_setting(module->knobs);
	//int status;

	//-------------------------------------------------------------------------------------------
	metadata_element *exec_elem = config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);
	if (exec_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	//-------------------------------------------------------------------------------------------
	metadata_element *get_elem = config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);
	if (get_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	//elem_add_param(get_elem, LOGGER_GET_INTERVAL__str, LOGGER_GET_INTERVAL__id, LOGGER_GET_INTERVAL__type);
	//elem_add_param(get_elem, LOGGER_GET_REPEATS__str, LOGGER_GET_REPEATS__id, LOGGER_GET_REPEATS__type);

	//-------------------------------------------------------------------------------------------
	metadata_element *set_elem = config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	if (set_elem == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	//elem_add_param(set_elem, LOGGER_SET_INTERVAL__str, LOGGER_SET_INTERVAL__id, LOGGER_SET_INTERVAL__type);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int icmp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_IMPORTANT("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	icmp_init_knobs(module);

	module->data = secure_malloc(sizeof(struct icmp_data));
	struct icmp_data *md = (struct icmp_data *) module->data;

	md->sent_list = list_create(ICMP_SENT_LIST_MAX);

	return 1;
}

int icmp_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_IMPORTANT("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	icmp_get_ff(module);

	struct icmp_data *md = (struct icmp_data *) module->data;
	secure_pthread_create(&md->switch_to_icmp_thread, attr, switch_to_icmp, module);

	return 1;
}

int icmp_pause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int icmp_unpause(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int icmp_shutdown(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct icmp_data *md = (struct icmp_data *) module->data;
	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_icmp_thread");
	pthread_join(md->switch_to_icmp_thread, NULL);

	return 1;
}

int icmp_release(struct fins_module *module) {
	PRINT_IMPORTANT("Entered: module=%p", module);

	struct icmp_data *md = (struct icmp_data *) module->data;
	PRINT_IMPORTANT("sent_list->len=%u", md->sent_list->len);
	list_free(md->sent_list, icmp_sent_free);

	if (md->link_list != NULL) {
		list_free(md->link_list, free);
	}
	free(md);
	module_destroy_structs(module);
	free(module);
	return 1;
}

void icmp_dummy(void) {

}

static struct fins_module_ops icmp_ops = { .init = icmp_init, .run = icmp_run, .pause = icmp_pause, .unpause = icmp_unpause, .shutdown = icmp_shutdown,
		.release = icmp_release, };

struct fins_module *icmp_create(uint32_t index, uint32_t id, uint8_t *name) {
	PRINT_IMPORTANT("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, ICMP_LIB);
	module->flows_max = ICMP_MAX_FLOWS;
	module->ops = &icmp_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_IMPORTANT("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
