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
	PRINT_DEBUG("Entered: module=%p", module);
	PRINT_IMPORTANT("Thread started: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);

	while (module->state == FMS_RUNNING) {
		icmp_get_ff(module);
		PRINT_DEBUG("");
	}

	PRINT_IMPORTANT("Thread exited: module=%p, index=%u, id=%u, name='%s'", module, module->index, module->id, module->name);
	PRINT_DEBUG("Exited: module=%p", module);
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
		icmp_error(module, ff);
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
		PRINT_DEBUG("param_id=ICMP_SET_PARAM_FLOWS (%d)", ff->ctrlFrame.param_id);
		module_set_param_flows(module, ff);
		break;
	case ICMP_SET_PARAM_LINKS:
		PRINT_DEBUG("param_id=ICMP_SET_PARAM_LINKS (%d)", ff->ctrlFrame.param_id);
		module_set_param_links(module, ff);
		break;
	case ICMP_SET_PARAM_DUAL:
		PRINT_DEBUG("param_id=ICMP_SET_PARAM_DUAL (%d)", ff->ctrlFrame.param_id);
		module_set_param_dual(module, ff);
		break;
	default:
		PRINT_WARN("param_id=default (%d)", ff->ctrlFrame.param_id);
		module_reply_fcf(module, ff, FCF_FALSE, 0);
		break;
	}
}

void icmp_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	PRINT_WARN("todo");
	module_reply_fcf(module, ff, FCF_FALSE, 0);
}

void icmp_error(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: module=%p, ff=%p, meta=%p", module, ff, ff->metaData);
	struct icmp_data *md = (struct icmp_data *) module->data;

	//TODO convert initial error into FDF sent to IPv4 as if received by Eth

	switch (ff->ctrlFrame.param_id) {
	case ICMP_ERROR_GET_ADDR:
		PRINT_DEBUG("param_id=ICMP_ERROR_GET_ADDR (%d)", ff->ctrlFrame.param_id);
		//created actual FDF icmp pkt for this error & send to daemon, then continue the FCF flow upwards
		//This should really send a ICMP fdf pkt down through IPv4/loopback that creates a real FCF error

		//should we separate icmp & error messages? what about disabling ICMP, what errors should it stop?
		//if yes, eth->ip->icmp or ip->proto
		//if no, eth->icmp->proto
		//if partial, eth->ip->icmp->proto (allows for similar to iptables)
		//Sending to ICMP mimic kernel func, if remove icmp stops error

		//should be: IPv4(self, self), ICMP(dest unreach, host unreach), IPv4(sent pkt), proto(...)
		metadata *meta_data = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta_data);

		uint32_t host_ip;
		struct addr_record *addr = (struct addr_record *) list_find(md->if_main->addr_list, addr_is_v4);
		if (addr != NULL) {
			host_ip = addr4_get_ip(&addr->ip);
		} else {
			PRINT_WARN("todo error");
		}

		//daemon meta
		uint32_t family = AF_INET;
		secure_metadata_writeToElement(meta_data, "send_family", &family, META_TYPE_INT32);
		secure_metadata_writeToElement(meta_data, "send_src_ipv4", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta_data, "send_dst_ipv4", &host_ip, META_TYPE_INT32);

		struct finsFrame *ff_data = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff_data->dataOrCtrl = FF_DATA;
		ff_data->metaData = meta_data;

		ff_data->dataFrame.directionFlag = DIR_DOWN;
		ff_data->dataFrame.pduLength = ff->ctrlFrame.data_len + ICMP_HEADER_SIZE;
		ff_data->dataFrame.pdu = (uint8_t *) secure_malloc(ff_data->dataFrame.pduLength); //add ICMP hdr

		struct icmp_packet *icmp_pkt = (struct icmp_packet *) ff_data->dataFrame.pdu;
		icmp_pkt->type = ICMP_TYPE_DESTUNREACH;
		icmp_pkt->code = ICMP_CODE_HOSTUNREACH;
		icmp_pkt->checksum = 0;
		icmp_pkt->param_1 = 0; //id
		icmp_pkt->param_2 = 0; //seq num

		memcpy(icmp_pkt->data, ff->ctrlFrame.data, ff->ctrlFrame.data_len);
		icmp_pkt->checksum = htons(icmp_checksum(ff_data->dataFrame.pdu, ff_data->dataFrame.pduLength));

		icmp_out_fdf(module, ff_data);

		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("param_id=default (%d)", ff->ctrlFrame.param_id);
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		break;
	}
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

	if (protocol != ICMP_PT_ICMP) { //TODO remove this check?
		//md->stats.wrongProtocol++;
		//md->stats.totalBadDatagrams++;

		PRINT_WARN("wrong protocol: expected=%u, proto=%u", ICMP_PT_ICMP, protocol);
		freeFinsFrame(ff);
		return;
	}

	if (icmp_pkt->checksum == 0) {
		PRINT_DEBUG("checksum==0");
	} else {
		if (icmp_checksum(ipv4_pkt->ip_data, icmp_len) != 0) {
			PRINT_WARN("Error in checksum of packet. Discarding...");
			freeFinsFrame(ff);
			return;
		} else {
			//do nothing
		}
	}

	uint32_t type = icmp_pkt->type;
	secure_metadata_writeToElement(ff->metaData, "recv_icmp_type", &type, META_TYPE_INT32);
	uint32_t code = icmp_pkt->code;
	secure_metadata_writeToElement(ff->metaData, "recv_icmp_code", &code, META_TYPE_INT32);
	uint32_t data_len = icmp_len - ICMP_HEADER_SIZE;

	//all icmp pkts pass through to daemon, special ones cause auto responses/errors
	PRINT_DEBUG("ff=%p, type=%u, code=%u, data_len=%u", ff, type, code, data_len);
	switch (type) {
	case ICMP_TYPE_ECHOREPLY:
		if (code == ICMP_CODE_ECHO) {
			//pass through to daemon
			PRINT_DEBUG("id=%u, seq_num=%u", ntohs(icmp_pkt->param_1), ntohs(icmp_pkt->param_2));
		} else {
			PRINT_WARN("Error in ICMP packet code.");
		}
		break;
	case ICMP_TYPE_DESTUNREACH:
		PRINT_DEBUG("Destination unreachable");
		if (code == ICMP_CODE_NETUNREACH) {
			PRINT_WARN("todo");
		} else if (code == ICMP_CODE_HOSTUNREACH) {
			//create FCF & send to proto then daemon
			PRINT_WARN("todo");
			//spawn error FCF
			icmp_handle_error(module, ff, icmp_pkt, data_len, ICMP_ERROR_DEST_UNREACH);
		} else if (code == ICMP_CODE_PROTOUNREACH) {
			PRINT_WARN("todo");
		} else if (code == ICMP_CODE_PORTUNREACH) {
			//create FCF & send to proto then daemon
			icmp_handle_error(module, ff, icmp_pkt, data_len, ICMP_ERROR_DEST_UNREACH); //TODO get to send after fdf passed up
			return;
		} else if (code == ICMP_CODE_FRAGNEEDED) {
			PRINT_WARN("todo");
			//TODO use icmp_pkt->param_2 as Next-Hop MTU
		} else if (code == ICMP_CODE_SRCROUTEFAIL) {
			PRINT_WARN("todo");
		} else {
			PRINT_WARN("Unrecognized code.");
		}
		break;
	case ICMP_TYPE_ECHOREQUEST:
		if (code == ICMP_CODE_ECHO) {
			PRINT_DEBUG("id=%u, seq_num=%u", ntohs(icmp_pkt->param_1), ntohs(icmp_pkt->param_2));
			icmp_ping_reply(module, ff, icmp_pkt, data_len); //TODO get to send after fdf passed up
			return;
		} else {
			PRINT_WARN("Error in ICMP packet code.");
		}
		break;
	case ICMP_TYPE_TTLEXCEED:
		PRINT_DEBUG("TTL Exceeded");
		if (code == ICMP_CODE_TTLEXCEEDED) {
			icmp_handle_error(module, ff, icmp_pkt, data_len, ICMP_ERROR_TTL); //TODO get to send after fdf passed up
			return;
		} else if (code == ICMP_CODE_DEFRAGTIMEEXCEEDED) {
			PRINT_WARN("todo");
		} else {
			PRINT_WARN("Error in ICMP packet code.");
		}
		break;
	default:
		PRINT_DEBUG("default: type=%u", type);
		//Simply pass up the stack,
		break;
	}

	//all icmp pkts pass through to daemon, special ones cause auto responses/errors
	if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}
}

void icmp_handle_error(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len, uint32_t param_id) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);
	struct icmp_data *md = (struct icmp_data *) module->data;

	if (data_len < IPV4_MIN_HLEN) {
		PRINT_WARN("data too small: data_len=%u, ipv4_req=%u", data_len, IPV4_MIN_HLEN);
		//stats.badhlen++;
		//stats.droppedtotal++;
		if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
			PRINT_WARN("todo error");
			freeFinsFrame(ff);
		}
		return;
	}

	struct ipv4_packet *ipv4_pkt_sent = (struct ipv4_packet *) icmp_pkt->data;
	uint16_t sent_data_len = data_len - IPV4_HLEN(ipv4_pkt_sent);

	struct finsFrame *ff_err;

	PRINT_DEBUG("sent: proto=%u, data_len=%u", ipv4_pkt_sent->ip_proto, sent_data_len);
	switch (ipv4_pkt_sent->ip_proto) {
	case ICMP_PT_ICMP:
		//cast first 8 bytes of ip->data to TCP frag, store in metadata
		if (sent_data_len < ICMP_FRAG_SIZE) {
			PRINT_WARN("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, ICMP_FRAG_SIZE);
			if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
				PRINT_WARN("todo error");
				freeFinsFrame(ff);
			}
			return;
		}

		if (list_is_empty(md->sent_list)) {
			PRINT_WARN("todo error");
			//TODO drop?
		} else {
			//TODO fix here
			struct icmp_sent *sent = (struct icmp_sent *) list_find2(md->sent_list, icmp_sent_match_test, &sent_data_len, ipv4_pkt_sent->ip_data);
			if (sent != NULL) {
				//ff=fdf, sent->ff=fdf, ff_err=fcf
				//ff_err should have sent->ff meta + recv info for: icmp_type, stamp, ttl,

				//uint32_t err_errno = EHOSTUNREACH; //from where? has to come from meta
				uint32_t err_src_ip;
				secure_metadata_readFromElement(ff->metaData, "recv_src_ipv4", &err_src_ip);
				secure_metadata_writeToElement(sent->ff->metaData, "recv_src_ipv4", &err_src_ip, META_TYPE_INT32);
				uint32_t err_ttl;
				secure_metadata_readFromElement(ff->metaData, "recv_ttl", &err_ttl);
				secure_metadata_writeToElement(sent->ff->metaData, "recv_ttl", &err_ttl, META_TYPE_INT32);

				uint32_t err_origin = SO_EE_ORIGIN_ICMP;
				secure_metadata_writeToElement(sent->ff->metaData, "recv_ee_origin", &err_origin, META_TYPE_INT32);

				uint32_t err_icmp_type = icmp_pkt->type;
				secure_metadata_writeToElement(sent->ff->metaData, "recv_icmp_type", &err_icmp_type, META_TYPE_INT32);
				uint32_t err_icmp_code = icmp_pkt->code;
				secure_metadata_writeToElement(sent->ff->metaData, "recv_icmp_code", &err_icmp_code, META_TYPE_INT32);

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

				if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
					PRINT_WARN("todo error");
					freeFinsFrame(ff);
				}

				if (!module_send_flow(module, ff_err, ICMP_FLOW_DAEMON)) {
					PRINT_WARN("todo error");
					freeFinsFrame(ff_err);
				}

				list_remove(md->sent_list, sent);
				icmp_sent_free(sent);
				return;
			} else {
				PRINT_WARN("todo error");
				//TODO drop?
			}
		}
		break;
	case ICMP_PT_UDP:
		//cast first 8 bytes of ip->data to udp frag, store in metadata
		if (sent_data_len < UDP_FRAG_SIZE) {
			PRINT_WARN("data too small: sent_data_len=%u, frag_size=%u", sent_data_len, UDP_FRAG_SIZE);
			if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
				PRINT_WARN("todo error");
				freeFinsFrame(ff);
			}
			return;
		}

		ff_err = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff_err->dataOrCtrl = FF_CONTROL;
		ff_err->metaData = metadata_clone(ff->metaData);

		uint32_t err_origin = SO_EE_ORIGIN_ICMP;
		secure_metadata_writeToElement(ff->metaData, "recv_ee_origin", &err_origin, META_TYPE_INT32);

		ff_err->ctrlFrame.sender_id = module->index;
		ff_err->ctrlFrame.serial_num = gen_control_serial_num();
		ff_err->ctrlFrame.opcode = CTRL_ERROR;
		ff_err->ctrlFrame.param_id = param_id; //TODO error msg code

		ff_err->ctrlFrame.data_len = sent_data_len;
		ff_err->ctrlFrame.data = (uint8_t *) secure_malloc(ff_err->ctrlFrame.data_len);
		memcpy(ff_err->ctrlFrame.data, ipv4_pkt_sent->ip_data, ff_err->ctrlFrame.data_len);

		if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
			PRINT_WARN("todo error");
			freeFinsFrame(ff);
		}

		if (!module_send_flow(module, ff_err, ICMP_FLOW_UDP)) {
			PRINT_WARN("todo error");
			freeFinsFrame(ff_err);
		}
		return;
	case ICMP_PT_TCP:
		PRINT_WARN("todo");
		//copy what's used for UDP?
		break;
	default:
		PRINT_WARN("todo error");
		break;
	}

	//continue flow upwards for ICMP fdf
	if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}
}

void icmp_ping_reply(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len) {
	PRINT_DEBUG("Entered: ff=%p, icmp_pkt=%p", ff, icmp_pkt);

	uint32_t pdu_len_reply = data_len + ICMP_HEADER_SIZE;
	uint8_t *pdu_reply = (uint8_t *) secure_malloc(pdu_len_reply);

	struct icmp_packet *icmp_pkt_reply = (struct icmp_packet *) pdu_reply;
	icmp_pkt_reply->type = ICMP_TYPE_ECHOREPLY;
	icmp_pkt_reply->code = ICMP_CODE_ECHO;
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

	uint32_t protocol = ICMP_PT_ICMP;
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

	if (!module_send_flow(module, ff, ICMP_FLOW_DAEMON)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff);
	}

	if (!module_send_flow(module, ff_reply, ICMP_FLOW_IPV4)) {
		PRINT_WARN("todo error");
		freeFinsFrame(ff_reply);
	}
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
	uint32_t protocol = ICMP_PT_ICMP;
	secure_metadata_writeToElement(ff->metaData, "send_protocol", &protocol, META_TYPE_INT32);

#ifdef DEBUG
	struct icmp_packet *icmp_pkt = (struct icmp_packet *) ff->dataFrame.pdu;
	uint32_t data_len = ff->dataFrame.pduLength - ICMP_HEADER_SIZE;
	PRINT_DEBUG("ff=%p, type=%u, code=%u, data_len=%u", ff, icmp_pkt->type, icmp_pkt->code, data_len);

	switch (icmp_pkt->type) {
	case ICMP_TYPE_ECHOREQUEST:
		if (icmp_pkt->code == ICMP_CODE_ECHO) {
			PRINT_DEBUG("id=%u, seq_num=%u", ntohs(icmp_pkt->param_1), ntohs(icmp_pkt->param_2));
		} else {
		}
		break;
	default:
		PRINT_DEBUG("default: type=%u", icmp_pkt->type);
		break;
	}
#endif

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
	//metadata_element *root = config_root_setting(module->knobs);

	//metadata_element *exec_elem = secure_config_setting_add(root, OP_EXEC_STR, META_TYPE_GROUP);

	//metadata_element *get_elem = secure_config_setting_add(root, OP_GET_STR, META_TYPE_GROUP);

	//metadata_element *set_elem = secure_config_setting_add(root, OP_SET_STR, META_TYPE_GROUP);
	//elem_add_param(set_elem, LOGGER_SET_REPEATS__str, LOGGER_SET_REPEATS__id, LOGGER_SET_REPEATS__type);
}

int icmp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi) {
	PRINT_DEBUG("Entered: module=%p, params=%p, envi=%p", module, params, envi);
	module->state = FMS_INIT;
	module_create_structs(module);

	icmp_init_knobs(module);

	module->data = secure_malloc(sizeof(struct icmp_data));
	struct icmp_data *md = (struct icmp_data *) module->data;

	md->if_list = list_clone(envi->if_list, ifr_clone);
	if (md->if_list->len > ICMP_IF_LIST_MAX) {
		PRINT_WARN("todo");
		struct linked_list *leftover = list_split(md->if_list, ICMP_IF_LIST_MAX - 1);
		list_free(leftover, free);
	}
	md->if_list->max = ICMP_IF_LIST_MAX;
	PRINT_DEBUG("if_list: list=%p, max=%u, len=%u", md->if_list, md->if_list->max, md->if_list->len);

	if (envi->if_loopback != NULL) {
		md->if_loopback = (struct if_record *) list_find1(md->if_list,ifr_index_test,&envi->if_loopback->index);
		PRINT_DEBUG("loopback: name='%s', addr_list->len=%u", md->if_loopback->name, md->if_loopback->addr_list->len);
	} else {
		md->if_loopback = NULL;
	}

	if (envi->if_main != NULL) {
		md->if_main = (struct if_record *) list_find1(md->if_list,ifr_index_test,&envi->if_main->index);
		PRINT_DEBUG("main: name='%s', addr_list->len=%u", md->if_main->name, md->if_main->addr_list->len);
	} else {
		md->if_main = NULL;
	}

	md->sent_list = list_create(ICMP_SENT_LIST_MAX);

	return 1;
}

int icmp_run(struct fins_module *module, pthread_attr_t *attr) {
	PRINT_DEBUG("Entered: module=%p, attr=%p", module, attr);
	module->state = FMS_RUNNING;

	icmp_get_ff(module);

	struct icmp_data *md = (struct icmp_data *) module->data;
	secure_pthread_create(&md->switch_to_icmp_thread, attr, switch_to_icmp, module);

	return 1;
}

int icmp_pause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_PAUSED;

	//TODO
	return 1;
}

int icmp_unpause(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_RUNNING;

	//TODO
	return 1;
}

int icmp_shutdown(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	module->state = FMS_SHUTDOWN;
	sem_post(module->event_sem);

	struct icmp_data *md = (struct icmp_data *) module->data;
	//TODO expand this

	PRINT_IMPORTANT("Joining switch_to_icmp_thread");
	pthread_join(md->switch_to_icmp_thread, NULL);

	return 1;
}

int icmp_release(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);

	struct icmp_data *md = (struct icmp_data *) module->data;
	PRINT_IMPORTANT("sent_list->len=%u", md->sent_list->len);
	list_free(md->sent_list, icmp_sent_free);

	//free common module data
	PRINT_IMPORTANT("if_list->len=%u", md->if_list->len);
	list_free(md->if_list, ifr_free);

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
	PRINT_DEBUG("Entered: index=%u, id=%u, name='%s'", index, id, name);

	struct fins_module *module = (struct fins_module *) secure_malloc(sizeof(struct fins_module));

	strcpy((char *) module->lib, ICMP_LIB);
	module->flows_max = ICMP_MAX_FLOWS;
	module->ops = &icmp_ops;
	module->state = FMS_FREE;

	module->index = index;
	module->id = id;
	strcpy((char *) module->name, (char *) name);

	PRINT_DEBUG("Exited: index=%u, id=%u, name='%s', module=%p", index, id, name, module);
	return module;
}
