/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4_internal.h"
#include <finsqueue.h>

void ipv4_get_ff(struct fins_module *module) {
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

	if (ff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID=%d, ff=%p, meta=%p", ff->dataOrCtrl, ff->destinationID, ff, ff->metaData);
		ipv4_fcf(module, ff);
	} else if (ff->dataOrCtrl == DATA) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID=%d, ff=%p, meta=%p", ff->dataOrCtrl, ff->destinationID, ff, ff->metaData);
		PRINT_DEBUG("PDU Length: %d", ff->dataFrame.pduLength);
		PRINT_DEBUG("Data direction: %d", ff->dataFrame.directionFlag);
		PRINT_DEBUG("pdu=%p", ff->dataFrame.pdu);

		if (ff->dataFrame.directionFlag == DIR_UP) {
			PRINT_DEBUG("IP4_in");

			IP4_in(module, ff, (struct ip4_packet*) ff->dataFrame.pdu, ff->dataFrame.pduLength);

		} else if (ff->dataFrame.directionFlag == DIR_DOWN) {
			PRINT_DEBUG("IP4_out");

			uint32_t protocol;
			secure_metadata_readFromElement(ff->metaData, "send_protocol", &protocol);

			uint32_t my_host_ip_addr = 0; //TODO remove/fix, is just for compiling
			PRINT_DEBUG("%u", my_host_ip_addr);
			PRINT_DEBUG("Transport protocol going out passed to IPv4: protocol=%u", protocol);
			//TODO change my_host_ip_addr to src_ip from metadata
			switch (protocol) {
			case IP4_PT_ICMP:
				IP4_out(module, ff, ff->dataFrame.pduLength, my_host_ip_addr, IP4_PT_ICMP);
				break;
			case IP4_PT_TCP:
				IP4_out(module, ff, ff->dataFrame.pduLength, my_host_ip_addr, IP4_PT_TCP);
				break;
			case IP4_PT_UDP:
				IP4_out(module, ff, ff->dataFrame.pduLength, my_host_ip_addr, IP4_PT_UDP);
				break;
			default:
				PRINT_ERROR("invalid protocol: protocol=%u", protocol);
				/**
				 * TODO investigate why the freeFinsFrame below create segmentation fault
				 */
				freeFinsFrame(ff);
				break;
			}

		} else {
			PRINT_ERROR("Error: Wrong value of fdf.directionFlag");
			freeFinsFrame(ff);
		}
	} else {
		PRINT_ERROR("Error: Wrong ff->dataOrCtrl value");
		exit(-1);
	}

}

void ipv4_fcf(struct fins_module *module, struct finsFrame *ff) {
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
		ipv4_read_param(module, ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		ipv4_set_param(module, ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		ipv4_exec(module, ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		ipv4_exec_reply(module, ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void ipv4_read_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}
void ipv4_set_param(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}
void ipv4_exec(struct fins_module *module, struct finsFrame *ff) {
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}

void ipv4_exec_reply(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	switch (ff->ctrlFrame.param_id) {
	case EXEC_ARP_GET_ADDR:
		PRINT_DEBUG("param_id=EXEC_ARP_GET_ADDR (%d)", ff->ctrlFrame.param_id);
		ipv4_exec_reply_get_addr(module, ff);
		break;
	default:
		PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
		PRINT_ERROR("todo");
		freeFinsFrame(ff);
		break;
	}
}

void ipv4_exec_reply_get_addr(struct fins_module *module, struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

	struct ipv4_data *data = (struct ipv4_data *) module->data;

	struct ipv4_store *store = (struct ipv4_store *) list_find1(data->store_list, ipv4_store_serial_test, &ff->ctrlFrame.serial_num);
	if (store != NULL) {
		PRINT_DEBUG("store=%p, serial_num=%u, cache=%p, resquest=%p", store, store->serial_num, store->cache, store->request);
		list_remove(data->store_list, store);

		struct ipv4_cache *cache = store->cache;
		struct ipv4_request *request = store->request;

		if (ff->ctrlFrame.ret_val) {
			uint64_t src_mac = request->src_mac;
			uint32_t src_ip = request->src_ip;
			uint64_t dst_mac = 0;
			uint32_t dst_ip = cache->addr_ip;

			metadata *meta = ff->metaData;
			secure_metadata_readFromElement(meta, "dst_mac", &dst_mac);

			PRINT_DEBUG("Entered: ff=%p, src=0x%llx/%u, dst=0x%llx/%u", ff, src_mac, src_ip, dst_mac, dst_ip);

			if (cache->seeking) {
				PRINT_DEBUG("Updating host: node=%p, mac=0x%llx, ip=%u", cache, dst_mac, dst_ip);
				cache->addr_mac = dst_mac;

				cache->seeking = 0;
				gettimeofday(&cache->updated_stamp, 0); //use this as time cache confirmed

				struct ipv4_request *request_resp;
				struct finsFrame *ff_resp;

				while (!list_is_empty(cache->request_list)) {
					request_resp = (struct ipv4_request *) list_remove_front(cache->request_list);
					ff_resp = request_resp->ff;

					uint32_t ether_type = IP4_ETH_TYPE;
					secure_metadata_writeToElement(ff_resp->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
					//secure_metadata_writeToElement(ff_resp->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
					secure_metadata_writeToElement(ff_resp->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);

					PRINT_DEBUG("send frame: src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", src_mac, dst_mac, ether_type);

					//print_finsFrame(fins_frame);
					module_to_switch(module, ff_resp);

					request_resp->ff = NULL;
					ipv4_request_free(request_resp);
				}
			} else {
				PRINT_ERROR("Not seeking addr. Dropping: ff=%p, src=0x%llx/%u, dst=0x%llx/%u, cache=%p", ff, src_mac, src_ip, dst_mac, dst_ip, cache);
			}

			store->cache = NULL;
			ipv4_store_free(store);
		} else {
			//TODO error sending back FDF as FCF? saved pdu for that
			PRINT_ERROR("todo error");

			uint64_t src_mac = request->src_mac;
			uint32_t src_ip = request->src_ip;
			uint64_t dst_mac = 0;
			uint32_t dst_ip = cache->addr_ip;

			PRINT_ERROR("Not seeking addr. Dropping: ff=%p, src=0x%llx/%u, dst=0x%llx/%u, cache=%p", ff, src_mac, src_ip, dst_mac, dst_ip, cache);

			//TODO remove all requests from same source //split cache into (src,dst) tuples?
			//ipv4_store_free(store);
		}
	} else {
		PRINT_ERROR("Exited, no corresponding store: ff=%p, serial_num=%u", ff, ff->ctrlFrame.serial_num);
	}

	freeFinsFrame(ff);
}

/*
 void ipv4_exec_reply_get_addr_old(struct finsFrame *ff, uint64_t src_mac, uint64_t dst_mac) {
 PRINT_DEBUG("Entered: ff=%p, src_mac=0x%llx, dst_mac=0x%llx", ff, src_mac, dst_mac);

 struct ipv4_store *store = store_list_find(ff->ctrlFrame.serial_num);
 if (store) {
 PRINT_DEBUG("store=%p, ff=%p, serial_num=%u", store, store->ff, store->serial_num);
 store_list_remove(store);

 uint32_t ether_type = IP4_ETH_TYPE;
 secure_metadata_writeToElement(store->ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
 secure_metadata_writeToElement(store->ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);
 secure_metadata_writeToElement(store->ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);

 PRINT_DEBUG("send frame: src=0x%12.12llx, dst=0x%12.12llx, type=0x%x", src_mac, dst_mac, ether_type);

 //print_finsFrame(fins_frame);
 ipv4_to_switch(store->ff);

 store->ff = NULL;
 store_free(store);

 freeFinsFrame(ff);
 } else {
 PRINT_ERROR("todo error");
 freeFinsFrame(ff);
 }
 }
 */
