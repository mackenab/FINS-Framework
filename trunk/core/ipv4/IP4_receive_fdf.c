/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

#include <switch.h>
extern struct fins_proto_module ipv4_proto;

extern IP4addr my_ip_addr;

void IP4_receive_fdf(void) {

	struct finsFrame* ff = NULL;
	uint32_t protocol;

	do {
		sem_wait(ipv4_proto.event_sem);
		sem_wait(ipv4_proto.input_sem);
		ff = read_queue(ipv4_proto.input_queue);
		sem_post(ipv4_proto.input_sem);
	} while (ipv4_proto.running_flag && ff == NULL);

	if (!ipv4_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID=%d, ff=%p, meta=%p", ff->dataOrCtrl, ff->destinationID.id, ff, ff->metaData);
		ipv4_fcf(ff);
	} else if (ff->dataOrCtrl == DATA) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID=%d, ff=%p, meta=%p", ff->dataOrCtrl, ff->destinationID.id, ff, ff->metaData);
		PRINT_DEBUG("PDU Length: %d", ff->dataFrame.pduLength);
		PRINT_DEBUG("Data direction: %d", ff->dataFrame.directionFlag);
		PRINT_DEBUG("pdu=%p", ff->dataFrame.pdu);

		if (ff->dataFrame.directionFlag == UP) {
			PRINT_DEBUG("IP4_in");

			IP4_in(ff, (struct ip4_packet*) ff->dataFrame.pdu, ff->dataFrame.pduLength);

		} else if (ff->dataFrame.directionFlag == DOWN) {
			PRINT_DEBUG("IP4_out");

			metadata *params = ff->metaData;
			if (params == NULL) {
				PRINT_ERROR("todo error");
				freeFinsFrame(ff);
				return;
			}

			int ret = 0;
			ret += metadata_readFromElement(params, "send_protocol", &protocol) == META_FALSE;

			if (ret) {
				PRINT_ERROR("metadata read error: ret=%d", ret);
			}

			PRINT_DEBUG("%lu", my_ip_addr);
			PRINT_DEBUG("Transport protocol going out passed to IPv4: protocol=%u", protocol);
			switch (protocol) {
			case IP4_PT_ICMP:
				IP4_out(ff, ff->dataFrame.pduLength, my_ip_addr, IP4_PT_ICMP);
				break;
			case IP4_PT_TCP:
				IP4_out(ff, ff->dataFrame.pduLength, my_ip_addr, IP4_PT_TCP);
				break;
			case IP4_PT_UDP:
				IP4_out(ff, ff->dataFrame.pduLength, my_ip_addr, IP4_PT_UDP);
				break;
			default:
				PRINT_ERROR("invalid protocol: protocol=%u", protocol)
				;
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
		freeFinsFrame(ff);
	}

}

void ipv4_fcf(struct finsFrame *ff) {
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
		//ipv4_read_param(ff);
		//TODO read interface_mac?
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY)
		;
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM)
		;
		//ipv4_set_param(ff);
		//TODO set interface_mac?
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY)
		;
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC)
		;
		//ipv4_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY)
		;
		ipv4_exec_reply(ff);
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

void ipv4_exec_reply_get_addr(struct finsFrame *ff, uint64_t src_mac, uint64_t dst_mac) {
	PRINT_DEBUG("Entered: ff=%p, src_mac=%llx, dst_mac=%llx", ff, src_mac, dst_mac);

	struct ip4_store *store = store_list_find(ff->ctrlFrame.serial_num);
	if (store) {
		store_list_remove(store);

		metadata *params = store->ff->metaData;

		uint32_t ether_type = IP4_ETH_TYPE;
		metadata_writeToElement(params, "send_dst_mac", &dst_mac, META_TYPE_INT64);
		metadata_writeToElement(params, "send_src_mac", &src_mac, META_TYPE_INT64);
		metadata_writeToElement(params, "send_ether_type", &ether_type, META_TYPE_INT32);

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

		//print_finsFrame(fins_frame);
		ipv4_to_switch(store->ff);
		store->ff = NULL;

		store_free(store);

		freeFinsFrame(ff);
	} else {
		PRINT_ERROR("todo error");
		//TODO error sending back FDF as FCF? saved pdu for that
	}
}

void ipv4_exec_reply(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	int ret = 0;

	metadata *params = ff->metaData;
	if (params) {
		switch (ff->ctrlFrame.param_id) {
		case EXEC_ARP_GET_ADDR:
			PRINT_DEBUG("param_id=EXEC_ARP_GET_ADDR (%d)", ff->ctrlFrame.param_id)
			;

			if (ff->ctrlFrame.ret_val) {
				uint64_t src_mac, dst_mac;
				ret += metadata_readFromElement(params, "src_mac", &src_mac) == META_FALSE;
				ret += metadata_readFromElement(params, "dst_mac", &dst_mac) == META_FALSE;

				if (ret) {
					PRINT_ERROR("ret=%d", ret);
					//TODO send nack
				} else {
					//ipv4_exec_reply_get_addr(ff, src_mac, dst_mac);
					struct ip4_store *store = store_list_find(ff->ctrlFrame.serial_num);
					if (store) {
						PRINT_DEBUG("store=%p, ff=%p, serial_num=%u", store, store->ff, store->serial_num);
						store_list_remove(store);

						uint32_t ether_type = IP4_ETH_TYPE;
						metadata_writeToElement(store->ff->metaData, "send_ether_type", &ether_type, META_TYPE_INT32);
						metadata_writeToElement(store->ff->metaData, "send_dst_mac", &dst_mac, META_TYPE_INT64);
						metadata_writeToElement(store->ff->metaData, "send_src_mac", &src_mac, META_TYPE_INT64);

						PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

						//print_finsFrame(fins_frame);
						ipv4_to_switch(store->ff);
						store->ff = NULL;

						store_free(store);

						freeFinsFrame(ff);
					} else {
						PRINT_ERROR("todo error");
					}
				}
			} else {
				//TODO error sending back FDF as FCF? saved pdu for that
				PRINT_ERROR("todo error");
			}
			break;
		default:
			PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id)
			;
			//TODO implement?
			freeFinsFrame(ff);
			break;
		}
	} else {
		//TODO send nack
		PRINT_ERROR("Error fcf.metadata==NULL");
		freeFinsFrame(ff);
	}
}
