/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

extern IP4addr my_ip_addr;

sem_t Switch_to_IPv4_Qsem;
finsQueue Switch_to_IPv4_Queue;

void IP4_receive_fdf() {

	struct finsFrame* pff = NULL;
	int protocol;
	do {
		sem_wait(&Switch_to_IPv4_Qsem);
		pff = read_queue(Switch_to_IPv4_Queue);
		sem_post(&Switch_to_IPv4_Qsem);
	} while (ipv4_running && pff == NULL);

	if (!ipv4_running) {
		return;
	}

	if (pff->dataOrCtrl == CONTROL) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID: %d, ff=%p meta=%p", pff->dataOrCtrl, pff->destinationID.id, pff, pff->metaData);
		ipv4_fcf(pff);
	} else if (pff->dataOrCtrl == DATA) {
		PRINT_DEBUG("Received frame: D/C: %d, DestID: %d, ff=%p meta=%p", pff->dataOrCtrl, pff->destinationID.id, pff, pff->metaData);
		PRINT_DEBUG("PDU Length: %d", pff->dataFrame.pduLength);
		PRINT_DEBUG("Data direction: %d", pff->dataFrame.directionFlag);
		PRINT_DEBUG("");

		if (pff->dataFrame.directionFlag == UP) {
			PRINT_DEBUG("");

			IP4_in(pff, (struct ip4_packet*) pff->dataFrame.pdu, pff->dataFrame.pduLength);

		} else if (pff->dataFrame.directionFlag == DOWN) {
			PRINT_DEBUG("");
			/** TODO extract the protocol from the metadata
			 * now it will be set by default to UDP
			 */
			int ret = 0;
			ret += metadata_readFromElement(pff->metaData, "protocol", &protocol) == CONFIG_FALSE;

			if (ret) {
				PRINT_DEBUG("metadata read error: ret=%d", ret);
			}

			PRINT_DEBUG("%lu", my_ip_addr);
			PRINT_DEBUG("Transport protocol going out passes to IPv4 is %d", protocol);
			switch (protocol) {
			case IP4_PT_UDP:
				IP4_out(pff, pff->dataFrame.pduLength, my_ip_addr, IP4_PT_UDP);
				break;
			case IP4_PT_ICMP:
				IP4_out(pff, pff->dataFrame.pduLength, my_ip_addr, IP4_PT_ICMP);
				break;
			case IP4_PT_TCP:
				IP4_out(pff, pff->dataFrame.pduLength, my_ip_addr, IP4_PT_TCP);
				break;
			default:
				PRINT_DEBUG("invalid protocol neither UDP nor ICMP !!!!!! protocol=%d", protocol);
				/**
				 * TODO investigate why the freeFinsFrame below create segmentation fault
				 */
				freeFinsFrame(pff);
				break;
			}

		} else {
			PRINT_DEBUG("Wrong value of fdf.directionFlag");
			freeFinsFrame(pff);
		}
	} else {
		PRINT_DEBUG("Wrong pff->dataOrCtrl value");
		freeFinsFrame(pff);
	}

}

void ipv4_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

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
		//ipv4_read_param(ff);
		//TODO read interface_mac?
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		//ipv4_set_param(ff);
		//TODO set interface_mac?
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		//ipv4_exec(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		ipv4_exec_reply(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		break;
	}
}

void ipv4_exec_reply_get_addr(struct finsFrame *ff, uint64_t src_mac, uint64_t dst_mac) {
	PRINT_DEBUG("Entered: ff=%p, src_mac=%llx, dst_mac=%llx", ff, src_mac, dst_mac);

	struct ip4_store *store = store_list_find(ff->ctrlFrame.serialNum);
	if (store) {
		store_list_remove(store);

		metadata *params = store->ff->metaData;

		uint32_t ether_type = (uint32_t) IP4_ETH_TYPE;
		metadata_writeToElement(params, "dst_mac", &dst_mac, META_TYPE_INT64);
		metadata_writeToElement(params, "src_mac", &src_mac, META_TYPE_INT64);
		metadata_writeToElement(params, "ether_type", &ether_type, META_TYPE_INT);

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

		//print_finsFrame(fins_frame);
		ipv4_to_switch(store->ff);

		PRINT_DEBUG("Freeing pdu=%p", store->pdu);
		free(store->pdu);
		store_free(store);

		freeFinsFrame(ff);
	} else {
		PRINT_DEBUG("todo error");
		//TODO error sending back FDF as FCF? saved pdu for that
	}
}

void ipv4_exec_reply(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

	int ret = 0;
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;

	metadata *params = ff->metaData;
	if (params) {
		ret += metadata_readFromElement(params, "exec_call", &exec_call) == CONFIG_FALSE;
		ret += metadata_readFromElement(params, "ret_val", &ret_val) == CONFIG_FALSE;

		switch (exec_call) {
		case EXEC_ARP_GET_ADDR:
			PRINT_DEBUG("exec_call=EXEC_ARP_GET_ADDR (%d)", exec_call);

			if (ret_val) {
				uint64_t src_mac, dst_mac;
				ret += metadata_readFromElement(params, "src_mac", &src_mac) == CONFIG_FALSE;
				ret += metadata_readFromElement(params, "dst_mac", &dst_mac) == CONFIG_FALSE;

				if (ret) {
					PRINT_ERROR("ret=%d", ret);
					//TODO send nack
				} else {
					//ipv4_exec_reply_get_addr(ff, src_mac, dst_mac);
					struct ip4_store *store = store_list_find(ff->ctrlFrame.serialNum);
					if (store) {
						store_list_remove(store);

						uint32_t ether_type = (uint32_t) IP4_ETH_TYPE;
						metadata_writeToElement(store->ff->metaData, "dst_mac", &dst_mac, META_TYPE_INT64);
						metadata_writeToElement(store->ff->metaData, "src_mac", &src_mac, META_TYPE_INT64);
						metadata_writeToElement(store->ff->metaData, "ether_type", &ether_type, META_TYPE_INT);

						PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

						//print_finsFrame(fins_frame);
						ipv4_to_switch(store->ff);

						PRINT_DEBUG("Freeing pdu=%p", store->pdu);
						free(store->pdu);
						store_free(store);

						freeFinsFrame(ff);
					} else {
						PRINT_DEBUG("todo error");
					}
				}
			} else {
				//TODO error sending back FDF as FCF? saved pdu for that
			}
			break;
		default:
			PRINT_ERROR("Error unknown exec_call=%d", exec_call);
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
