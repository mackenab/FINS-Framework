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
		/** TODO:  Here goes code for control messages */

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
