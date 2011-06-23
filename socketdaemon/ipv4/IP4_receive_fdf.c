/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "ipv4.h"
#include <queueModule.h>

extern IP4addr my_ip_addr;

extern sem_t Switch_to_IPv4_Qsem;
extern finsQueue Switch_to_IPv4_Queue;

void IP4_receive_fdf() {

	struct finsFrame* pff = NULL;
	do {
		sem_wait(&Switch_to_IPv4_Qsem);
		pff = read_queue(Switch_to_IPv4_Queue);
		sem_post(&Switch_to_IPv4_Qsem);
	} while (pff == NULL);

	PRINT_DEBUG("Received frame: D/C: %d, DestID: %d", pff->dataOrCtrl,
			pff->destinationID.id);

	if (pff->dataOrCtrl == CONTROL) {
		/** TODO:  Here goes code for control messages */

	} else if (pff->dataOrCtrl == DATA) {
		PRINT_DEBUG("PDU Length: %d",pff->dataFrame.pduLength); PRINT_DEBUG("Data direction: %d",pff->dataFrame.directionFlag); PRINT_DEBUG("");

		if (pff->dataFrame.directionFlag == UP) {
			PRINT_DEBUG("");

			IP4_in(pff, (struct ip4_packet*) pff->dataFrame.pdu,
					pff->dataFrame.pduLength);
		} else if (pff->dataFrame.directionFlag == DOWN) {
			PRINT_DEBUG("");
			/** TODO extract the protocol from the metadata
			 * now it will be set by default to UDP
			 */
			PRINT_DEBUG("%d",my_ip_addr);
			IP4_out(pff, (pff->dataFrame).pduLength, my_ip_addr, IP4_PT_UDP);
			PRINT_DEBUG("");

		} else {
			PRINT_DEBUG("Wrong value of fdf.directionFlag");
		}
	}

	else {
		PRINT_DEBUG("Wrong pff->dataOrCtrl value");
	}

}
