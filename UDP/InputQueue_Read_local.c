/*
 * InputQueue_Read_local.c
 *
 *  Created on: Jul 19, 2010
 *      Author: Rado
 *      Author: Alex
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "finstype.h"
#include "udp.h"

int UDP_InputQueue_Read_local(struct finsFrame *pff_local) {
	struct finsFrame *pff = 0;
	// one of these 2 will be the call to receive the FF
	//InputQueue_Read(pff);
	//queue_receive(pff);
	if (pff == NULL)
		printf("Failure, InputQueue_Read() didn't give anything useful");
	return (0);
	*pff_local = *pff;
	if (pff->dataOrCtrl == DATA) {
		if (pff->dataFrame.directionFlag == DOWN) {
			pff_local->dataFrame.pdu = malloc((pff->dataFrame.pduLength)+U_HEADER_LEN);
			memcpy((pff_local->dataFrame.pdu)+U_HEADER_LEN, pff->dataFrame.pdu,
					pff->dataFrame.pduLength);
			free(pff->dataFrame.pdu);
			free(pff);
		} else {
			pff_local->dataFrame.pdu = malloc(pff->dataFrame.pduLength);
			memcpy(pff_local->dataFrame.pdu, pff->dataFrame.pdu,
					pff->dataFrame.pduLength);
			free(pff->dataFrame.pdu);
			free(pff);
		}
	} else {
		//todo: do the copy for control if requested by Abdallah
	}
	return (1);
}
