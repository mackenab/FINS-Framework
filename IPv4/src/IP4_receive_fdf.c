/*
 * IP4_fdf_in.c
 *
 *  Created on: Jun 24, 2010
 *      Author: rado
 */

#include "IP4.h"

extern IP4addr my_ip_addr;

int InputQueue_Read_local(struct finsFrame *pff)
{
	InputQueue_Read(pff);
	if (pff->dataOrCtrl == DATA)
	{
		void *pdu = malloc(pff->dataFrame.pduLength);
		memcpy(pdu, pff->dataFrame.pdu, pff->dataFrame.pduLength);
		free(pff->dataFrame.pdu);
		pff->dataFrame.pdu = pdu;
	} else
	{

		//todo: do the copy for control if requested by Abdallah
	}
	return (1);
}

void IP4_receive_fdf(struct finsFrame* pff)
{
	InputQueue_Read_local(pff);
	PRINT_DEBUG("Received frame: D/C: %d, DestID: %d", pff->dataOrCtrl,
			pff->destinationID);
	if (pff->dataOrCtrl == DATA)
	{
		PRINT_DEBUG("Data direction: %d",pff->dataFrame.directionFlag);
		if (pff->dataFrame.directionFlag == UP)
		{
			IP4_in((struct ip4_packet*) pff->dataFrame.pdu,
					pff->dataFrame.pduLength);
		} else if (pff->dataFrame.directionFlag == DOWN)
		{
			IP4_out((void*) pff->dataFrame.pdu, pff->dataFrame.pduLength,
					my_ip_addr, *((IP4addr*) &pff->dataFrame.metaData[0]),
					IP4_PT_TCP);
		} else
		{
			PRINT_DEBUG("Wrong value of fdf.directionFlag");
		}
	} else if (pff->dataOrCtrl == CONTROL)
	{
		/* Here goes code for todo: control messages */
	} else
	{
		PRINT_DEBUG("Wrong pff->dataOrCtrl value");
	}
}
