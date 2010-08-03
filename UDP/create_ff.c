/**@file create_ff.c
 * create_ff.c
 *
 *  Created on: Jul 5, 2010
 *      Author: alex
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "finstype.h"
#include "udp.h"

/**@brief generates and returns a new Fins Frame using the paramters provided
 * @param dataOrCtrl tells whether or not to make an FCF or FDF
 * @param direction 0 for incoming, up the stack: 1 for outgoing, down the stack
 * @param destID the ID of the module that the FF should be sent to
 * @param PDU_length the length of the PDU
 * @param PDU a pointer to where the PDU actually is
 * @param metadata a pointer to the metadata
 */


extern struct udp_statistics udpStat;

struct finsFrame* create_ff(int dataOrCtrl, int direction, int destID,
		int PDU_length, unsigned char* PDU, unsigned char* metadata) {
	struct finsFrame ff;

	if (dataOrCtrl == DATA) {
		ff.dataOrCtrl = dataOrCtrl;
		ff.destinationID = destID;
		ff.dataFrame.pduLength = PDU_length;

		ff.dataFrame.directionFlag = direction;
		ff.dataFrame.pduLength = PDU_length;
		ff.dataFrame.pdu = PDU;
		memcpy(&ff.dataFrame.metaData, metadata, MAX_METADATASIZE);
	}

	if (dataOrCtrl == CONTROL) {
		ff.dataOrCtrl = dataOrCtrl;
		ff.destinationID = destID;
		// fill the important FCF data in here
	}

	struct finsFrame* ff_return;
	ff_return = &ff;
	return ff_return;
}
