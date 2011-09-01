/**
 * 	UDP test.c
 *
 *  Created on: Jun 30, 2010
 *      Author: Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <finstypes.h>
#include <queueModule.h>
#include "udp.h"

struct udp_statistics udpStat;
extern sem_t UDP_to_Switch_Qsem;
extern finsQueue UDP_to_Switch_Queue;

extern sem_t Switch_to_UDP_Qsem;
extern finsQueue Switch_to_UDP_Queue;

void sendToSwitch(struct finsFrame *ff) {

	sem_wait(&UDP_to_Switch_Qsem);
	write_queue(ff, UDP_to_Switch_Queue);
	sem_post(&UDP_to_Switch_Qsem);

}

void udp_get_FF() {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_UDP_Qsem);
		ff = read_queue(Switch_to_UDP_Queue);
		sem_post(&Switch_to_UDP_Qsem);
	} while (ff == NULL);

	udpStat.totalRecieved++;
	PRINT_DEBUG("UDP Total %d", udpStat.totalRecieved);
	if (ff->dataOrCtrl == CONTROL) {
		// send to something to deal with FCF
		PRINT_DEBUG("send to CONTROL HANDLER !");
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == UP)) {
		udp_in(ff);
		PRINT_DEBUG();
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == DOWN)) {
		udp_out(ff);
		PRINT_DEBUG();
	}

}

void udp_init() {
	PRINT_DEBUG("UDP Started");
	while (1) {

		udp_get_FF();
		PRINT_DEBUG();
		//	free(pff);


	}

}
