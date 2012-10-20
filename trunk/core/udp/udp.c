/**
 * 	UDP test.c
 *
 *  Created on: Jun 30, 2010
 *      Author: Abdallah Abdallah
 */

//Kevin added some debugging code in this file to print out the received control frames and send back a response
//The control frames were never updated to the new types
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <finstypes.h>
#include <queueModule.h>
#include <pthread.h>
#include "udp.h"

#define DUMMYA 123
#define DUMMYB 456
#define DUMMYC 789

int udp_running;
pthread_t switch_to_udp_thread;

sem_t UDP_to_Switch_Qsem;
finsQueue UDP_to_Switch_Queue;

sem_t Switch_to_UDP_Qsem;
finsQueue Switch_to_UDP_Queue;

struct udp_statistics udpStat;

void udp_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	sem_wait(&UDP_to_Switch_Qsem);
	write_queue(ff, UDP_to_Switch_Queue);
	sem_post(&UDP_to_Switch_Qsem);
}

void udp_get_ff(void) {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_UDP_Qsem);
		ff = read_queue(Switch_to_UDP_Queue);
		sem_post(&Switch_to_UDP_Qsem);
	} while (udp_running && ff == NULL);

	if (!udp_running) {
		return;
	}

	udpStat.totalRecieved++;
	PRINT_DEBUG("UDP Total %d, ff=%p, meta=%p", udpStat.totalRecieved, ff, ff->metaData);
	if (ff->dataOrCtrl == CONTROL) {
		udp_fcf(ff);
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == UP) {
			udp_in(ff);
			PRINT_DEBUG("");
		} else if (ff->dataFrame.directionFlag == DOWN) {
			udp_out(ff);
			PRINT_DEBUG("");
		}
	} else {
		PRINT_ERROR("todo error");
	}
}

void udp_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		freeFinsFrame(ff);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		freeFinsFrame(ff);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		//daemon_read_param_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		freeFinsFrame(ff);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		//daemon_set_param_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		freeFinsFrame(ff);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		//daemon_exec_reply(ff);
		freeFinsFrame(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		udp_error(ff);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		freeFinsFrame(ff);
		break;
	}
}

void udp_error(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

	int ret = 0;

	metadata *params = ff->metaData;
	if (params) {
		switch (ff->ctrlFrame.param_id) {
		case ERROR_ICMP_TTL:
			PRINT_DEBUG("param_id=ERROR_ICMP_TTL (%d)", ff->ctrlFrame.param_id);

			if (ret) {
				PRINT_ERROR("todo error");
				return;
			}
			PRINT_DEBUG("todo");

			//TODO finish for
			//if (ff->ctrlFrame.para)
			freeFinsFrame(ff);
			break;
		case ERROR_ICMP_DEST_UNREACH:
			PRINT_DEBUG("param_id=ERROR_ICMP_DEST_UNREACH (%d)", ff->ctrlFrame.param_id);

			if (ret) {
				PRINT_ERROR("todo error");
				return;
			}
			PRINT_DEBUG("todo");

			//TODO finish
			freeFinsFrame(ff);
			break;
		default:
			PRINT_ERROR("Error unknown param_id=%d", ff->ctrlFrame.param_id);
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

void *switch_to_udp(void *local) {
	PRINT_DEBUG("Entered");

	while (udp_running) {
		udp_get_ff();
		PRINT_DEBUG("");
		//	free(ff);
	}

	PRINT_DEBUG("Exited");
	pthread_exit(NULL);
}

void udp_init(void) {
	PRINT_DEBUG("Entered");
	udp_running = 1;
}

void udp_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Entered");

	pthread_create(&switch_to_udp_thread, fins_pthread_attr, switch_to_udp, fins_pthread_attr);
}

void udp_shutdown(void) {
	PRINT_DEBUG("Entered");
	udp_running = 0;

	//TODO expand this

	pthread_join(switch_to_udp_thread, NULL);
}

void udp_release(void) {
	PRINT_DEBUG("Entered");

	//TODO free all module related mem

	term_queue(UDP_to_Switch_Queue);
	term_queue(Switch_to_UDP_Queue);
}
