/*
 * rtm.c
 *
 *  @date June 14, 2011
 *      @author: Abdallah Abdallah
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <finstypes.h>
#include <queueModule.h>
#include "rtm.h"

extern sem_t RTM_to_Switch_Qsem;
extern finsQueue RTM_to_Switch_Queue;

extern sem_t Switch_to_RTM_Qsem;
extern finsQueue Switch_to_RTM_Queue;


extern int rtm_in_fd;
extern int rtm_out_fd;

#define RTM_PIPE_IN "/tmp/fins/rtm_in"
#define RTM_PIPE_OUT "/tmp/fins/rtm_out"



void rtm_get_FF() {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_RTM_Qsem);
		ff = read_queue(Switch_to_RTM_Queue);
		sem_post(&Switch_to_RTM_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL) {
		// send to something to deal with FCF
		PRINT_DEBUG("send to CONTROL HANDLER !");
	}
	else
	{



	}

}



void rtm_init() {

	printf("RTM started");


	char data[1000];
	int datalen;
	int numBytes;
	struct finsFrame *ff = NULL;

//	rtm_in_fd = open(RTM_PIPE_OUT, O_WRONLY);
//
//		if (rtm_in_fd == -1) {
//			PRINT_DEBUG("rtm_in_fd Pipe failure \n");
//			exit(EXIT_FAILURE);
//		}

	rtm_out_fd = open(RTM_PIPE_IN, O_RDONLY);

			if (rtm_out_fd == -1) {
				PRINT_DEBUG("rtm_out_fd Pipe failure \n");
				exit(EXIT_FAILURE);
			}

			printf("RTM_IN Pipe line passed openning");
			fflush(stdout);

		while (1) {

			numBytes = read(rtm_in_fd, &datalen, sizeof(int));
			if (numBytes <= 0) {
				PRINT_DEBUG("numBytes written %d\n", numBytes);
				break;
			}

			//frame = (char *) malloc (framelen);
			numBytes = read(rtm_in_fd, &data, datalen);

			if (numBytes <= 0) {
				PRINT_DEBUG("numBytes written %d\n", numBytes);
				break;
			}

			data[datalen] = '\0';
			printf("\n received data %s \n", data);



		}




//
//	while (1) {
//
//			rtm_get_FF();
//			PRINT_DEBUG();
//			//	free(pff);
//
//
//		}

}
