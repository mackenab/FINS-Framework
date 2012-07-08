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

//declares external semaphores to manage/protect the RTM_to_Switch Queue multithreading
extern sem_t RTM_to_Switch_Qsem;
extern finsQueue RTM_to_Switch_Queue;

//declares external semaphores to manage/protect the RTM_to_Switch Queue due to multithreading
extern sem_t Switch_to_RTM_Qsem;
extern finsQueue Switch_to_RTM_Queue;

//declares file descriptors for the two pipes
extern int rtm_in_fd;
extern int rtm_out_fd;

//defines named pipe localtions for rtm //ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
	#define FINS_TMP_ROOT "/data/data/fins"
#else
	#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_PIPE_IN FINS_TMP_ROOT "/rtm_in"
#define RTM_PIPE_OUT FINS_TMP_ROOT "/rtm_out"

//Code to receive a finsFrame from the Switch
void rtm_get_FF() {
	int numBytes = 0;
	
	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_RTM_Qsem);
		ff = read_queue(Switch_to_RTM_Queue);
		sem_post(&Switch_to_RTM_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL)
	{//CONTROL FF
		// send to something to deal with FCF
		//format: || Data/Control | Destination_IDs_List | SenderID | Write_parameter_Confirmation_Code | Serial_Number ||

		PRINT_DEBUG("RTM: send to CONTROL HANDLER !");
		PRINT_DEBUG("RTM: dataOrCtrl parameter has been set to %d",(int)(ff->dataOrCtrl));
		PRINT_DEBUG("RTM: destinationID parameter has been set to %d",(int)(ff->destinationID.id));
		PRINT_DEBUG("RTM: opcode parameter has been set to %d",ff->ctrlFrame.opcode);
		PRINT_DEBUG("RTM: senderID parameter has been set to %d",(int)(ff->ctrlFrame.senderID));

		//PRINT_DEBUG("RTM: serialNum parameter has been set to %d",ff->ctrlFrame.serialNum);

		//Currently it serializes and sends any Control Frame it receives over the rtm_out pipe
		rtm_out_fd = open(RTM_PIPE_OUT, O_RDWR);//should not be O_RDWR, should be WRITE ONLY

		//FOWARD CONFIRMATION FRAME TO CLICOMM
		//|| Data/Control | Destination_IDs_List | SenderID | Write_parameter_Confirmation_Code | Serial_Number ||
		// reimplement with the new serialize function
		numBytes = 0;
		numBytes += write(rtm_out_fd, &ff->dataOrCtrl, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->destinationID.id, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.senderID, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.opcode, sizeof(unsigned short int));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.serialNum, sizeof(unsigned int));
		PRINT_DEBUG("RTM: serialNum %d",ff->ctrlFrame.serialNum)

	}
	else//DATA FF
	{
		PRINT_DEBUG("RTM: Find out what to do with data frames")
	}

}

//RTM's main function
//Gets information from RTM_IN pipe
//Is started as a thread in core.c
void rtm_init() {

	PRINT_DEBUG("RTM: RTM has started");

	//int datalen;
	int numBytes;
	//int val_len;
	int temp_serial_cntr = 0;
	unsigned char* serialized_FCF;
	int length_serialized_FCF;

	//create a finsframe to be sent tover the queue
	struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	fins_frame->dataOrCtrl = CONTROL;

	//opens the pipe from clicomm (or wherever)
	rtm_in_fd = open(RTM_PIPE_IN, O_RDWR);

	if (rtm_in_fd == -1)
	{
		PRINT_DEBUG("rtm_in_fd Pipe failure \n");
		exit(EXIT_FAILURE);
	}

	fflush(stdout);
	
	while (1)
	{
		temp_serial_cntr++;	//used as a temporary serialNumber generator

		//READ FROM PIPE RTM_IN
		numBytes = 0;
		numBytes += read(rtm_in_fd, &length_serialized_FCF, sizeof(int));		//length of incoming serialized FCF
		numBytes += read(rtm_in_fd, serialized_FCF, length_serialized_FCF);		//incoming serialized FCF

		fins_frame = unserializeCtrlFrame(serialized_FCF,length_serialized_FCF);

		//value, Assumption was made, notice the size
		PRINT_DEBUG("RTM: received data");
		numBytes = 0;

		//ERROR Message
		fflush(stdout);
		if (numBytes >= 0)
		{
			PRINT_DEBUG("RTM: numBytes written %d", numBytes);
		}

		//CHANGE SenderID and SerialNum
		fins_frame->ctrlFrame.senderID = RTMID;
		fins_frame->ctrlFrame.serialNum = temp_serial_cntr;

		//SEND TO QUEUE
		sem_wait(&RTM_to_Switch_Qsem);
		write_queue(fins_frame, RTM_to_Switch_Queue);
		sem_post(&RTM_to_Switch_Qsem);
		PRINT_DEBUG("RTM: sent data ");

		//READ FROM QUEUE
		rtm_get_FF();
	}
}
