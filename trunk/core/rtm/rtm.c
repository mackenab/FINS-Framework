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
sem_t RTM_to_Switch_Qsem;
finsQueue RTM_to_Switch_Queue;

//declares external semaphores to manage/protect the RTM_to_Switch Queue due to multithreading
sem_t Switch_to_RTM_Qsem;
finsQueue Switch_to_RTM_Queue;

//declares file descriptors for the two pipes
int rtm_in_fd;
int rtm_out_fd;


//ADDED mrd015 !!!!! (this crap really needs to be gathered into one header.)
#ifdef BUILD_FOR_ANDROID
//#define FINS_TMP_ROOT "/data/data/fins"
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_PIPE_IN FINS_TMP_ROOT "/rtm_in"
#define RTM_PIPE_OUT FINS_TMP_ROOT "/rtm_out"

//Code to receive a finsFrame from the Switch
void rtm_get_ff(void) {
	int numBytes = 0;

	struct finsFrame *ff;
	do {
		secure_sem_wait(&Switch_to_RTM_Qsem);
		ff = read_queue(Switch_to_RTM_Queue);
		sem_post(&Switch_to_RTM_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL) { //CONTROL FF
		// send to something to deal with FCF
		//format: || Data/Control | Destination_IDs_List | SenderID | Write_parameter_Confirmation_Code | Serial_Number ||

		PRINT_DEBUG("send to CONTROL HANDLER !");
		PRINT_DEBUG("dataOrCtrl parameter has been set to %d", (int)(ff->dataOrCtrl));
		PRINT_DEBUG("destinationID parameter has been set to %d", (int)(ff->destinationID.id));
		PRINT_DEBUG("opcode parameter has been set to %d", ff->ctrlFrame.opcode);
		PRINT_DEBUG("senderID parameter has been set to %d", (int)(ff->ctrlFrame.senderID));

		//PRINT_DEBUG("serial_num parameter has been set to %d",ff->ctrlFrame.serial_num);

		//Currently it serializes and sends any Control Frame it receives over the rtm_out pipe
		rtm_out_fd = open(RTM_PIPE_OUT, O_RDWR); //should not be O_RDWR, should be WRITE ONLY

		//FOWARD CONFIRMATION FRAME TO CLICOMM
		//|| Data/Control | Destination_IDs_List | SenderID | Write_parameter_Confirmation_Code | Serial_Number ||
		// reimplement with the new serialize function
		numBytes = 0;
		numBytes += write(rtm_out_fd, &ff->dataOrCtrl, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->destinationID.id, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.senderID, sizeof(unsigned char));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.opcode, sizeof(unsigned short int));
		numBytes += write(rtm_out_fd, &ff->ctrlFrame.serial_num, sizeof(unsigned int));
		PRINT_DEBUG ("serial_num %d", ff->ctrlFrame.serial_num);

	} else //DATA FF
	{
		PRINT_DEBUG("Find out what to do with data frames");
	}

}

//RTM's main function
//Gets information from RTM_IN pipe
//Is started as a thread in core.c
void rtm_init(pthread_attr_t *fins_pthread_attr) {

	PRINT_IMPORTANT("RTM has started");

	/*
	 //added to include code from fins_daemon.sh -- mrd015 !!!!! //TODO move this to RTM module
	 if (mkfifo(RTM_PIPE_IN, 0777) != 0) {
	 if (errno == EEXIST) {
	 PRINT_DEBUG("mkfifo(" RTM_PIPE_IN ", 0777) already exists.");
	 } else {
	 PRINT_ERROR("mkfifo(" RTM_PIPE_IN ", 0777) failed.");
	 exit(-1);
	 }
	 }
	 if (mkfifo(RTM_PIPE_OUT, 0777) != 0) {
	 if (errno == EEXIST) {
	 PRINT_DEBUG("mkfifo(" RTM_PIPE_OUT ", 0777) already exists.");
	 } else {
	 PRINT_ERROR("mkfifo(" RTM_PIPE_OUT ", 0777) failed.");
	 exit(-1);
	 }
	 }
	 */

	//int datalen;
	int numBytes;
	//int val_len;
	int temp_serial_cntr = 0;
	unsigned char* serialized_FCF = NULL;
	int length_serialized_FCF;

	//create a finsframe to be sent tover the queue
	struct finsFrame *fins_frame = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
	fins_frame->dataOrCtrl = CONTROL;

	//opens the pipe from clicomm (or wherever)
	rtm_in_fd = open(RTM_PIPE_IN, O_RDWR);

	if (rtm_in_fd == -1) {
		PRINT_DEBUG("rtm_in_fd Pipe failure ");
		exit(EXIT_FAILURE);
	}

	fflush(stdout);

	while (1) {
		temp_serial_cntr++; //used as a temporary serial_number generator

		//READ FROM PIPE RTM_IN
		numBytes = 0;
		numBytes += read(rtm_in_fd, &length_serialized_FCF, sizeof(int)); //length of incoming serialized FCF
		numBytes += read(rtm_in_fd, serialized_FCF, length_serialized_FCF); //incoming serialized FCF

		fins_frame = unserializeCtrlFrame(serialized_FCF, length_serialized_FCF);

		//value, Assumption was made, notice the size
		PRINT_DEBUG("received data");
		numBytes = 0;

		//ERROR Message
		fflush(stdout);
		if (numBytes >= 0) {
			PRINT_DEBUG("numBytes written %d", numBytes);
		}

		//CHANGE SenderID and SerialNum
		fins_frame->ctrlFrame.senderID = RTM_ID;
		fins_frame->ctrlFrame.serial_num = temp_serial_cntr;

		//SEND TO QUEUE
		secure_sem_wait(&RTM_to_Switch_Qsem);
		write_queue(fins_frame, RTM_to_Switch_Queue);
		sem_post(&RTM_to_Switch_Qsem);
		PRINT_DEBUG("sent data ");

		//READ FROM QUEUE
		rtm_get_ff();
	}
}
