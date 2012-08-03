/*
 * rtm.c
 *
 *  Created on: Jul 10, 2012
 *      Author: bamj001, atm011
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "finstypes.h"
#include <queueModule.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include "rtm.h"

//declares external semaphores to manage/protect the RTM_to_Switch Queue multithreading
extern sem_t RTM_to_Switch_Qsem;
extern finsQueue RTM_to_Switch_Queue;

//declares external semaphores to manage/protect the RTM_to_Switch Queue due to multithreading
extern sem_t Switch_to_RTM_Qsem;
extern finsQueue Switch_to_RTM_Queue;

//declares the file descriptor for the Unix domain socket
int rtm_in_fd, rtm_in_fd1;

//pthread id
pthread_t pid;

//Struct for args passed to rtm_send_ff
//struct args {
//int socket;
//struct finsFrame *ff;
//};



//defines named socket locations for rtm
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/fins"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define RTM_SOCK_IN FINS_TMP_ROOT "/rtm_in"


//Code to receive a finsFrame from the Switch and send it over the socket
// This is designed to run in its own thread
void* rtm_get_FF(void* socket) {
	for(;;){	
	int numBytes = 0;

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_RTM_Qsem);
		ff = read_queue(Switch_to_RTM_Queue);
		sem_post(&Switch_to_RTM_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL)
	{
		PRINT_DEBUG("RTM: send to CONTROL HANDLER !");
		PRINT_DEBUG("RTM: dataOrCtrl parameter has been set to %d",(int)(ff->dataOrCtrl));
		PRINT_DEBUG("RTM: destinationID parameter has been set to %d",(int)(ff->destinationID.id));
		PRINT_DEBUG("RTM: opcode parameter has been set to %d",ff->ctrlFrame.opcode);
		PRINT_DEBUG("RTM: senderID parameter has been set to %d",(int)(ff->ctrlFrame.senderID));

		PRINT_DEBUG("RTM: serialNum parameter has been set to %d",ff->ctrlFrame.serialNum);
		PRINT_DEBUG("RTM: data parameter has been set to %d",(int) ff->ctrlFrame.data);
		
		//Creates the buffer
		unsigned char *buffer;
		//Serializes the finsFrame to be sent back out to the external app
		int length = serializeCtrlFrame(ff, &buffer);
		//Printing contents of buffer for debugging purposes
		PRINT_DEBUG("Printing buffer...");
		int i;
		for (i = 0; i < 32; i++) {
		printf("char: %d is %c as char or %u as unsigned int\n", i, *(buffer + i),(unsigned int) *(buffer + 			i));
		} 

		//PRINT_DEBUG("BUFFER LENGTH: %d", strlen(buffer));
	   	int numBytes = 0;
		//Sending length of finsFrame over the socket
		numBytes += send(rtm_in_fd1, &length, sizeof(int),0);
		perror("Sending length of buffer: ");
		//Sending the serialized finsFrame over the socket
		numBytes += send(rtm_in_fd1, buffer, length,0);
		perror("Sending buffer: ");
		PRINT_DEBUG("numbytes = %d",numBytes);
		
	

	}
	else//DATA FF
	{
		PRINT_DEBUG("RTM: Find out what to do with data frames")
	}
		PRINT_DEBUG("FRAME SENT OVER SOCKET!");
	}
}
//recvr function to be called every time a thread is created
//for each new connection
//Designed to be run in its own thread
void* recvr (void* socket){
	//initializes all necessary variables
	int numBytes;
	int temp_serial_cntr = 0;
	unsigned char * serialized_FCF;
	int length_serialized_FCF;

	PRINT_DEBUG("recvr running");
	//create a fins frame to be sent over the queue
	struct finsFrame *fins_frame = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	fins_frame->dataOrCtrl = CONTROL;
	for(;;){
		//checks for errors
		if(rtm_in_fd1 == -1){
			perror("accept");
		}
		else {
			temp_serial_cntr++;	//used as a temporary serialNumber generator

			//RECEIVE FROM RTM_IN
			numBytes = 0;
			numBytes += recv(rtm_in_fd1, &length_serialized_FCF, sizeof(int), 0);	//length of incoming serialized FCF
			perror("receiving buffer length: ");
			printf("length_serialized_FCF: %d\n", length_serialized_FCF);
			PRINT_DEBUG("number of bytes of buffer length received by RTM: %d", numBytes);
			serialized_FCF = malloc(length_serialized_FCF);
			numBytes += recv(rtm_in_fd1, serialized_FCF, length_serialized_FCF, 0);	//incoming serialized FCF
			int i =0;
			for (i = 0; i < 27; i++) {
				printf("char: %d %u\n", i, (unsigned int) serialized_FCF[i]/*,(int) *(serialized_FCF + i)*/);
			} 			
			perror("receiving serialized FCF: ");	
			PRINT_DEBUG("length of buffer: %d", length_serialized_FCF);
			PRINT_DEBUG("TOTAL number of bytes received by RTM: %d", numBytes);
			PRINT_DEBUG("Printing buffer...");

			
                        //PRINT_DEBUG("finsframe raw: %s", serialized_FCF);
			fins_frame = unserializeCtrlFrame(serialized_FCF,length_serialized_FCF);

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
			break;
		}
		
	}
	//pthread_exit(NULL);
	//close(rtm_in_fd1);
	return((void *)0);

}

//RTM's main function
//Gets information from RTM_IN socket
//Is started as a thread in core.c
void rtm_init() {
	//Initializes all necessary variables to create the socket and the threads
	uint32_t i = 0;
	struct sockaddr_un server;
	//pthread_t threads[5];
	PRINT_DEBUG("RTM: RTM has started");


	//creates a socket
	rtm_in_fd = socket(AF_UNIX,SOCK_STREAM,0);
	//checks for error
	if (rtm_in_fd == -1)
	{
		PRINT_DEBUG("rtm_in_fd socket failure \n");
		exit(EXIT_FAILURE);
	}
	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, "/tmp/socket");
	//checks for binding error
	if (bind(rtm_in_fd, (struct sockaddr *) &server, sizeof(struct sockaddr_un))< 0) {
		perror("binding stream socket");
		exit(1);
	}
	// creates fins attr to be the new created threads attr
	pthread_attr_t fins_pthread_attr;
	//initialize attr
	pthread_attr_init(&fins_pthread_attr);

	fflush(stdout);
	//listen to all incoming connections
	listen(rtm_in_fd, 5);
	pthread_create(&pid, &fins_pthread_attr, rtm_get_FF, NULL);
	while(1){
		//accept connection
		rtm_in_fd1 = accept(rtm_in_fd,0,0);
		//create thread for each connection that comes in
		//pthread_create(&threads[i],&fins_pthread_attr,recvr,NULL);
		recvr((void *) socket);
		//increment thread counter
		i++;

	}
	//close socket and unlink name
	close(rtm_in_fd);
	unlink("/tmp/socket");
}


