/*
 * socketgeni.h
 *
 *  Created on: Nov 26, 2010
 *      Author: Abdallah Abdallah
 */

#ifndef SOCKETGENI_H_
#define SOCKETGENI_H_


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>




#include <linux/if_ether.h>
#include <pthread.h>
/** additional header for queues */
#include <queueModule.h>
/**additional headers for testing */
#include <finsdebug.h>
/** Additional header for meta-data manipulation */
#include <metadata.h>
#include "wifidemux.h"
//#include "arp.c"

/* to handle forking + pipes operations */
#include <unistd.h>
#include <sys/types.h>

#define MAX_sockets 100
#define MAX_parallel_threads 10
#define MAX_Queue_size 1000
#define MAX_parallel_processes 10
#define MAX_modules 	14
#define SNAP_LEN 4096



#define MAIN_SOCKET_CHANNEL "/tmp/fins/mainsocket_channel"
#define CLIENT_CHANNEL_TX "/tmp/fins/processID_%d_TX_%d"
#define CLIENT_CHANNEL_RX "/tmp/fins/processID_%d_RX_%d"

struct  socketUniqueID
{
	int processID;
	int socketDesc;
};

struct finssocket
{

pid_t processid;
int sockfd; /** it is equal to the value of the pipe descriptor from the client side */
int fakeID; /** The ID given by the interceptor side to distinguish this socket from other sockets
created by the sam process, it is used within the pipe name to open the correct pipe on both sides */
int jinniside_pipe_ds;  /**  the descriptor to access the pipe from the jinni side */
int type;
int protocol;
/** All the above already initialized using the insert function
 * the remaining below is handled using the update function*/
uint16_t hostport;
uint16_t dstport;
uint32_t host_IP;
uint32_t dst_IP;
char name[50];
int     data_pipe[2];
finsQueue dataQueue;
sem_t Qs; /** The data Queue Semaphore Pointer*/
char semaphore_name[30]; /** The client channel semaphore name */
char asemaphore_name[30];
sem_t *s; /** The client channel semaphore pointer*/
sem_t *as;
};


struct bind_call_msg
{
	int sockfd;
	socklen_t addrlen;
	struct sockaddr addr;


};



struct socketIdentifier
{
pid_t processID;
int sockerDesc;

};





void init_jinnisockets();
int checkjinniSocket(pid_t target1, int target2);
int matchjinniSocket(uint16_t dstport,uint32_t dstip,int protocol);
int findjinniSocket(pid_t target1, int target2);

int insertjinniSocket(pid_t processID, int sockfd,int fakeID,int type,int protocol);
int removejinniSocket(pid_t target1, int target2);
int checkjinniports(uint16_t hostport);


void jinni_init();
void Queues_init();
int ack_write(int pipe_desc,int processid,int sockfd);
int nack_write( int pipe_desc, int processid, int sockfd);






/** Socket related calls and their codes */
#define socket_call 1
#define socketpair_call 2
#define bind_call 3
#define getsockname_call 4
#define connect_call 5
#define getpeername_call 6
#define send_call 7
#define recv_call 8
#define sendto_call 9
#define recvfrom_call 10
#define sendmsg_call 11
#define recvmsg_call 12
#define getsockopt_call 13
#define setsockopt_call 14
#define listen_call 15
#define accept_call 16
#define accept4_call 17
#define shutdown_call 18
#define ACK 	200
#define NACK 	6666


	/** calls handling functions */
		void 	socket_call_handler(pid_t senderProcessid);
		void 	socketpair_call_handler();
		void 	bind_call_handler(int senderid);
		void	getsockname_call_handker();
		void	connect_call_handler();
		void	getpeername_call_handler();
		void	send_call_handler(int senderid);
		void	recv_call_handler(int senderid);
		void	sendto_call_handler();
		void	recvfrom_call_handler();
		void	sendmsg_call_handler();
		void	recvmsg_call_handler();
		void	getsockopt_call_handler();
		void	setsockopt_call_handler();
		void	listen_call_handler();
		void	accept_call_handler();
		void	accept4_call_handler();
		void	shutdown_call_handler();


 /** special functions to print the data within a frame for testing*/
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

		 	int i;
		 	int gap;
		 	const u_char *ch;

		 	/* offset */
		 	printf("%05d   ", offset);

		 	/* hex */
		 	ch = payload;
		 	for(i = 0; i < len; i++) {
		 		printf("%02x ", *ch);
		 		ch++;
		 		/* print extra space after 8th byte for visual aid */
		 		if (i == 7)
		 			printf(" ");
		 	}
		 	/* print space to handle line less than 8 bytes */
		 	if (len < 8)
		 		printf(" ");

		 	/* fill hex gap with spaces if not full line */
		 	if (len < 16) {
		 		gap = 16 - len;
		 		for (i = 0; i < gap; i++) {
		 			printf("   ");
		 		}
		 	}
		 	printf("   ");

		 	/* ascii (if printable) */
		 	ch = payload;
		 	for(i = 0; i < len; i++) {
		 		if (isprint(*ch))
		 			printf("%c", *ch);
		 		else
		 			printf(".");
		 		ch++;
		 	}

		 	printf("\n");

		 return;

} //end of print_hex_ascii_line()






void print_frame(const u_char *payload, int len)
		 {

		 	PRINT_DEBUG("passed len = %d", len);
		 	int len_rem = len;
		 	int line_width = 16;			/* number of bytes per line */
		 	int line_len;
		 	int offset = 0;					/* zero-based offset counter */
		 	const u_char *ch = payload;


		 	if (len <= 0)
		 		return;

		 	/* data fits on one line */
		 	if (len <= line_width) {
		 		PRINT_DEBUG("calling hex_ascii_line");
		 		print_hex_ascii_line(ch, len, offset);
		 		return;
		 	}

		 	/* data spans multiple lines */
		 	for ( ;; ) {
		 		/* compute current line length */
		 		line_len = line_width % len_rem;
		 		/* print line */
		 		print_hex_ascii_line(ch, line_len, offset);
		 		/* compute total remaining */
		 		len_rem = len_rem - line_len;
		 		/* shift pointer to remaining bytes to print */
		 		ch = ch + line_len;
		 		/* add offset */
		 		offset = offset + line_width;
		 		/* check if we have line width chars or less */
		 		if (len_rem <= line_width) {
		 			/* print last line and get out */
		 			print_hex_ascii_line(ch, len_rem, offset);
		 			break;
		 		}
		 	}

		 return;
		 } // end of print_frame
/** ---------------------------------------------------------*/


#endif /* SOCKETGENI_H_ */

