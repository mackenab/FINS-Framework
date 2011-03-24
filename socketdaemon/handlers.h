/*
 * handlers.h
 *
 *  Created on: Mar 6, 2011
 *      Author: alex
 */

#ifndef HANDLERS_H_
#define HANDLERS_H_


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
//#include "arp.c"

/* to handle forking + pipes operations */
#include <unistd.h>
#include <sys/types.h>


#include "udpHandling.h"
#include "tcpHandling.h"


#define MAX_sockets 100
#define MAX_parallel_threads 10
#define MAX_Queue_size 1000
#define MAX_parallel_processes 10
#define ACK 	200
#define NACK 	6666


struct socket_call_msg
{
		int domain;
		int type;
		int protocol;
		int sockfd;
		int fakeID;

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

struct socketIdentifier
{
pid_t processID;
int sockerDesc;

};

#define MAIN_SOCKET_CHANNEL "/tmp/fins/mainsocket_channel"
#define CLIENT_CHANNEL_TX "/tmp/fins/processID_%d_TX_%d"
#define CLIENT_CHANNEL_RX "/tmp/fins/processID_%d_RX_%d"

int findjinniSocket(pid_t target1, int target2);

int matchjinniSocket(uint16_t dstport,uint32_t dstip,int protocol);

int insertjinniSocket(pid_t processID, int sockfd,int fakeID,int type,int protocol);
int removejinniSocket(pid_t target1, int target2) ;

int checkjinniports(uint16_t hostport, uint32_t hostip);

int nack_write( int pipe_desc, int processid, int sockfd);

int ack_write( int pipe_desc, int processid, int sockfd);

void socket_call_handler(pid_t senderProcessid);
void bind_call_handler(int senderid);
void send_call_handler(int senderid);
void sendto_call_handler(int senderid);
void recv_call_handler(int senderid);
void recvfrom_call_handler(int senderid);
void	sendmsg_call_handler();
void	recvmsg_call_handler();
void	getsockopt_call_handler();
void	setsockopt_call_handler();
void	listen_call_handler();

void	accept_call_handler();

void	accept4_call_handler();
void	shutdown_call_handler();
void	getsockname_call_handker();


void	connect_call_handler();
void	getpeername_call_handler();
void 	socketpair_call_handler();



#endif /* HANDLERS_H_ */
