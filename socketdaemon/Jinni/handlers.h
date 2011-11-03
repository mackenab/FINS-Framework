/*
 * handlers.h
 *
 *  Created on: Mar 6, 2011
 *      Author: Abdallah Abdallah
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
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/netlink.h>
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
#include "icmpHandling.h"

/** FINS Sockets database related defined constants */
#define MAX_sockets 100
#define MaxChildrenNumSharingSocket 100
#define MAX_parallel_threads 10
#define MAX_Queue_size 100000
#define MAX_parallel_processes 10
#define ACK 	200
#define NACK 	6666

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
/**
 *
 */
#define close_call 19
#define release_call 20
#define ioctl_call 21
#define daemonconnect_call 22

//fins netlink stuff
#define NETLINK_FINS	20		// Pick an appropriate protocol or define a new one in include/linux/netlink.h
struct sockaddr_nl local_sockaddress; // sockaddr_nl for this process (source)
struct sockaddr_nl kernel_sockaddress; // sockaddr_nl for the kernel (destination)
int nl_sockfd; //temp for now


enum sockOptions {





	FSO_DEBUG = 1,
	FSO_REUSEADDR,
	FSO_TYPE	,
	FSO_ERROR	,
	FSO_DONTROUTE	,
	FSO_BROADCAST	,
	FSO_SNDBUF	,
	FSO_RCVBUF	,
	FSO_KEEPALIVE	,
	FSO_OOBINLINE	,
	FSO_NO_CHECK	,
	FSO_PRIORITY,
	FSO_LINGER	,
	FSO_BSDCOMPAT	,  		/** 14 */
	FSO_REUSEPORT = 15 ,  /** FSO_REUSEPORT = 15 */
	FSO_PASSCRED= 16,
	FSO_PEERCRED ,
	FSO_RCVLOWAT,
	FSO_SNDLOWAT,
	FSO_RCVTIMEO,
	FSO_SNDTIMEO,   /** SO_SNDTIMEO	21 */

	FSO_BINDTODEVICE = 25,
	FSO_TIMESTAMP= 29,
	FSO_ACCEPTCONN = 30,
	 FSO_PEERSEC = 31,
	FSO_SNDBUFFORCE	=32,
	FSO_RCVBUFFORCE=	33,



} ;


struct tcp_Parameters
{

	 int SHUT_RD;
	 int SHUT_WR ;





};


struct finssocket {
	/** variables tells a connect call has been called over this socket or not in order to
	 * check the address of the senders of the received datagrams against the address which this
	 * socket is connected to it before approving or dropping any datagram
	 */
	int connection_status;
	unsigned long long uniqueSockID;
	pid_t childrenList[MaxChildrenNumSharingSocket];
	int jinniside_pipe_ds; /**  the descriptor to access the pipe from the jinni side */
	int type;
	int protocol;

	/** check the opt_name to find which bit to access in the options variable then use
	 * the following code to handle the bits individually
	 * setting a bit   number |= 1 << x;  That will set bit x.
	 * Clearing a bit number &= ~(1 << x); That will clear bit x.
	 * The XOR operator (^) can be used to toggle a bit. number ^= 1 << x; That will toggle bit x.
	 * Checking a bit      value = number & (1 << x);
	 */
	uint32_t socketoptions;
	int blockingFlag;
	struct tcp_Parameters tcpParameters;

	/** All the above already initialized using the insert function
	 * the remaining below is handled using the update function*/
	uint16_t hostport; //host format
	uint16_t dstport; //host format
	uint32_t host_IP; //host format
	uint32_t dst_IP; //host format
	char name[50];
	int data_pipe[2];
	finsQueue dataQueue;
	sem_t Qs; /** The data Queue Semaphore Pointer*/

	char semaphore_name[30]; /** The client channel semaphore name */
	char asemaphore_name[30];
	sem_t *s; /** The client channel semaphore pointer*/
	sem_t *as;
};

//ADDED mrd015 !!!!! (this crap really needs to be gathered into one header.)
#ifdef BUILD_FOR_ANDROID
	#define FINS_TMP_ROOT "/data/data/fins"
#else
	#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define MAIN_SOCKET_CHANNEL FINS_TMP_ROOT "/mainsocket_channel"
#define CLIENT_CHANNEL_TX FINS_TMP_ROOT "/uniqueSockID_%llu_TX"
#define CLIENT_CHANNEL_RX FINS_TMP_ROOT "/uniqueSockID_%llu_RX"
#define RTM_PIPE_IN FINS_TMP_ROOT "/rtm_in"
#define RTM_PIPE_OUT FINS_TMP_ROOT "/rtm_out"

int init_fins_nl();
int send_wedge(int sockfd, void *buf, size_t len, int flags);

int nack_send(unsigned long long uniqueSockID, int socketCallType);
int ack_send(unsigned long long uniqueSockID, int socketCallType);

void init_jinnisockets();
int randoming(int min, int max);
int checkjinniSocket(unsigned long long uniqueSockID);
int matchjinniSocket(uint16_t dstport, uint32_t dstip, int protocol);
int findjinniSocket(unsigned long long uniqueSockID);
int insertjinniSocket(unsigned long long uniqueSockID, int type,
		int protocol);
int removejinniSocket(unsigned long long uniqueSockID);
int checkjinniports(uint16_t hostport, uint32_t hostip);

int nack_write(int pipe_desc, unsigned long long uniqueSockID);
int ack_write(int pipe_desc, unsigned long long uniqueSockID);

/** calls handling functions */
void socket_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void socketpair_call_handler();
void bind_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void getsockname_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void connect_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void getpeername_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void send_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void recv_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void sendto_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void recvfrom_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void sendmsg_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void recvmsg_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void getsockopt_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void setsockopt_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void listen_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void accept_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void accept4_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);
void shutdown_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);

void close_call_handler(unsigned long long uniqueSockID, unsigned char *buf, ssize_t len);

#endif /* HANDLERS_H_ */
