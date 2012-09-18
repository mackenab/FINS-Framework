/*
 * daemon.h
 *
 *  Created on: Mar 6, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef DAEMON_H_
#define DAEMON_H_

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
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>

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
#define MAX_SOCKETS 100
#define MaxChildrenNumSharingSocket 100
#define MAX_parallel_threads 10
#define MAX_Queue_size 100000
#define MAX_parallel_processes 10
#define ACK 	200
#define NACK 	6666
#define MIN_port 32768
#define MAX_port 61000
#define DEFAULT_BACKLOG 5

/** Socket related calls and their codes */
#define socket_call 1
#define bind_call 2
#define listen_call 3
#define connect_call 4
#define accept_call 5
#define getname_call 6
#define ioctl_call 7
#define sendmsg_call 8
#define recvmsg_call 9
#define getsockopt_call 10
#define setsockopt_call 11
#define release_call 12
#define poll_call 13
#define mmap_call 14
#define socketpair_call 15
#define shutdown_call 16
#define close_call 17
#define sendpage_call 18
#define daemon_start_call 19
#define daemon_stop_call 20
/** Additional calls
 * To hande special cases
 * overwriting the generic functions which write to a socket descriptor
 * in order to make sure that we cover as many applications as possible
 * This range of these functions will start from 30
 */
#define MAX_CALL_TYPES 21

//fins netlink stuff
#define NETLINK_FINS	20		// Pick an appropriate protocol or define a new one in include/linux/netlink.h
struct sockaddr_nl local_sockaddress; // sockaddr_nl for this process (source)
struct sockaddr_nl kernel_sockaddress; // sockaddr_nl for the kernel (destination)
int nl_sockfd; //temp for now
sem_t nl_sem;

enum sockOptions {

	FSO_DEBUG = 1,
	FSO_REUSEADDR,
	FSO_TYPE,
	FSO_ERROR,
	FSO_DONTROUTE,
	FSO_BROADCAST,
	FSO_SNDBUF,
	FSO_RCVBUF,
	FSO_KEEPALIVE,
	FSO_OOBINLINE,
	FSO_NO_CHECK,
	FSO_PRIORITY,
	FSO_LINGER,
	FSO_BSDCOMPAT, /** 14 */
	FSO_REUSEPORT = 15, /** FSO_REUSEPORT = 15 */
	FSO_PASSCRED = 16,
	FSO_PEERCRED,
	FSO_RCVLOWAT,
	FSO_SNDLOWAT,
	FSO_RCVTIMEO,
	FSO_SNDTIMEO, /** SO_SNDTIMEO	21 */

	FSO_BINDTODEVICE = 25,
	FSO_TIMESTAMP = 29,
	FSO_ACCEPTCONN = 30,
	FSO_PEERSEC = 31,
	FSO_SNDBUFFORCE = 32,
	FSO_RCVBUFFORCE = 33,

};

struct socket_Options {

	int FSO_DEBUG;
	int FSO_REUSEADDR;
	int FSO_TYPE;
	int FSO_PROTOCOL;
	int FSO_DOMAIN;
	int FSO_ERROR;
	int FSO_DONTROUTE;
	int FSO_BROADCAST;
	int FSO_SNDBUF;
	int FSO_SNDBUFFORCE;
	int FSO_RCVBUF;
	int FSO_RCVBUFFORCE;
	int FSO_KEEPALIVE;
	int FSO_OOBINLINE;
	int FSO_NO_CHECK;
	int FSO_PRIORITY;
	int FSO_LINGER;
	int FSO_BSDCOMPAT;
	int FSO_TIMESTAMP;
	int FSO_TIMESTAMPNS;
	int FSO_TIMESTAMPING;
	int FSO_RCVTIMEO;
	int FSO_SNDTIMEO;
	int FSO_RCVLOWAT;
	int FSO_SNDLOWAT;
	int FSO_PASSCRED;
	int FSO_PEERCRED;
	char FSO_PEERNAME[128];
	int FSO_ACCEPTCONN;
	int FSO_PASSSEC;
	int FSO_PEERSEC;
	int FSO_MARK;
	int FSO_RXQ_OVFL;
	int FSO_ATTACH_FILTER;
	int FSO_DETACH_FILTER;
};

struct tcp_Parameters {

	int SHUT_RD;
	int SHUT_WR;

};

//TODO merge with ipv4 stuff & create centralized IP/MAC/Device handling
uint64_t my_host_mac_addr;
uint32_t my_host_ip_addr; // = IP4_ADR_P2H(192,168,1,20);
uint32_t my_host_mask;
uint32_t loopback_ip_addr; // = IP4_ADR_P2H(127,0,0,1);
uint32_t any_ip_addr; // = IP4_ADR_P2H(0,0,0,0);

struct nl_wedge_to_daemon {
	uint64_t sock_id; //TODO when ironed out remove uID or index, prob uID
	int sock_index;

	uint32_t call_type;
	int call_threads;

	uint32_t call_id; //TODO when ironed out remove id or index
	int call_index;
};

struct nl_daemon_to_wedge {
	uint32_t call_type;

	union {
		uint32_t call_id; //TODO when ironed out remove id or index
		uint64_t sock_id; //TODO when ironed out remove uID & index
	};
	union {
		int call_index;
		int sock_index;
	};

	uint32_t ret;
	uint32_t msg;
};

struct fins_daemon_call {
	//next or have array?

	uint32_t call_id;
	uint32_t call_type;
	uint32_t call_index;

	uint32_t data;
	uint32_t fcf_serialNum;
	//uint64_t sock_id;
	//int sock_index;

	//TODO timestamp? so can remove after timeout/hit MAX_CALLS cap
};

struct fins_daemon_socket {
	/** variables tells a connect call has been called over this socket or not in order to
	 * check the address of the senders of the received datagrams against the address which this
	 * socket is connected to it before approving or dropping any datagram
	 */
	//int connection_status; //0=created, not connected to anything, 1=connecting/accepting, 2=established
	socket_state state;
	uint64_t uniqueSockID;
	pid_t childrenList[MaxChildrenNumSharingSocket]; //TODO remove or implement? not used
	int type;
	int protocol;

	sem_t sem; //TODO implement? would need for multithreading
	int listening;
	int backlog;

	/** check the opt_name to find which bit to access in the options variable then use
	 * the following code to handle the bits individually
	 * setting a bit   number |= 1 << x;  That will set bit x.
	 * Clearing a bit number &= ~(1 << x); That will clear bit x.
	 * The XOR operator (^) can be used to toggle a bit. number ^= 1 << x; That will toggle bit x.
	 * Checking a bit      value = number & (1 << x);
	 */
	//uint32_t socketoptions;
	struct socket_Options sockopts;
	int blockingFlag;
	struct tcp_Parameters tcpParameters;

	/** All the above already initialized using the insert function
	 * the remaining below is handled using the update function*/
	uint32_t host_ip; //host format
	uint16_t host_port; //host format
	uint32_t dst_ip; //host format
	uint16_t dst_port; //host format
	char name[50];
	int data_pipe[2];

	sem_t Qs; /** The data Queue Semaphore Pointer*/
	finsQueue controlQueue;
	sem_t control_sem;

	finsQueue dataQueue;
	sem_t data_sem;
	int buf_data;

	int recv_ind;
	int threads;
	int replies;

	int poll_events;
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

#define RECV_BUFFER_SIZE	1024// Pick an appropriate value here
int init_fins_nl(void);
int send_wedge(int sockfd, u_char *buf, size_t len, int flags);

int nack_send(uint64_t uniqueSockID, int index, uint32_t call_id, int call_index, uint32_t call_type, uint32_t ret_msg);
int ack_send(uint64_t uniqueSockID, int index, uint32_t call_id, int call_index, uint32_t call_type, uint32_t ret_msg);

void init_daemonSockets(void);
int randoming(int min, int max);
int check_daemonSocket(uint64_t uniqueSockID);
int match_daemonSocket(uint16_t dstport, uint32_t dstip, int protocol);
int match_daemon_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol);
int find_daemonSocket(uint64_t uniqueSockID);
int insert_daemonSocket(uint64_t uniqueSockID, int index, int type, int protocol);
int remove_daemonSocket(uint64_t uniqueSockID, int index);

int check_daemon_ports(uint16_t hostport, uint32_t hostip);

int get_fdf(int index, uint64_t uniqueSockID, struct finsFrame **ff, int non_blocking_flag);
int get_fcf(int index, uint64_t uniqueSockID, struct finsFrame **ff, int non_blocking_flag); //blocking doesn't matter

/** calls handling functions */
void socket_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void bind_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void listen_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void connect_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void accept_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void getname_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void ioctl_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void sendmsg_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void recvmsg_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void getsockopt_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void setsockopt_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void release_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void poll_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void mmap_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void socketpair_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void shutdown_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void close_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);
void sendpage_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len);

void daemon_init(void);
void daemon_run(pthread_attr_t *fins_pthread_attr);
void daemon_shutdown(void);
void daemon_release(void);
void daemon_get_ff(void);
int daemon_to_switch(struct finsFrame *ff);

void daemon_out_fdf(struct finsFrame *ff);
void daemon_in_fdf(struct finsFrame *ff);
void daemon_fcf(struct finsFrame *ff);
void daemon_read_param_reply(struct finsFrame *ff);
void daemon_exec_reply(struct finsFrame *ff);

#endif /* DAEMON_H_ */
