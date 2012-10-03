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

/** FINS Sockets database related defined constants */
#define MAX_SOCKETS 100
#define MAX_CALLS 500
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

	int pid;
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

struct daemon_call {
	struct daemon_call *next;

	uint32_t call_id;
	int call_index;
	uint32_t call_type;

	uint64_t sock_id;
	int sock_index;

	uint32_t serial_num;
	uint32_t data;
	uint32_t flags;

	uint64_t sock_id_new;
	int sock_index_new;
	//TODO timestamp? so can remove after timeout/hit MAX_CALLS cap
};

struct daemon_call *call_create(uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index);
void call_free(struct daemon_call *call);

int daemon_calls_insert(uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index);
int daemon_calls_find(uint32_t serialNum);
int daemon_calls_remove(int call_index);

struct daemon_call_list {
	struct daemon_call *front;
	struct daemon_call *end;
	uint32_t max;
	uint32_t len;
};

#define DAEMON_CALL_LIST_MAX 20

struct daemon_call_list *call_list_create(uint32_t max);
void call_list_append(struct daemon_call_list *call_list, struct daemon_call *call);
struct daemon_call *call_list_find(struct daemon_call_list *call_list, uint32_t serialNum);
struct daemon_call *call_list_remove_front(struct daemon_call_list *call_list);
void call_list_remove(struct daemon_call_list *call_list, struct daemon_call *call);
int call_list_is_empty(struct daemon_call_list *call_list);
int call_list_has_space(struct daemon_call_list *call_list);
void call_list_free(struct daemon_call_list *call_list);

struct daemon_socket {
	//## //TODO remove/finish - these are all for handle_call_new
	sem_t sem; //TODO implement? would need for multithreading
	int ops; //TODO change to struct with functions in it
	uint8_t running;
	int threads;
	//##

	uint64_t sock_id;
	socket_state state;

	int type;
	int protocol;

	int listening;
	int backlog;

	//pid_t childrenList[MaxChildrenNumSharingSocket]; //TODO remove or implement? not used

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
	//struct tcp_Parameters tcpParameters;

	/** All the above already initialized using the insert function
	 * the remaining below is handled using the update function*/
	uint32_t host_ip; //host format
	uint16_t host_port; //host format
	uint32_t dst_ip; //host format
	uint16_t dst_port; //host format

	finsQueue dataQueue;
	int buf_data;
	sem_t data_sem; //TODO remove? not used or tie calls to this sem somehow

	struct daemon_call_list *call_list;
};

int daemon_sockets_insert(uint64_t sock_id, int sock_index, int sock_type, int protocol);
int daemon_sockets_find(uint64_t sock_id);
int daemon_sockets_match(uint16_t dstport, uint32_t dstip, int protocol);
int daemon_sockets_match_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol);
//int check_daemonSocket(uint64_t sock_id);
int daemon_sockets_check_ports(uint16_t hostport, uint32_t hostip);
int daemon_sockets_remove(int sock_index);

int randoming(int min, int max);

//ADDED mrd015 !!!!! (this crap really needs to be gathered into one header.)
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/fins"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

//#define MAIN_SOCKET_CHANNEL FINS_TMP_ROOT "/mainsocket_channel"
//#define CLIENT_CHANNEL_TX FINS_TMP_ROOT "/uniqueSockID_%llu_TX"
//#define CLIENT_CHANNEL_RX FINS_TMP_ROOT "/uniqueSockID_%llu_RX"
#define RTM_PIPE_IN FINS_TMP_ROOT "/rtm_in"
#define RTM_PIPE_OUT FINS_TMP_ROOT "/rtm_out"

#define RECV_BUFFER_SIZE	1024// Pick an appropriate value here
int init_fins_nl(void);
int send_wedge(int sockfd, u_char *buf, size_t len, int flags);
int nack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);
int ack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);

int get_fdf(int sock_index, uint64_t sock_id, struct finsFrame **ff, int non_blocking_flag);
int get_fcf(int sock_index, uint64_t sock_id, struct finsFrame **ff, int non_blocking_flag); //blocking doesn't matter

/** calls handling functions */
void socket_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void bind_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void listen_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void connect_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void accept_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void getname_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void ioctl_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void sendmsg_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void recvmsg_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void getsockopt_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void setsockopt_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void release_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void poll_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void mmap_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void socketpair_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void shutdown_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void close_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);
void sendpage_out(struct nl_wedge_to_daemon *hdr, u_char *buf, ssize_t len);

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
void daemon_set_param_reply(struct finsFrame *ff);
void daemon_exec_reply(struct finsFrame *ff);

#include "udpHandling.h"
#include "tcpHandling.h"
#include "icmpHandling.h"

//TODO standardize these, so that there aren't different ones for each proto
#define EXEC_TCP_CONNECT 0
#define EXEC_TCP_LISTEN 1
#define EXEC_TCP_ACCEPT 2
#define EXEC_TCP_SEND 3
#define EXEC_TCP_RECV 4
#define EXEC_TCP_CLOSE 5
#define EXEC_TCP_CLOSE_STUB 6
#define EXEC_TCP_OPT 7
#define EXEC_TCP_POLL 8

#endif /* DAEMON_H_ */
