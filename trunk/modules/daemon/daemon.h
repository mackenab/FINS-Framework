/*
 * daemon.h
 *
 *  Created on: Mar 6, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef DAEMON_H_
#define DAEMON_H_

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/errqueue.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/socket.h>
//#include <linux/tcp.h> //TODO remove?
#include <math.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>

/**additional headers for testing */
#include <finsdebug.h>
/** Additional header for meta-data manipulation */
#include <metadata.h>
#include <finstypes.h>
#include <finstime.h>
/** additional header for queues */
#include <finsqueue.h>
//#include <switch.h>

/** FINS Sockets database related defined constants */
#define MAX_SOCKETS 50 //TODO increase
#define MAX_CALLS 50 //TODO increase
#define MAX_Queue_size 100000
#define ACK 	200
#define NACK 	6666
#define MIN_port 32768
#define MAX_port 61000
#define DEFAULT_BACKLOG 5
#define DAEMON_BLOCK_DEFAULT 500
#define CONTROL_LEN_MAX 10240
#define CONTROL_LEN_DEFAULT 1024

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

//only sent from daemon to wedge
#define daemon_start_call 19
#define daemon_stop_call 20
#define poll_event_call 21

/** Additional calls
 * To hande special cases
 * overwriting the generic functions which write to a socket descriptor
 * in order to make sure that we cover as many applications as possible
 * This range of these functions will start from 30
 */
#define MAX_CALL_TYPES 22

//fins netlink stuff
#define NETLINK_FINS	20		// Pick an appropriate protocol or define a new one in include/linux/netlink.h
struct sockaddr_nl local_sockaddress; // sockaddr_nl for this process (source)
struct sockaddr_nl kernel_sockaddress; // sockaddr_nl for the kernel (destination)
int nl_sockfd; //temp for now
sem_t nl_sem;

enum sock_flags {
	SOCK_DEAD = 0, SOCK_DONE, SOCK_URGINLINE, SOCK_KEEPOPEN, SOCK_LINGER, SOCK_DESTROY, SOCK_BROADCAST, SOCK_TIMESTAMP, SOCK_ZAPPED, SOCK_USE_WRITE_QUEUE, //whether to call sk->sk_write_space in sock_wfree
	SOCK_DBG, //SO_DEBUG setting
	SOCK_RCVTSTAMP, //SO_TIMESTAMP setting
	SOCK_RCVTSTAMPNS, //SO_TIMESTAMPNS setting
	SOCK_LOCALROUTE, //route locally only, %SO_DONTROUTE setting
	SOCK_QUEUE_SHRUNK, //write queue has been shrunk recently
	SOCK_TIMESTAMPING_TX_HARDWARE, //SOF_TIMESTAMPING_TX_HARDWARE
	SOCK_TIMESTAMPING_TX_SOFTWARE, //SOF_TIMESTAMPING_TX_SOFTWARE
	SOCK_TIMESTAMPING_RX_HARDWARE, //SOF_TIMESTAMPING_RX_HARDWARE
	SOCK_TIMESTAMPING_RX_SOFTWARE, //SOF_TIMESTAMPING_RX_SOFTWARE
	SOCK_TIMESTAMPING_SOFTWARE, //SOF_TIMESTAMPING_SOFTWARE
	SOCK_TIMESTAMPING_RAW_HARDWARE, //SOF_TIMESTAMPING_RAW_HARDWARE
	SOCK_TIMESTAMPING_SYS_HARDWARE, //SOF_TIMESTAMPING_SYS_HARDWARE
	SOCK_FASYNC, //fasync() active
	SOCK_RXQ_OVFL,
};

/*
enum sol_sockOptions {
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
	FSO_BSDCOMPAT, //14
	FSO_REUSEPORT = 15,
	FSO_PASSCRED = 16,
	FSO_PEERCRED,
	FSO_RCVLOWAT,
	FSO_SNDLOWAT,
	FSO_RCVTIMEO,
	FSO_SNDTIMEO, //SO_SNDTIMEO	21

	FSO_BINDTODEVICE = 25,
	FSO_TIMESTAMP = 29,
	FSO_ACCEPTCONN = 30,
	FSO_PEERSEC = 31,
	FSO_SNDBUFFORCE = 32,
	FSO_RCVBUFFORCE = 33,

};
//*/

struct socket_options { //TODO change to common opts, then union of structs for ICMP/UDP/TCP

	//SOL_SOCKET stuff
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

	//SOL_IP stuff
	int FIP_TOS;
	int FIP_TTL;
	int FIP_RECVERR;
	int FIP_RECVTTL;

	//SOL_RAW stuff
	int FICMP_FILTER;

	//SOL_TCP stuff;
	int FTCP_NODELAY;
};

struct tcp_Parameters {

	int SHUT_RD;
	int SHUT_WR;

};

//TODO merge with ipv4 stuff & create centralized IP/MAC/Device handling
extern char my_host_if_name[IFNAMSIZ];
extern uint8_t my_host_if_num;
extern uint64_t my_host_mac_addr;
extern uint32_t my_host_ip_addr;
extern uint32_t my_host_mask;
extern uint32_t loopback_ip_addr;
extern uint32_t loopback_mask;
extern uint32_t any_ip_addr;

struct nl_wedge_to_daemon_hdr {
	int msg_len;
	int part_len;
	int pos;
};

struct nl_wedge_to_daemon {
	uint64_t sock_id;
	int sock_index;

	uint32_t call_type;
	int call_pid;

	uint32_t call_id;
	int call_index;
};

struct nl_daemon_to_wedge {
	uint32_t call_type;

	union {
		uint32_t call_id;
		uint64_t sock_id; //TODO currently unused, remove if never needed
	};
	union {
		int call_index;
		int sock_index; //TODO currently unused, remove if never needed
	};

	uint32_t ret;
	uint32_t msg;
};

struct daemon_call {
	struct daemon_call *next;
	uint8_t alloc;

	uint32_t call_id;
	int call_index;

	int call_pid;
	uint32_t call_type;

	uint64_t sock_id;
	int sock_index;

	uint32_t serial_num;
	uint32_t data;
	uint32_t flags;
	uint32_t ret;

	uint64_t sock_id_new;
	int sock_index_new;

	struct intsem_to_timer_data *to_data;
	uint8_t to_flag;
	//TODO timestamp? so can remove after timeout/hit MAX_CALLS cap
};

struct daemon_call *call_create(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index);
struct daemon_call *call_clone(struct daemon_call *call);
void call_free(struct daemon_call *call);

int daemon_calls_insert(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index);
int daemon_calls_find(uint32_t serialNum);
void daemon_calls_remove(int call_index);
void daemon_calls_shutdown(int call_index);

struct daemon_call_list {
	struct daemon_call *front;
	struct daemon_call *end;
	uint32_t max;
	uint32_t len;
};

#define DAEMON_CALL_LIST_MAX 30

struct daemon_call_list *call_list_create(uint32_t max);
void call_list_append(struct daemon_call_list *call_list, struct daemon_call *call);
struct daemon_call *call_list_find_pid(struct daemon_call_list *call_list, int call_pid, uint32_t call_type, uint64_t sock_id);
struct daemon_call *call_list_remove_front(struct daemon_call_list *call_list);
void call_list_remove(struct daemon_call_list *call_list, struct daemon_call *call);
int call_list_check(struct daemon_call_list *call_list);
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

	uint32_t host_ip; //host format
	uint16_t host_port; //host format
	uint32_t rem_ip; //host format
	uint16_t rem_port; //host format

	uint8_t bound;
	uint8_t listening;
	int backlog;

	uint64_t sock_id_new;
	int sock_index_new;

	struct daemon_call_list *call_list;
	struct timeval stamp;

	finsQueue data_queue;
	int data_buf;
	//sem_t data_sem; //TODO remove? not used or tie calls to this sem somehow

	finsQueue error_queue;
	int error_buf;
	//sem_t error_sem; //TODO remove? not used or tie calls to this sem somehow

	uint32_t error_msg;
	uint32_t error_call;

	struct socket_options sockopts;
};

int daemon_sockets_insert(uint64_t sock_id, int sock_index, int sock_type, int protocol);
int daemon_sockets_find(uint64_t sock_id);
int daemon_sockets_match(uint16_t dstport, uint32_t dstip, int protocol);
int daemon_sockets_match_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol);
//int check_daemonSocket(uint64_t sock_id);
int daemon_sockets_check_ports(uint16_t hostport, uint32_t hostip);
int daemon_sockets_remove(int sock_index);

int randoming(int min, int max);

#define RECV_BUFFER_SIZE	4096//1024//NLMSG_DEFAULT_SIZE//NLMSG_GOODSIZE//8192 //Pick an appropriate value here

int init_fins_nl(void);
int send_wedge(int sockfd, uint8_t *buf, size_t len, int flags);
int nack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);
int ack_send(uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);

int get_fdf(int sock_index, uint64_t sock_id, struct finsFrame **ff, int non_blocking_flag);
int get_fcf(int sock_index, uint64_t sock_id, struct finsFrame **ff, int non_blocking_flag); //blocking doesn't matter

/** calls handling functions */
void socket_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void bind_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void listen_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void connect_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void accept_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void getname_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void ioctl_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void sendmsg_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void recvmsg_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void getsockopt_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void setsockopt_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void release_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void poll_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void mmap_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void socketpair_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void shutdown_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void close_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void sendpage_out(struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);

void connect_timeout(struct daemon_call *call);
void accept_timeout(struct daemon_call *call);
//void sendmsg_timeout(struct daemon_call *call); //udp/icmp no TO, tcp TO in module
void recvmsg_timeout(struct daemon_call *call);
//void poll_timeout(struct daemon_call *call); //poll is special

void daemon_dummy(void);
void daemon_init(void);
void daemon_run(pthread_attr_t *fins_pthread_attr);
void daemon_shutdown(void);
void daemon_release(void);

int daemon_to_switch(struct finsFrame *ff);
int daemon_fcf_to_switch(uint8_t dest_id, metadata *meta, uint32_t serial_num, uint16_t opcode, uint32_t param_id);
int daemon_fdf_to_switch(uint8_t dest_id, uint8_t *data, uint32_t data_len, metadata *meta);

void daemon_get_ff(void);

void daemon_fcf(struct finsFrame *ff);
void daemon_read_param_reply(struct finsFrame *ff);
void daemon_set_param_reply(struct finsFrame *ff);
void daemon_exec(struct finsFrame *ff);
void daemon_exec_reply(struct finsFrame *ff);
void daemon_error(struct finsFrame *ff);

void daemon_in_fdf(struct finsFrame *ff);
void daemon_out_fdf(struct finsFrame *ff);

void daemon_interrupt(void);

//TODO standardize these, so that there aren't different ones for each proto
//#define EXEC_TCP_CONNECT 0
//#define EXEC_TCP_LISTEN 1
//#define EXEC_TCP_ACCEPT 2
//#define EXEC_TCP_SEND 3
//#define EXEC_TCP_RECV 4
//#define EXEC_TCP_CLOSE 5
//#define EXEC_TCP_CLOSE_STUB 6
//#define EXEC_TCP_OPT 7
//#define EXEC_TCP_POLL 8
#define EXEC_TCP_POLL_POST 9 //only one that's used in daemon.c
//TODO not used? what are these for in this module file?
//#define ERROR_ICMP_TTL 0
//#define ERROR_ICMP_DEST_UNREACH 1

struct errhdr {
	struct sock_extended_err ee;
	struct sockaddr_in offender;
};

//--------------------------------------------------- //temp stuff to cross compile, remove/implement better eventual?
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLWRBAND
#define POLLWRBAND POLLOUT
#endif

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL 40
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0x80000
#endif

#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0x40000000
#endif

//---------------------------------------------------

#include "udpHandling.h"
#include "tcpHandling.h"
#include "icmpHandling.h"

#endif /* DAEMON_H_ */
