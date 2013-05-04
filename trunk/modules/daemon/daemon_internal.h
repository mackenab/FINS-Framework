/*
 * daemon_internal.h
 *
 *  Created on: May 2, 2013
 *      Author: Jonathan Reed
 */

#ifndef DAEMON_INTERNAL_H_
#define DAEMON_INTERNAL_H_

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

#include <finsdebug.h>
#include <metadata.h>
#include <finstypes.h>
#include <finstime.h>
#include <finsqueue.h>

#include "daemon.h"

/** FINS Sockets database related defined constants */
#define MAX_SOCKETS 50 //TODO increase
#define MAX_CALLS 50 //TODO increase
#define DAEMON_CALL_LIST_MAX 30
//#define MAX_QUEUE_SIZE 100000
#define ACK 	200
#define NACK 	6666
#define MIN_port 32768
#define MAX_port 61000
#define DEFAULT_BACKLOG 5
#define DAEMON_BLOCK_DEFAULT 500
#define CONTROL_LEN_MAX 10240
#define CONTROL_LEN_DEFAULT 1024

/** Socket related calls and their codes */
typedef enum {
	SOCKET_CALL = 1,
	BIND_CALL,
	LISTEN_CALL,
	CONNECT_CALL,
	ACCEPT_CALL,
	GETNAME_CALL,
	IOCTL_CALL,
	SENDMSG_CALL,
	RECVMSG_CALL,
	GETSOCKOPT_CALL,
	SETSOCKOPT_CALL,
	RELEASE_CALL,
	POLL_CALL,
	MMAP_CALL,
	SOCKETPAIR_CALL,
	SHUTDOWN_CALL,
	CLOSE_CALL,
	SENDPAGE_CALL,
	//only sent from daemon to wedge
	DAEMON_START_CALL,
	DAEMON_STOP_CALL,
	POLL_EVENT_CALL,
	/** Additional calls
	 * To hande special cases
	 * overwriting the generic functions which write to a socket descriptor
	 * in order to make sure that we cover as many applications as possible
	 * This range of these functions will start from 30
	 */
	MAX_CALL_TYPES
} call_types;

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
extern uint8_t my_host_if_name[IFNAMSIZ];
extern uint8_t my_host_if_num;
extern uint64_t my_host_mac_addr;
extern uint32_t my_host_ip_addr;
extern uint32_t my_host_mask;
extern uint32_t loopback_ip_addr;
extern uint32_t loopback_mask;
extern uint32_t any_ip_addr;

//Netlink stuff
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
		uint64_t sock_id;
	};
	union {
		int call_index;
		int sock_index;
	};

	uint32_t ret;
	uint32_t msg;
};
#define NETLINK_FINS	20		// Pick an appropriate protocol or define a new one in include/linux/netlink.h
#define RECV_BUFFER_SIZE	4096//1024//NLMSG_DEFAULT_SIZE//NLMSG_GOODSIZE//8192 //Pick an appropriate value here
int init_fins_nl(struct fins_module *module);
int send_wedge(struct fins_module *module, uint8_t *buf, size_t len, int flags);
int nack_send(struct fins_module *module, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);
int ack_send(struct fins_module *module, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg);

struct daemon_call {
	uint8_t alloc;

	uint32_t call_id;
	int call_index;

	int call_pid;
	uint32_t call_type;

	uint64_t sock_id;
	int sock_index;

	uint32_t serial_num;
	uint32_t buf;
	uint32_t flags;
	uint32_t ret;

	uint64_t sock_id_new;
	int sock_index_new;

	struct intsem_to_timer_data *to_data;
	uint8_t to_flag;
//TODO timestamp? so can remove after timeout/hit MAX_CALLS cap
};
struct daemon_call *daemon_call_create(uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index);
struct daemon_call *daemon_call_clone(struct daemon_call *call);
int daemon_call_pid_test(struct daemon_call *call, int *call_pid, uint32_t *call_type);
int daemon_call_serial_test(struct daemon_call *call, uint32_t *serial_num);
void daemon_call_free(struct daemon_call *call);

int daemon_calls_insert(struct fins_module *module, uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index);
int daemon_calls_find(struct fins_module *module, uint32_t serialNum);
void daemon_calls_remove(struct fins_module *module, int call_index);
void daemon_calls_shutdown(struct fins_module *module, int call_index);

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

	struct linked_list *call_list;
	struct timeval stamp;

	finsQueue data_queue;
	int data_buf;

	finsQueue error_queue;
	int error_buf;

	uint32_t error_msg;
	uint32_t error_call;

	struct socket_options sockopts;
};

int daemon_sockets_insert(struct fins_module *module, uint64_t sock_id, int sock_index, int sock_type, int protocol);
int daemon_sockets_find(struct fins_module *module, uint64_t sock_id);
int daemon_sockets_match(struct fins_module *module, uint16_t dstport, uint32_t dstip, int protocol);
int daemon_sockets_match_connection(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol);
//int check_daemonSocket(struct fins_module *module, uint64_t sock_id);
int daemon_sockets_check_ports(struct fins_module *module, uint16_t hostport, uint32_t hostip);
int daemon_sockets_remove(struct fins_module *module, int sock_index);

int randoming(int min, int max);

//TODO fix the usage of these
int daemon_fcf_to_switch(struct fins_module *module, uint8_t dest_id, metadata *meta, uint32_t serial_num, uint16_t opcode, uint32_t param_id);
int daemon_fdf_to_switch(struct fins_module *module, uint8_t dest_id, uint8_t *data, uint32_t data_len, metadata *meta);

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

#define DAEMON_LIB "daemon"
#define DAEMON_MAX_FLOWS 3
#define DAEMON_FLOW_IPV4 0
#define DAEMON_FLOW_ARP 	1
#define DAEMON_FLOW_IPV6	2

struct daemon_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[DAEMON_MAX_FLOWS];

	pthread_t switch_to_daemon_thread;
	pthread_t wedge_to_daemon_thread;

	sem_t daemon_sockets_sem;
	struct daemon_socket daemon_sockets[MAX_SOCKETS];

	struct daemon_call daemon_calls[MAX_CALLS];
	struct linked_list *expired_call_list;

	uint8_t interrupt_flag;

	struct sockaddr_nl daemon_addr; // sockaddr_nl for this process (source)
	struct sockaddr_nl wedge_addr; // sockaddr_nl for the kernel (destination)
	int nl_sockfd; //temp for now
	sem_t nl_sem;

	struct linked_list *if_list;
	struct linked_list *store_list; //Stored FDF waiting to send
};

int daemon_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int daemon_run(struct fins_module *module, pthread_attr_t *attr);
int daemon_pause(struct fins_module *module);
int daemon_unpause(struct fins_module *module);
int daemon_shutdown(struct fins_module *module);
int daemon_release(struct fins_module *module);

void daemon_get_ff(struct fins_module *module);
void daemon_fcf(struct fins_module *module, struct finsFrame *ff);
void daemon_read_param(struct fins_module *module, struct finsFrame *ff);
void daemon_read_param_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_set_param(struct fins_module *module, struct finsFrame *ff);
void daemon_set_param_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_exec(struct fins_module *module, struct finsFrame *ff);
void daemon_exec_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_error(struct fins_module *module, struct finsFrame *ff);

void daemon_in_fdf(struct fins_module *module, struct finsFrame *ff);
//void daemon_out_fdf(struct fins_module *module, struct finsFrame *ff);

void daemon_interrupt(struct fins_module *module);
void daemon_handle_to(struct fins_module *module, struct daemon_call *call);

void connect_timeout(struct fins_module *module, struct daemon_call *call);
void accept_timeout(struct fins_module *module, struct daemon_call *call);
//void sendmsg_timeout(struct fins_module *module, struct daemon_call *call); //udp/icmp no TO, tcp TO in module
void recvmsg_timeout(struct fins_module *module, struct daemon_call *call);
//void poll_timeout(struct fins_module *module, struct daemon_call *call); //poll is special

void daemon_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *msg_pt, int msg_len);
typedef void (*call_out_type)(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);

/** calls handling functions */
void socket_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void bind_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void listen_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void connect_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void accept_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void getname_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void ioctl_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void sendmsg_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void recvmsg_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void getsockopt_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void setsockopt_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void release_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void poll_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void mmap_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void socketpair_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void shutdown_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void close_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);
void sendpage_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len);

#define EXEC_DAEMON_GET_ADDR 0

//don't use 0
#define DAEMON_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define DAEMON_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define DAEMON_GET_PARAM_DUAL MOD_GET_PARAM_DUAL

#define DAEMON_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define DAEMON_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define DAEMON_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#include "udpHandling.h"
#include "tcpHandling.h"
#include "icmpHandling.h"

#endif /* DAEMON_INTERNAL_H_ */
