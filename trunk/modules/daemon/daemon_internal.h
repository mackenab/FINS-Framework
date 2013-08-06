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
#define DAEMON_MAX_SOCKETS 50 //TODO increase
#define DAEMON_MAX_CALLS 50 //TODO increase
#define DAEMON_CALL_LIST_MAX 30
#define DAEMON_IF_LIST_MAX 256
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

#define DAEMON_STATUS_NONE 	0x0
#define DAEMON_STATUS_RD 	0x1
#define DAEMON_STATUS_WR 	0x2
#define DAEMON_STATUS_RDWR (DAEMON_STATUS_RD|DAEMON_STATUS_WR)

//Netlink stuff
struct nl_wedge_to_daemon_hdr {
	uint32_t msg_len;
	int32_t part_len;
	int32_t pos;
};

struct wedge_to_daemon_hdr {
	uint64_t sock_id;
	int32_t sock_index;

	uint32_t call_type;
	int32_t call_pid;

	uint32_t call_id;
	int32_t call_index;
};

struct daemon_to_wedge_hdr {
	uint32_t call_type;

	union {
		uint32_t call_id;
		uint64_t sock_id;
	};
	union {
		int32_t call_index;
		int32_t sock_index;
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
int recvmsg_control(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t *msg_flags, metadata *meta, uint32_t msg_controllen, int flags,
		int32_t *control_len, uint8_t **control);
int send_wedge_recvmsg(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t msg_flags, uint32_t addr_len, struct sockaddr_storage *addr,
		uint32_t data_len, uint8_t *data, uint32_t control_len, uint8_t *control);

struct daemon_store {
	struct sockaddr_storage *addr;
	struct finsFrame *ff;
	uint32_t pos;
};
void daemon_store_free(struct daemon_store *store);

struct daemon_call {
	//vvvvvvvvvvvvv should be equal to: struct nl_wedge_to_daemon
	uint64_t sock_id;
	int sock_index;

	uint32_t type;
	int pid;

	uint32_t id;
	int index;
	//^^^^^^^^^^^^^ to here

	uint8_t alloc;

	uint32_t serial_num;
	uint32_t buf;
	uint32_t flags;
	uint32_t ret;
	uint32_t sent;

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
int daemon_call_recvmsg_test(struct daemon_call *call, uint32_t *flags);
void daemon_call_free(struct daemon_call *call);

int daemon_calls_insert(struct fins_module *module, uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index);
int daemon_calls_find(struct fins_module *module, uint32_t serialNum);
void daemon_calls_remove(struct fins_module *module, int call_index);
void daemon_calls_shutdown(struct fins_module *module, int call_index);

struct daemon_socket {
	int type;
	int protocol;
	struct daemon_socket_out_ops *out_ops;
	struct daemon_socket_in_ops *in_ops;
	struct daemon_socket_other_ops *other_ops;

	uint64_t sock_id;
	socket_state state;
	uint8_t status; //DAEMON_STATUS_RD=reading, DAEMON_STATUS_WR=writing, or DAEMON_STATUS_RDWR=both

	uint32_t family;
	struct sockaddr_storage host_addr; //host format
	uint8_t host_any_addr; //signals was bound to INANY_ADDR //if bind w/INANY_ADDR, bind to current main IP, flag this for recv
	struct sockaddr_storage rem_addr; //host format
	//uint8_t rem_any_addr; //signals was bound to INANY_ADDR //TODO unneeded, remove?

	uint8_t listening;
	int backlog;

	uint64_t sock_id_new;
	int sock_index_new;

	struct linked_list *call_list;
	struct timeval stamp;

	struct linked_list *data_list;
	int data_buf;

	struct linked_list *error_list;
	int error_buf;

	uint32_t error_msg;
	uint32_t error_call;

	int count; //TODO remove, only for testing

	struct socket_options sockopts;
};
int daemon_sockets_insert(struct fins_module *module, uint64_t sock_id, int sock_index, int type, int protocol, struct daemon_socket_out_ops *out_ops,
		struct daemon_socket_in_ops *in_ops, struct daemon_socket_other_ops *other_ops);
int daemon_sockets_find(struct fins_module *module, uint64_t sock_id);
//int check_daemonSocket(struct fins_module *module, uint64_t sock_id);
int daemon_sockets_check_addr6(struct fins_module *module, struct sockaddr_storage *addr, int protocol);
int daemon_sockets_remove(struct fins_module *module, int sock_index);

//TODO fix the usage of these
uint32_t daemon_fcf_to_switch(struct fins_module *module, uint32_t flow, metadata *meta, uint32_t serial_num, uint16_t opcode, uint32_t param_id);
uint32_t daemon_fdf_to_switch(struct fins_module *module, uint32_t flow, uint32_t data_len, uint8_t *data, metadata *meta);

//TODO standardize these, so that there aren't different ones for each proto
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

#define DAEMON_ADDR4_EVERY_IP	INADDR_BROADCAST

#define DAEMON_LIB "daemon"
#define DAEMON_MAX_FLOWS	3
#define DAEMON_FLOW_ICMP	0
#define DAEMON_FLOW_TCP		1
#define DAEMON_FLOW_UDP		2

struct daemon_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	struct fins_module_flow flows[DAEMON_MAX_FLOWS];

	pthread_t switch_to_daemon_thread;
	pthread_t wedge_to_daemon_thread;

	sem_t sockets_sem;
	struct daemon_socket sockets[DAEMON_MAX_SOCKETS];

	struct daemon_call calls[DAEMON_MAX_CALLS];
	struct linked_list *expired_call_list;

	uint8_t interrupt_flag;

	struct sockaddr_nl daemon_addr; // sockaddr_nl for this process (source)
	struct sockaddr_nl wedge_addr; // sockaddr_nl for the kernel (destination)
	int nl_sockfd; //temp for now
	sem_t nl_sem;

	struct linked_list *if_list;
	struct if_record *if_loopback;
	struct if_record *if_main;

	struct linked_list *store_list; //Stored FDF waiting to send
};

int daemon_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int daemon_run(struct fins_module *module, pthread_attr_t *attr);
int daemon_pause(struct fins_module *module);
int daemon_unpause(struct fins_module *module);
int daemon_shutdown(struct fins_module *module);
int daemon_release(struct fins_module *module);

void daemon_get_ff(struct fins_module *module);
void daemon_fcf(struct fins_module *module, struct finsFrame *ff);
void daemon_alert(struct fins_module *module, struct finsFrame *ff);
void daemon_read_param_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_set_param(struct fins_module *module, struct finsFrame *ff);
void daemon_set_param_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_exec_reply(struct fins_module *module, struct finsFrame *ff);
void daemon_error(struct fins_module *module, struct finsFrame *ff);

void daemon_in_fdf(struct fins_module *module, struct finsFrame *ff);

void daemon_interrupt(struct fins_module *module);
void daemon_handle_to(struct fins_module *module, struct daemon_call *call);

void daemon_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *msg_pt, int msg_len);
typedef void (*call_out_type)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);

/** calls handling functions */
void socket_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void bind_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void listen_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void connect_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void accept_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void getname_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void ioctl_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void sendmsg_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void recvmsg_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void getsockopt_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void setsockopt_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void release_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void poll_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void mmap_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void socketpair_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void shutdown_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void close_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);
void sendpage_out(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint8_t *buf, int len);

struct daemon_socket_general_ops {
	uint32_t proto;
	int (*socket_type_test)(int domain, int type, int protocol);
	void (*socket_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int domain);
	void (*daemon_in_fdf)(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr,
			struct sockaddr_storage *dst_addr);
	void (*daemon_in_error)(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr,
			struct sockaddr_storage *dst_addr);
	void (*daemon_in_poll)(struct fins_module *module, struct finsFrame *ff, uint32_t ret_msg); //change to exec?
};

struct daemon_socket_out_ops {
	//convert to socket_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, struct socket_out_hdr *shdr);
	void (*socket_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int domain);
	void (*bind_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr);
	void (*listen_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int backlog);
	void (*connect_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr, int flags);
	void (*accept_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint64_t uniqueSockID_new, int index_new, int flags);
	void (*getname_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int peer);
	void (*ioctl_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t cmd, uint8_t *buf, int buf_len);
	void (*sendmsg_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t data_len, uint8_t *data, uint32_t flags,
			struct sockaddr_storage *dest_addr, int addr_len);
	void (*recvmsg_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int data_len, uint32_t msg_controllen, int flags);
	void (*getsockopt_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval);
	void (*setsockopt_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval);
	void (*release_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
	void (*poll_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t events);
	void (*mmap_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
	void (*socketpair_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
	void (*shutdown_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int how);
	void (*close_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
	void (*sendpage_out)(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
};

typedef void (*call_in_type)(struct fins_module *module, struct daemon_call *call);

struct daemon_socket_in_ops {
	void (*connect_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*accept_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*sendmsg_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*getsockopt_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*setsockopt_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*release_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
	void (*poll_in)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
};

struct daemon_socket_other_ops {
	void (*connect_timeout)(struct fins_module *module, struct daemon_call *call);
	void (*connect_expired)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply);

	void (*accept_timeout)(struct fins_module *module, struct daemon_call *call);
	void (*accept_expired)(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply);

	void (*recvmsg_timeout)(struct fins_module *module, struct daemon_call *call);
//void (*poll_timeout)(struct fins_module *module, struct daemon_call *call); //TODO remove? not used atm
//void (*sendmsg_timeout)(struct fins_module *module, struct daemon_call *call); //TODO remove? not used atm
};

#define DAEMON_ALERT_POLL 0 //only one that's used in daemon.c
#define DAEMON_ALERT_SHUTDOWN 1

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
