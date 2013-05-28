#ifndef FINS_STACK_WEDGE_H_
#define FINS_STACK_WEDGE_H_

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <net/sock.h>		/* Needed for proto and sock struct defs, etc. */
#include <linux/socket.h>	/* Needed for the sockaddr struct def */
#include <linux/errno.h>	/* Needed for error number defines */
#include <linux/aio.h>		/* Needed for fins_sendmsg */
#include <linux/skbuff.h>	/* Needed for sk_buff struct def, etc. */
#include <linux/net.h>		/* Needed for socket struct def, etc. */
#include <linux/netlink.h>	/* Needed for netlink socket API, macros, etc. */
#include <linux/semaphore.h>	/* Needed to lock/unlock blocking calls with handler */
#include <asm/uaccess.h>	/** Copy from user */
#include <asm/ioctls.h>		/* Needed for fins_ioctl */
#include <linux/sockios.h>
#include <linux/delay.h>	/* For sleep */
#include <linux/if.h>		/* Needed for fins_ioctl */
#include <linux/types.h>

/*
 * NETLINK_FINS must match a corresponding constant in the userspace daemon program that is to talk to this module.  
 * NETLINK_ constants are normally defined in <linux/netlink.h> although adding a constant here would necessitate a 
 * full kernel rebuild in order to change it.  This is not necessary, as long as the constant matches in both LKM and
 * userspace program.  To choose an appropriate value, view the linux/netlink.h file and find an unused value 
 * (probably best to choose one under 32) following the list of NETLINK_ constants and define the constant here to
 * match that value as well as in the userspace program.
 */
//#define NETLINK_FINS    20	// must match userspace definition
#define KERNEL_PID      0	// This is used to identify netlink traffic into and out of the kernel

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

#define ACK 	200
#define NACK 	6666
#define MAX_SOCKETS 100
#define MAX_CALLS 100
//#define LOOP_LIMIT 10

#define CONTROL_LEN_MAX 10240
#define CONTROL_LEN_DEFAULT 1024

/* Data for protocol registration */
static struct proto_ops fins_proto_ops;
static struct proto fins_proto;
static struct net_proto_family fins_net_proto;
/* Protocol specific socket structure */
struct fins_sock {
	/* struct sock MUST be the first member of fins_sock */
	struct sock sk;
	/* Add the protocol implementation specific members per socket here from here on */
// Other stuff might go here, maybe look at IPX or IPv4 registration process
};

// Function prototypes:
static int fins_create(struct net *net, struct socket *sock, int protocol, int kern);
static int fins_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
static int fins_listen(struct socket *sock, int backlog);
static int fins_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);
static int fins_accept(struct socket *sock, struct socket *newsock, int flags);
static int fins_getname(struct socket *sock, struct sockaddr *addr, int *len, int peer);
static int fins_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len);
static int fins_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags);
static int fins_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
static int fins_release(struct socket *sock);
static unsigned int fins_poll(struct file *file, struct socket *sock, poll_table *table);
static int fins_shutdown(struct socket *sock, int how);

static int fins_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
static int fins_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);

static int fins_socketpair(struct socket *sock1, struct socket *sock2);
static int fins_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma);
static ssize_t fins_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags);

/* FINS netlink functions*/
__s32 nl_send(__s32 pid, void *buf, __u32 len, __s32 flags);
__s32 nl_send_msg(__s32 pid, __u32 seq, __s32 type, void *buf, __s32 len, __s32 flags);
void nl_data_ready(struct sk_buff *skb);

// This function extracts a unique ID from the kernel-space perspective for each socket
inline __u64 get_unique_sock_id(struct sock *sk);

struct nl_wedge_to_daemon_hdr {
	__u32 msg_len;
	__s32 part_len;
	__s32 pos;
};

struct nl_wedge_to_daemon {
	__u64 sock_id;
	__s32 sock_index;

	__u32 call_type;
	__s32 call_pid;

	__u32 call_id;
	__s32 call_index;
};

struct nl_daemon_to_wedge {
	__u32 call_type;

	union {
		__u32 call_id;
		__u64 sock_id; //TODO currently unused, remove if never needed
	};
	union {
		__s32 call_index;
		__s32 sock_index; //TODO currently unused, remove if never needed
	};

	__u32 ret;
	__u32 msg;
};

struct fins_wedge_call {
	__s32 running; //TODO remove?

	__u32 call_id;
	__u32 call_type;

	__u64 sock_id;
	__s32 sock_index;
	//TODO timestamp? so can remove after timeout/hit MAX_CALLS cap

	//struct semaphore sem; //TODO remove? might be unnecessary
	struct semaphore wait_sem;

	__u8 reply;
	__u32 ret;
	__u32 msg;
	__u8 *buf;
	__s32 len;
};

void wedge_calls_init(void);
__s32 wedge_calls_insert(__u32 id, __u64 sock_id, __s32 sock_index, __u32 type);
__s32 wedge_calls_find(__u64 sock_id, __s32 sock_index, __u32 type);
__s32 wedge_calls_remove(__u32 id);
void wedge_calls_remove_all(void);

struct fins_wedge_socket {
	__s32 running; //TODO remove? merge with release_flag

	__u64 sock_id;
	struct socket *sock;
	struct sock *sk;

	__s32 threads[MAX_CALL_TYPES];

	__s32 release_flag;
	struct socket *sock_new;
	struct sock *sk_new;
};

void wedge_sockets_init(void);
__s32 wedge_sockets_insert(__u64 sock_id, struct sock *sk);
__s32 wedge_sockets_find(__u64 sock_id);
__s32 wedge_sockets_remove(__u64 sock_id, __s32 sock_index, __u32 type);
void wedge_socket_remove_all(void);
__s32 wedge_sockets_wait(__u64 sock_id, __s32 sock_index, __u32 calltype);
__s32 checkConfirmation(__s32 sock_index);

/* This is a flag to enable or disable the FINS stack passthrough */
//__s32 fins_stack_passthrough_enabled;
//EXPORT_SYMBOL (fins_stack_passthrough_enabled);

#endif /* FINS_STACK_WEDGE_H_ */
