/*  
 * FINS_stack_wedge.c - 
 */

/* License and signing info */
#define M_LICENSE	"GPL"	// READ ABOUT THIS BEFORE CHANGING! Must be some form of GPL.
#define M_DESCRIPTION	"Registers the FINS protocol with the kernel"
#define M_AUTHOR	"Mark Horvath <bisondeveloper@gmail.com>"

/* Includes needed for LKM overhead */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
/* Includes for the protocol registration part (the main component, not the LKM overhead) */
#include <net/sock.h>		/* Needed for proto and sock struct defs, etc. */
#include <linux/socket.h>	/* Needed for the sockaddr struct def */
#include <linux/errno.h>	/* Needed for error number defines */
#include <linux/aio.h>		/* Needed for FINS_sendmsg */
#include <linux/skbuff.h>	/* Needed for sk_buff struct def, etc. */
#include <linux/net.h>		/* Needed for socket struct def, etc. */
/* Includes for the netlink socket part */
#include <linux/netlink.h>	/* Needed for netlink socket API, macros, etc. */
#include <linux/semaphore.h>	/* Needed to lock/unlock blocking calls with handler */
#include <asm/uaccess.h>

//#include <sys/socket.h> /* may need to be removed */
#include "FINS_stack_wedge.h"	/* Defs for this module */

// Create one semaphore here for every socketcall that is going to block
struct semaphore FINS_socket_sem;
struct semaphore FINS_bind_sem;
struct semaphore FINS_recvmsg_sem;

#define RECV_BUFFER_SIZE	1024	// Same as userspace, Pick an appropriate value here

//for compiling in non mod kernel
#ifndef PF_FINS
#define AF_FINS 2
#define PF_FINS AF_FINS
#endif
#ifndef NETLINK_FINS
#define NETLINK_FINS 20
#endif


u_char *shared_buf;
ssize_t shared_len;
u_int shared_call;
unsigned long long shared_sockID;

/* Wedge core functions (Protocol Registration) */
/*
 * This function tests whether the FINS data passthrough has been enabled or if the original stack is to be used
 * and passes data through appropriately.  This function is called when socket() call is made from userspace 
 * (specified in struct net_proto_family FINS_net_proto) 
 */
static int FINS_wedge_create_socket(struct net *net, struct socket *sock,
		int protocol, int kern) {
	if (FINS_stack_passthrough_enabled == 1) {
		return FINS_create_socket(net, sock, protocol, kern);
	} else { // Use original inet stack
		//	return inet_create(net, sock, protocol, kern);
	}
	return 0;
}

/* 
 * If the FINS stack passthrough is enabled, this function is called when socket() is called from userspace.
 * See FINS_wedge_create_socket for details.
 */
static int FINS_create_socket(struct net *net, struct socket *sock,
		int protocol, int kern) {
	unsigned long long uniqueSockID;
	int rc = -ESOCKTNOSUPPORT;
	struct sock *sk;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered\n", __FUNCTION__);

	// Required stuff for kernel side	
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_FINS, GFP_KERNEL, &FINS_proto);

	if (!sk) {
		printk(KERN_ERR "FINS: %s: allocation failed\n", __FUNCTION__);
		goto out;
		// if allocation failed
	}
	sk_refcnt_debug_inc(sk);
	sock_init_data(sock, sk);

	sk->sk_no_check = 1;
	sock->ops = &FINS_proto_ops;

	rc = 0;

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		rc = -1; // pick an appropriate errno
		goto out;
	}

	// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		rc = -1;
		goto out;
	}
	pt = buf;

	*(u_int *) pt = socket_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = AF_FINS; //~2, since this overrides AF_INET (39)
	pt += sizeof(int);

	*(u_int *) pt = sock->type;
	pt += sizeof(u_int);

	*(int *) pt = protocol;
	pt += sizeof(int);

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		rc = -1;
		goto out;
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, socket_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		rc = -1; // pick an appropriate errno
		goto out;
	}

	// ONLY FOR BLOCKING CALLS: must get a semaphore and go to sleep until daemon sends response and netlink handler unlocks semaphore
	// get semaphore before continuing - unlocked by netlink handler
	if (down_interruptible(&FINS_socket_sem)) {
		;
	} // Should be locked at start
	// relock the semaphore so it is locked next time around
	sema_init(&FINS_socket_sem, 0);
	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from shared_buf
	if ((shared_buf != NULL) && (shared_len == sizeof(int))) {
		if ((socket_call != shared_call) || (uniqueSockID != shared_sockID)) {
			printk(KERN_ERR "FINS: %s: msg for (%d, %llu) recv by (%d, %llu)\n", __FUNCTION__, shared_call, shared_sockID, socket_call, uniqueSockID);
			rc = -1;
		} else {
			pt = shared_buf;

			ret = *(int *) pt;
			pt += sizeof(int);

			if (ret == ACK) {
				printk			(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
			} else if (ret == NACK) {
				printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
				rc = -1;
			} else {
				printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
				rc = -1;
			}
			shared_buf = NULL;
			shared_len = 0;
		}
	} else {
		printk(KERN_ERR "FINS: %s: shared_buf error, shared_len=%d shared_buf=%p\n", __FUNCTION__, shared_len, shared_buf);
		rc = -1;
	}

	out: printk(KERN_INFO "FINS %s: Exited\n", __FUNCTION__);
	return rc;
}

/* This function is called from within FINS_release and is modeled after ipx_destroy_socket() */
static void FINS_destroy_socket(struct sock *sk) {
	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);
	skb_queue_purge(&sk->sk_receive_queue);
	sk_refcnt_debug_dec(sk);
}

/*
 * This function is called automatically to cleanup when a program that 
 * created a socket terminates.
 * Or manually via close()?????
 * Modeled after ipx_release().
 */
static int FINS_release(struct socket *sock) {
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;
	struct sock *sk = sock->sk;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk	(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
	} else {
		pt = buf;

		*(u_int *) pt = release_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		if (pt - (u_char *)buf != buf_len) {
			printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
			kfree(buf);
			return -1;
		}

		printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, release_call, uniqueSockID, buf_len);

		// Send message to FINS_daemon
		ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);

		if (ret != 0) {
			printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
			return -1; // pick an appropriate errno
		}
	}

	if (!sk)
		goto out;

	printk(KERN_INFO "FINS: %s: FINS_release -- sk was set.\n", __FUNCTION__);

	lock_sock(sk);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	FINS_destroy_socket(sk);
	sock_put(sk);
	out: return 0;
}

static int FINS_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
	unsigned long long uniqueSockID;
	int rc;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		rc = -1;
		goto out;
	}

	pt = buf;

	*(u_int *) pt = bind_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		rc = -1;
		goto out;
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, bind_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		rc = -1; // pick an appropriate errno
		goto out;
	}

	if (down_interruptible(&FINS_bind_sem)) {;} // block until daemon replies
	sema_init(&FINS_bind_sem, 0); // relock semaphore
	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from shared_buf
	if ((shared_buf != NULL) && (shared_len == sizeof(int))) {
		if ((bind_call != shared_call) || (uniqueSockID != shared_sockID)) {
			printk(KERN_ERR "FINS: %s: msg for (%d, %llu) recv by (%d, %llu)\n", __FUNCTION__, shared_call, shared_sockID, bind_call, uniqueSockID);
			rc = -1;
		} else {
			pt = shared_buf;

			ret = *(int *) pt;
			pt += sizeof(int);

			if (ret == ACK) {
				printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
			} else if (ret == NACK) {
				printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
				rc = -1;
			} else {
				printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
				rc = -1;
			}
			shared_buf = NULL;
			shared_len = 0;
		}
	} else {
		printk(KERN_ERR "FINS: %s: shared_buf error, shared_len=%d shared_buf=%p\n", __FUNCTION__, shared_len, shared_buf);
		rc = -1;
	}

	out: printk(KERN_INFO "FINS: %s: Exited\n", __FUNCTION__);
	return rc;
}

static int FINS_connect(struct socket *sock, struct sockaddr *addr,
		int addr_len, int flags) {
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return -1;
	}

	pt = buf;

	*(u_int *) pt = connect_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return -1;
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, connect_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_socketpair(struct socket *sock1, struct socket *sock2) {
	unsigned long long uniqueSockID1, uniqueSockID2;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID1 = getUniqueSockID(sock1);
	uniqueSockID2 = getUniqueSockID(sock2);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_socketpair() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_accept(struct socket *sock, struct socket *newsock, int flags) {
	unsigned long long uniqueSockIDoriginal, uniqueSockIDnew;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockIDoriginal = getUniqueSockID(sock);
	uniqueSockIDnew = getUniqueSockID(newsock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_accept() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_getname(struct socket *sock, struct sockaddr *saddr, int *len,
		int peer) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_getname() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static unsigned int FINS_poll(struct file *file, struct socket *sock,
		poll_table *pt) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_poll() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}
	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return -1;
	} else {
		pt = buf;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		//we have not supported this before
		//TODO: find out what else needs to be sent/done

		if (pt - (u_char *)buf != buf_len) {
			printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
			kfree(buf);
			return -1;
		}

		printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, ioctl_call, uniqueSockID, buf_len);

		// Send message to FINS_daemon
		ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);

		if (ret != 0) {
			printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
			return -1; // pick an appropriate errno
		}
	}

	return 0;
}

static int FINS_listen(struct socket *sock, int backlog) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_listen() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_shutdown(struct socket *sock, int how) {
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return -1;
	} else {
		pt = buf;

		*(u_int *) pt = shutdown_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *) pt = how;
		pt += sizeof(int);

		if (pt - (u_char *)buf != buf_len) {
			printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
			kfree(buf);
			return -1;
		}

		printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, shutdown_call, uniqueSockID, buf_len);

		// Send message to FINS_daemon
		ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);

		if (ret != 0) {
			printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
			return -1; // pick an appropriate errno
		}
	}

	return 0;
}

static int FINS_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = 2*sizeof(u_int) + sizeof(unsigned long long) + 2*sizeof(int) + optlen;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return -1;
	} else {
		pt = buf;

		*(u_int *)pt = setsockopt_call;
		pt += sizeof(u_int);

		*(unsigned long long *)pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *)pt = level;
		pt += sizeof(int);

		*(int *)pt = optname;
		pt += sizeof(int);

		*(u_int *)pt = optlen;
		pt += sizeof(u_int);

		ret = copy_from_user(pt, optval, optlen);
		pt += optlen;
		if (ret != 0) {
			kfree(buf);
			return -1;
		}

		if (pt - (u_char *)buf != buf_len) {
			printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
			kfree(buf);
			return -1;
		}

		printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, setsockopt_call, uniqueSockID, buf_len);

		// Send message to FINS_daemon
		ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);

		if (ret != 0) {
			printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
			return -1; // pick an appropriate errno
		}
	}

	return 0;
}

static int FINS_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen) {
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + 3*sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return -1;
	} else {
		pt = buf;

		*(u_int *)pt = getsockopt_call;
		pt += sizeof(u_int);

		*(unsigned long long *)pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *)pt = level;
		pt += sizeof(int);

		*(int *)pt = optname;
		pt += sizeof(int);

		//TODO: finish this part
		*(int *)pt = *optlen; //this function isn't actually implemented but this should be a pointer
		pt += sizeof(int);

		/*
		 *(char **)pt = optval;
		 *pt += sizeof (optval); //would this work?
		 */
		//could pass pointer of optlen & optval, have daemon trasnfer the info, would still need to block

		if (pt - (u_char *)buf != buf_len) {
			printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
			kfree(buf);
			return -1;
		}

		printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, getsockopt_call, uniqueSockID, buf_len);

		// Send message to FINS_daemon
		ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);

		if (ret != 0) {
			printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
			return -1; // pick an appropriate errno
		}

		//seems like this should be binding as well
		//use copy_from_user(pt, buf, len) to get from daemon
		//use copy_to_user(pt, buf, len) to get back to user space app

	}
	return 0;
}

static int FINS_sendmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t len) {
	unsigned long long uniqueSockID;
	int controlFlag = 0;
	int i = 0;
	u_int data_len = 0;
	int symbol = 1; //default value unless passes address equal NULL
	int flags = 0; //TODO: determine correct value

	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	if (m->msg_controllen != 0)
		controlFlag = 1;

	for (i = 0; i < (m->msg_iovlen); i++) {
		data_len += (m->msg_iov[i]).iov_len;
	}

	if (m->msg_name == NULL)
		symbol = 0;

	// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + 4 * sizeof(int)
			+ (symbol ? sizeof(u_int) + m->msg_namelen : 0)
			+ (controlFlag ? sizeof(u_int) + m->msg_controllen : 0) + data_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buf allocation failed\n", __FUNCTION__);
		return -1;
	}
	pt = buf;

	*(u_int *) pt = sendmsg_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = flags; //TODO: fill in correct value
	pt += sizeof(int);

	*(int *) pt = symbol;
	pt += sizeof(int);

	if (symbol) {
		*(u_int *) pt = m->msg_namelen; //socklen_t is of type u_int
		pt += sizeof(u_int);

		memcpy(pt, m->msg_name, m->msg_namelen);
		pt += m->msg_namelen;
	}

	*(int *) pt = m->msg_flags;
	pt += sizeof(int);

	*(int *) pt = controlFlag;
	pt += sizeof(int);

	if (controlFlag) {
		*(u_int *) pt = m->msg_controllen;
		pt += sizeof(u_int);

		memcpy(pt, m->msg_control, m->msg_controllen);
		pt += m->msg_controllen;
	}
	//Notice that the compiler takes  (msg->msg_iov[i]) as a struct not a pointer to struct

	*(u_int *) pt = data_len;
	pt += sizeof(u_int);

	i = 0;
	for (i = 0; i < (m->msg_iovlen); i++) {
		memcpy(pt, (m->msg_iov[i]).iov_base, (m->msg_iov[i]).iov_len);
		pt += (m->msg_iov[i]).iov_len;
		//PRINT_DEBUG("current element %d , element length = %d", i ,(msg->msg_iov[i]).iov_len );
	}

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return -1;
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, sendmsg_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1;
		// pick an appropriate errno
	}

	return 0;
}

static int FINS_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t len, int flags) {
	unsigned long long uniqueSockID;
	int symbol = 1; //default value unless passes msg->msg_name equal NULL
	int controlFlag = 0;
	int rc = 0;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		rc = -1;
		goto out;
	}

	if ((m->msg_controllen != 0) && (m->msg_control != NULL))
		controlFlag = 1;
	if (m->msg_name == NULL)
		symbol = 0;

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(ssize_t) + 4
			* sizeof(int) + (controlFlag ? sizeof(u_int) + m->msg_controllen
			: 0);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buf allocation failed\n", __FUNCTION__);
		rc = -1;
		goto out;
	}
	pt = buf;

	*(u_int *) pt = recvmsg_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(ssize_t *) pt = len;
	pt += sizeof(ssize_t);

	*(int *) pt = flags;
	pt += sizeof(int);

	*(int *) pt = symbol;
	pt += sizeof(int);

	*(int *) pt = m->msg_flags;
	pt += sizeof(int);

	*(int *) pt = controlFlag;
	pt += sizeof(int);

	if (controlFlag) {
		*(u_int *) pt = m->msg_controllen;
		pt += sizeof(u_int);

		memcpy(pt, m->msg_control, m->msg_controllen);
		pt += m->msg_controllen;
	}

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		rc = -1;
		goto out;
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, recvmsg_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		rc = -1;
		goto out;
		// pick an appropriate errno
	}

	if (down_interruptible(&FINS_recvmsg_sem)) {
		;
	} // block until daemon replies
	sema_init(&FINS_recvmsg_sem, 0); // relock semaphore
	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from shared_buf
	if ((shared_buf != NULL) && (shared_len >= sizeof(int))) {
		if ((recvmsg_call == shared_call) && (uniqueSockID == shared_sockID)) {
			pt = shared_buf;

			ret = *(int *) pt;
			pt += sizeof(int);

			if (ret == ACK) {
				printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);

				if (symbol == 1) {
					//TODO: find out if this is right! udpHandling writes sockaddr_in here
					m->msg_namelen = *(u_int *) pt;
					pt += sizeof(u_int);

					printk(KERN_INFO "FINS: %s: msg_namelen=%d\n", __FUNCTION__, m->msg_namelen);

					if (m->msg_namelen > 0) {
						memcpy(m->msg_name, pt, m->msg_namelen);
						pt += m->msg_namelen;
					} else {
						printk(KERN_ERR "FINS: %s: address problem, msg_namelen=%d\n", __FUNCTION__, m->msg_namelen);
						rc = -1;
					}
				} else if (symbol != 0) {
					printk(KERN_ERR "FINS: %s: symbol error, symbol=%d\n", __FUNCTION__, symbol); //will remove
					rc = -1;
				}

				buf_len = *(int *) pt; //reuse var since not needed anymore
				pt += sizeof(int);

				if (buf_len >= 0) {
					m->msg_iov->iov_len = buf_len;
					//TODO: possible memory leak? find out
					m->msg_iov->iov_base = (u_char *) kmalloc(buf_len,
							GFP_KERNEL);
					if (m->msg_iov->iov_base) {
						memcpy(m->msg_iov->iov_base, pt, buf_len);
						pt += buf_len;

						m->msg_iovlen = 1;
						if (rc != -1) {
							rc = buf_len;
						}
					} else {
						printk(KERN_ERR "FINS: %s: iov_base alloc failure\n", __FUNCTION__);
						rc = -1;
					}
				} else {
					printk(KERN_ERR "FINS: %s: iov_base alloc failure\n", __FUNCTION__);
					rc = -1;
				}

				if (pt - shared_buf != shared_len) {
					printk(KERN_ERR "FINS: %s: READING ERROR! diff=%d len=%d\n", __FUNCTION__, pt - shared_buf, shared_len);
					rc = -1;
				}
			} else if (ret == NACK) {
				printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
				rc = -1;
			} else {
				printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
				rc = -1;
			}
			shared_buf = NULL;
			shared_len = 0;
		} else {
			printk(KERN_ERR "FINS: %s: msg for (%d, %llu) recv by (%d, %llu)\n", __FUNCTION__, shared_call, shared_sockID, recvmsg_call, uniqueSockID);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: shared_buf error, shared_len=%d shared_buf=%p\n", __FUNCTION__, shared_len, shared_buf);
		rc = -1;
	}

	out: printk(KERN_INFO "FINS: %s: Exited\n", __FUNCTION__);
	return rc;
}

static int FINS_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_mmap() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	/* Mirror missing mmap method error code */
	return -ENODEV;
}

static ssize_t FINS_sendpage(struct socket *sock, struct page *page,
		int offset, size_t size, int flags) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: called.\n", __FUNCTION__);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	// Build the message
	buf = "FINS_sendpage() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret != 0) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	/* See sock_no_sendpage() in /net/core/sock.c for more information of what maybe should go here? */
	return 0;
}

/* Data structures needed for protocol registration */
/* A proto struct for the dummy protocol */
static struct proto FINS_proto = { .name = "FINS_PROTO", .owner = THIS_MODULE,
		.obj_size = sizeof(struct FINS_sock), };

/* see IPX struct net_proto_family ipx_family_ops for comparison */
static struct net_proto_family FINS_net_proto = { .family = PF_FINS,
		.create = FINS_wedge_create_socket, // This function gets called when socket() is called from userspace
		.owner = THIS_MODULE, };

/* Defines which functions get called when corresponding calls are made from userspace */
static struct proto_ops FINS_proto_ops = { .family = PF_FINS,
		.owner = THIS_MODULE, .release = FINS_release, .bind = FINS_bind, //sock_no_bind,
		.connect = FINS_connect, //sock_no_connect,
		.socketpair = FINS_socketpair, //sock_no_socketpair,
		.accept = FINS_accept, //sock_no_accept,
		.getname = FINS_getname, //sock_no_getname,
		.poll = FINS_poll, //sock_no_poll,
		.ioctl = FINS_ioctl, //sock_no_ioctl,
		.listen = FINS_listen, //sock_no_listen,
		.shutdown = FINS_shutdown, //sock_no_shutdown,
		.setsockopt = FINS_setsockopt, //sock_no_setsockopt,
		.getsockopt = FINS_getsockopt, //sock_no_getsockopt,
		.sendmsg = FINS_sendmsg, //sock_no_sendmsg,
		.recvmsg = FINS_recvmsg, //sock_no_recvmsg,
		.mmap = FINS_mmap, //sock_no mmap,
		.sendpage = FINS_sendpage, //sock_no_sendpage,
		};

/* FINS Netlink functions  */
/*
 * Sends len bytes from buffer buf to process pid, and sets the flags.
 * If buf is longer than RECV_BUFFER_SIZE, it's broken into sequential messages.
 * Returns 0 if successful or -1 if an error occurred.
 */

//assumes msg_buf is just the msg, does not have a prepended msg_len
//break msg_buf into parts of size RECV_BUFFER_SIZE with a prepended header (header part of RECV...)
//prepend msg header: total msg length, part length, part starting position
int nl_send_msg(int pid, unsigned int seq, int type, void *buf, ssize_t len,
		int flags) {
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int ret_val;

	//####################
	u_char *print_buf;
	u_char *print_pt;
	u_char *pt;
	int i;

	printk(KERN_INFO "FINS: %s: pid=%d, seq=%d, type=%d, len=%d", __FUNCTION__, pid, seq, type, len);

	print_buf = kmalloc(5 * len, GFP_KERNEL);
	if (!print_buf) {
		printk	(KERN_ERR "FINS: %s: print_buf allocation fail", __FUNCTION__);
	} else {
		print_pt = print_buf;
		pt = buf;
		for (i = 0; i < len; i++) {
			if (i == 0) {
				sprintf(print_pt, "%02x", *(pt + i));
				print_pt += 2;
			} else if (i % 4 == 0) {
				sprintf(print_pt, ":%02x", *(pt + i));
				print_pt += 3;
			} else {
				sprintf(print_pt, " %02x", *(pt + i));
				print_pt += 3;
			}
		}
		printk(KERN_INFO "FINS: %s: buf='%s'", __FUNCTION__, print_buf);
		kfree(print_buf);
	}
	//####################


	// Allocate a new netlink message
	skb = nlmsg_new(len, 0); // nlmsg_new(size_t payload, gfp_t flags)
	if (!skb) {
		printk(KERN_ERR "FINS: %s: netlink Failed to allocate new skb\n",
		__FUNCTION__);
		return -1;
	}

	// Load nlmsg header
	// nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int payload, int flags)
	nlh = nlmsg_put(skb, KERNEL_PID, seq, type, len, flags);
	NETLINK_CB(skb).dst_group = 0; // not in a multicast group

	// Copy data into buffer
	memcpy(NLMSG_DATA(nlh), buf, len);

	// Send the message
	ret_val = nlmsg_unicast(FINS_nl_sk, skb, pid);
	if (ret_val < 0) {
		printk(KERN_ERR "FINS: %s: netlink error sending to user\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

int nl_send(int pid, void *msg_buf, ssize_t msg_len, int flags) {
	int ret;
	void *part_buf;
	u_char *msg_pt;
	int pos;
	u_int seq;
	u_char *hdr_msg_len;
	u_char *hdr_part_len;
	u_char *hdr_pos;
	u_char *msg_start;
	ssize_t header_size;
	ssize_t part_len;

	//####################
	u_char *print_buf;
	u_char *print_pt;
	u_char *pt;
	int i;

	print_buf = kmalloc(5 * msg_len, GFP_KERNEL);
	if (!print_buf) {
		printk	(KERN_ERR "FINS: %s: print_buf allocation fail", __FUNCTION__);
	} else {
		print_pt = print_buf;
		pt = msg_buf;
		for (i = 0; i < msg_len; i++) {
			if (i == 0) {
				sprintf(print_pt, "%02x", *(pt + i));
				print_pt += 2;
			} else if (i % 4 == 0) {
				sprintf(print_pt, ":%02x", *(pt + i));
				print_pt += 3;
			} else {
				sprintf(print_pt, " %02x", *(pt + i));
				print_pt += 3;
			}
		}
		printk(KERN_INFO "FINS: %s: nl_send: msg_buf='%s'", __FUNCTION__, print_buf);
		kfree(print_buf);
	}
	//####################


	part_buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
	if (!part_buf) {
		printk (KERN_ERR "FINS: %s: part_buf allocation fail", __FUNCTION__);
	}

	msg_pt = msg_buf;
	pos = 0;
	seq = 0;

	hdr_msg_len = part_buf;
	hdr_part_len = hdr_msg_len + sizeof(ssize_t);
	hdr_pos = hdr_part_len + sizeof(ssize_t);
	msg_start = hdr_pos + sizeof(int);

	header_size = msg_start - hdr_msg_len;
	part_len = RECV_BUFFER_SIZE - header_size;

	*(ssize_t *) hdr_msg_len = msg_len;
	*(ssize_t *) hdr_part_len = part_len;

	while (msg_len - pos > part_len) {
		printk(KERN_INFO "FINS: %s: pos=%d", __FUNCTION__, pos);

		*(int *) hdr_pos = pos;

		memcpy(msg_start, msg_pt, part_len);

		printk(KERN_INFO "FINS: %s: seq=%d", __FUNCTION__, seq);

		ret
				= nl_send_msg(pid, seq, 0x0, part_buf, RECV_BUFFER_SIZE, flags/*| NLM_F_MULTI*/);
		if (ret < 0) {
			printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n",
			__FUNCTION__, seq);
			return -1;
		}

		msg_pt += part_len;
		pos += part_len;
		seq++;
	}

	part_len = msg_len - pos;
	*(ssize_t *) hdr_part_len = part_len;
	*(int *) hdr_pos = pos;

	memcpy(msg_start, msg_pt, part_len);

	ret = nl_send_msg(pid, seq, NLMSG_DONE, part_buf, header_size + part_len,
			flags);
	if (ret < 0) {
		printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n",
		__FUNCTION__, seq);
		return -1;
	}

	kfree(part_buf);

	return 0;
}

//assumes that the msg (buf) has a first value of msg_len, does not append header
int nl_send_old(int pid, void *buf, ssize_t msg_len, int flags) {
	ssize_t len = msg_len;
	u_int seq = 0;
	int ret;

	while (len > RECV_BUFFER_SIZE) {
		ret = nl_send_msg(pid, seq, 0x0, buf, RECV_BUFFER_SIZE, flags
				| NLM_F_MULTI);
		if (ret < 0) {
			printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n",
			__FUNCTION__, seq);
			return -1;
		}

		buf += RECV_BUFFER_SIZE;
		len -= RECV_BUFFER_SIZE;
		seq++;
	}

	ret = nl_send_msg(pid, seq, NLMSG_DONE, buf, len, flags);
	if (ret < 0) {
		printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n",
		__FUNCTION__, seq);
		return -1;
	}

	return 0;
}

/*
 * This function is automatically called when the kernel receives a datagram on the corresponding netlink socket. 
 */
void nl_data_ready(struct sk_buff *skb) {
	struct nlmsghdr *nlh = NULL;
	void *buf; // Pointer to data in payload
	u_char *pt;
	ssize_t len; // Payload length
	int pid; // pid of sending process

	u_int socketDaemonResponseType; // a number corresponding to the type of socketcall this packet is in response to

	printk(KERN_INFO "FINS: %s, Entered\n", __FUNCTION__);

	if (skb == NULL) {
		printk("skb is NULL \n");
		return;
	}
	nlh = (struct nlmsghdr *) skb->data;
	pid = nlh->nlmsg_pid; // get pid from the header

	// Get a pointer to the start of the data in the buffer and the buffer (payload) length
	buf = NLMSG_DATA(nlh);
	len = NLMSG_PAYLOAD(nlh, 0);

	printk(KERN_INFO "FINS: %s, nl_len=%d\n", __FUNCTION__, len);

	// **** Remember the LKM must be up first, then the daemon, 
	// but the daemon must make contact before any applications try to use socket()

	if (pid == -1) { // if the socket daemon hasn't made contact before
		// Print what we received
		printk	(KERN_INFO "FINS: %s: Socket Daemon made contact: %s\n", __FUNCTION__, (char *) buf);
	} else {
		// demultiplex to the appropriate call handler
		pt = buf;

		socketDaemonResponseType = *(u_int *) pt;
		pt += sizeof(u_int);
		len -= sizeof(u_int);

		switch (socketDaemonResponseType) {
		case daemonconnect_call:
			FINS_daemon_pid = pid;

			printk(KERN_INFO "FINS: %s: Daemon connected, pid=%d\n", __FUNCTION__,FINS_daemon_pid);
			/*
			 char *test = "test string";
			 int stringlength = strlen(test) + 1;
			 int ret;
			 ret = nl_send(FINS_daemon_pid, test, stringlength, 0);
			 */
			break;
		case socket_call:
			// do whatever you need to here as a handler
			printk(KERN_INFO "FINS: %s: got a daemon reply to a socket() call.\n",
			__FUNCTION__);
			/*
			 * extract msg or pass to shared buffer
			 * shared_call & shared_sockID, are to verify buf goes to the write sock & call
			 * This is preemptive as with multithreading we may have to add a shared queue
			 */
			shared_call = socketDaemonResponseType;
			shared_sockID = *(unsigned long long *) pt;
			pt += sizeof(unsigned long long);
			len -= sizeof(unsigned long long);

			shared_buf = pt;
			shared_len = len;

			up(&FINS_socket_sem); // unblock the socket call
			break;
		case bind_call:
			printk(KERN_INFO "FINS: %s: got a daemon reply to a bind() call\n",
			__FUNCTION__);
			shared_call = socketDaemonResponseType;
			shared_sockID = *(unsigned long long *) pt;
			pt += sizeof(unsigned long long);
			len -= sizeof(unsigned long long);

			shared_buf = pt;
			shared_len = len;

			up(&FINS_bind_sem); // unblock the bind call
			break;
		case recv_call:
		case recvfrom_call:
		case recvmsg_call:
			printk(KERN_INFO "FINS: %s: got a daemon reply to a recv(), recvfrom(), or recvmsg() call\n",
			__FUNCTION__);

			shared_call = socketDaemonResponseType;
			shared_sockID = *(unsigned long long *) pt;
			pt += sizeof(unsigned long long);
			len -= sizeof(unsigned long long);

			shared_buf = pt;
			shared_len = len;

			up(&FINS_recvmsg_sem); // unblock the recvmsg call
			break;
		default:
			printk(KERN_INFO "FINS: %s: got an unsupported/binding daemon reply (%d)\n", __FUNCTION__, socketDaemonResponseType);
			break;
		}
	}

	// Ok to process netlink message here if fast, otherwise use another kernel thread and wake it up here
	printk(KERN_INFO "FINS: %s: shared_len=%d\n", __FUNCTION__, shared_len);
}

/* Helper function to extract a unique socket ID from a given struct sock */
inline unsigned long long getUniqueSockID(struct socket *sock) {
	return (unsigned long long) &(sock->sk->__sk_common); // Pointer to sock_common struct as unique ident
}

static void setup_FINS_blocking_semaphores(void) {
	// initialize all semaphores used for blocking calls to locked state at first	
	sema_init(&FINS_socket_sem, 0);
	sema_init(&FINS_bind_sem, 0);
	sema_init(&FINS_recvmsg_sem, 0);
}

/* Functions to initialize and teardown the protocol */
static void setup_FINS_protocol(void) {
	int rc; // used for reporting return value

	// Changing this value to 0 disables the FINS passthrough by default
	// Changing this value to 1 enables the FINS passthrough by default
	FINS_stack_passthrough_enabled = 1; // Initialize kernel wide FINS data passthrough

	/* Call proto_register and report debugging info */
	rc = proto_register(&FINS_proto, 1);
	printk(KERN_INFO "FINS: %s: proto_register returned: %d\n", __FUNCTION__, rc);
	printk(KERN_INFO "FINS: %s: Made it through FINS proto_register()\n", __FUNCTION__);

	/* Call sock_register to register the handler with the socket layer */
	rc = sock_register(&FINS_net_proto);
	printk(KERN_INFO "FINS: %s: sock_register returned: %d\n", __FUNCTION__, rc);
	printk(KERN_INFO "FINS: %s: Made it through FINS sock_register()\n", __FUNCTION__);
}

static void teardown_FINS_protocol(void) {
	/* Call sock_unregister to unregister the handler with the socket layer */
	sock_unregister(FINS_net_proto.family);
	printk(KERN_INFO "FINS: %s: Made it through FINS sock_unregister()\n", __FUNCTION__);

	/* Call proto_unregister and report debugging info */
	proto_unregister(&FINS_proto);
	printk(KERN_INFO "FINS: %s: Made it through FINS proto_unregister()\n", __FUNCTION__);
}

/* Functions to initialize and teardown the netlink socket */
static int setup_FINS_netlink(void) {
	// nl_data_ready is the name of the function to be called when the kernel receives a datagram on this netlink socket.
	FINS_nl_sk = netlink_kernel_create(&init_net, NETLINK_FINS, 0,
			nl_data_ready, NULL, THIS_MODULE);
	if (!FINS_nl_sk) {
		printk(KERN_ALERT "FINS: %s: Error creating socket.\n", __FUNCTION__);
		return -10;
	}
	return 0;
}

static void teardown_FINS_netlink(void) {
	// closes the netlink socket
	if (FINS_nl_sk != NULL) {
		sock_release(FINS_nl_sk->sk_socket);
	}
}

/* LKM specific functions */
/* 
 * Note: the init and exit functions must be defined (or declared/declared in header file) before the macros are called
 */
static int __init FINS_stack_wedge_init(void) {
	printk(KERN_INFO "FINS: %s: #################################", __FUNCTION__);
	printk(KERN_INFO "FINS: %s: Loading the FINS_stack_wedge module\n", __FUNCTION__);
	setup_FINS_protocol();
	setup_FINS_netlink();
	setup_FINS_blocking_semaphores();
	printk(KERN_INFO "FINS: %s: Made it through the FINS_stack_wedge initialization\n", __FUNCTION__);
	return 0;
}

static void __exit FINS_stack_wedge_exit(void) {
	printk(KERN_INFO "FINS: %s: Unloading the FINS_stack_wedge module\n", __FUNCTION__);
	teardown_FINS_netlink();
	teardown_FINS_protocol();
	printk(KERN_INFO "FINS: %s: Made it through the FINS_stack_wedge removal\n", __FUNCTION__);
	// the system call wrapped by rmmod frees all memory that is allocated in the module
}

/* Macros defining the init and exit functions */
module_init( FINS_stack_wedge_init);
module_exit( FINS_stack_wedge_exit);

/* Set the license and signing info for the module */
MODULE_LICENSE(M_LICENSE);
MODULE_DESCRIPTION(M_DESCRIPTION);
MODULE_AUTHOR(M_AUTHOR);
