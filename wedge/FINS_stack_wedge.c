/*  
 * FINS_stack_wedge.c - 
 */

/* License and signing info */
#define M_LICENSE	"GPL"	// READ ABOUT THIS BEFORE CHANGING! Must be some form of GPL.
#define M_DESCRIPTION	"Registers the FINS protocol with the kernel"
#define M_AUTHOR	"Jonathan Reed <jonathanreed07@gmail.com>"

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
#include <asm/ioctls.h>
#include <linux/sockios.h>
#include <linux/ipx.h>
#include <linux/delay.h>

#include <asm/spinlock.h> //might be linux/spin... for rwlock
//#include <sys/socket.h> /* may need to be removed */
#include "FINS_stack_wedge.h"	/* Defs for this module */

// Create one semaphore here for every socketcall that is going to block
//struct semaphore FINS_semaphores[MAX_calls];
struct finssocket jinniSockets[MAX_sockets];

#define RECV_BUFFER_SIZE	1024	// Same as userspace, Pick an appropriate value here
//for compiling in non mod kernel
#ifndef PF_FINS
#define AF_FINS 2
#define PF_FINS AF_FINS
#endif
#ifndef NETLINK_FINS
#define NETLINK_FINS 20
#endif

/*
 struct semaphore shared_sem_w;
 struct semaphore shared_sem_r; //reassuring, but might not be necessary
 u_int shared_call;
 unsigned long long shared_sockID;
 int shared_ret;
 u_char *shared_buf;
 int shared_len;
 //*/

int print_exit(const char *func, int rc) {
	printk(KERN_INFO "FINS: %s: Exited: %d\n", func, rc);
	return rc;
}

rwlock_t jinnisockets_rwlock;

void init_jinnisockets(void) {
	int i;

	printk(KERN_INFO "FINS: %s: Entered\n", __FUNCTION__);

	rwlock_init(&jinnisockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		jinniSockets[i].uniqueSockID = -1;
		jinniSockets[i].type = -1;
		jinniSockets[i].protocol = -1;
	}

	printk(KERN_INFO "FINS: %s: Exited.\n", __FUNCTION__);
}

int insertjinniSocket(unsigned long long uniqueSockID, int type, int protocol) {
	int i;
	int j;

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	write_lock(&jinnisockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if ((jinniSockets[i].uniqueSockID == -1)) {
			jinniSockets[i].uniqueSockID = uniqueSockID;
			jinniSockets[i].type = type;
			jinniSockets[i].protocol = protocol;

			for (j = 0; j < MAX_calls; j++) {
				sema_init(&jinniSockets[i].call_sems[j], 0);
			}

			jinniSockets[i].threads = 0;
			sema_init(&jinniSockets[i].threads_sem, 1);
			jinniSockets[i].replies = 0;
			sema_init(&jinniSockets[i].replies_sem, 1);

			//jinniSockets[i].blockingFlag = 1;

			sema_init(&jinniSockets[i].reply_sem_w, 1);
			sema_init(&jinniSockets[i].reply_sem_r, 1);
			jinniSockets[i].reply_call = 0;
			jinniSockets[i].reply_ret = -1;
			jinniSockets[i].reply_buf = NULL;
			jinniSockets[i].reply_len = -1;

			write_unlock(&jinnisockets_rwlock);
			return print_exit(__FUNCTION__, i);
			//return (i);
		} else if (jinniSockets[i].uniqueSockID == uniqueSockID) {

			write_unlock(&jinnisockets_rwlock);
			return print_exit(__FUNCTION__, -1);
			//return (-1);
		}
	}

	write_unlock(&jinnisockets_rwlock);
	return print_exit(__FUNCTION__, -1);
	//return (-1);
}

int findjinniSocket(unsigned long long uniqueSockID) {
	int i;

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	read_lock(&jinnisockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == uniqueSockID) {
			read_unlock(&jinnisockets_rwlock);
			return print_exit(__FUNCTION__, i);
			//return (i);
		}
	}
	read_unlock(&jinnisockets_rwlock);
	return print_exit(__FUNCTION__, -1);
	//return (-1);
}

int removejinniSocket(unsigned long long uniqueSockID) {
	int i;
	int j;

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	write_lock(&jinnisockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == uniqueSockID) {
			jinniSockets[i].uniqueSockID = -1;
			jinniSockets[i].type = -1;
			jinniSockets[i].protocol = -1;
			write_unlock(&jinnisockets_rwlock);

			//clear semaphores?
			for (j = 0; j < jinniSockets[i].threads; j++) {
				up(&jinniSockets[i].reply_sem_w);
			}
			msleep(500);

			return (1);
		}
	}
	write_unlock(&jinnisockets_rwlock);
	return (-1);
}


int waitjinniSocket(unsigned long long uniqueSockID, u_int calltype) {
	int index;
	int count;

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	index = findjinniSocket(uniqueSockID);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	if (down_interruptible(&jinniSockets[index].threads_sem)) {
		;
	}
	jinniSockets[index].threads++;
	up(&jinniSockets[index].threads_sem);

	count = 0;
	while (count < LOOP_LIMIT) {
		printk(KERN_INFO "FINS: %s: index=%d, count=%d", __FUNCTION__, index, count);
		// ONLY FOR BLOCKING CALLS: must get a semaphore and go to sleep until daemon sends response and netlink handler unlocks semaphore
		// get semaphore before continuing - unlocked by netlink handler
		if (down_interruptible(&jinniSockets[index].call_sems[calltype])) {
			printk(KERN_INFO "FINS: %s: call aquire fail, using hard down sem[%d]=%d", __FUNCTION__, calltype, jinniSockets[index].call_sems[calltype].count);
			//down(&jinniSockets[index].call_sems[calltype]);
		} // block until daemon replies
		count++;

		if (down_interruptible(&jinniSockets[index].reply_sem_r)) {
			printk(KERN_INFO "FINS: %s: shared aquire fail, using hard down r=%d", __FUNCTION__, jinniSockets[index].reply_sem_r.count);
		}
		if (jinniSockets[index].uniqueSockID != uniqueSockID) {
			up(&jinniSockets[index].reply_sem_r);
			printk(KERN_ERR "FINS: %s: jinniSocket removed for uniqueSockID=%llu", __FUNCTION__, uniqueSockID);
			return print_exit(__FUNCTION__, -1);
		}

		if (jinniSockets[index].reply_call == calltype) {
			if (down_interruptible(&jinniSockets[index].replies_sem)) {
				printk(KERN_INFO "FINS: %s: jinniSockets[%d].replies_sem aquire fail", __FUNCTION__,index);
			}
			printk(KERN_INFO "FINS: %s: jinniSockets[%d].replies=%d", __FUNCTION__,index, jinniSockets[index].replies);
			if (jinniSockets[index].replies) {
				jinniSockets[index].replies--;
				if (jinniSockets[index].replies) {
					up(&jinniSockets[index].call_sems[calltype]);
				}
				up(&jinniSockets[index].replies_sem);
				break;
			} else {
				up(&jinniSockets[index].replies_sem);
			}
		} else {
			printk(KERN_ERR "FINS: %s: msg for (%d, %llu) recv by (%d, %llu)\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, calltype, uniqueSockID);
			//up(&jinniSockets[index].call_sems[calltype]);
		}
		up(&jinniSockets[index].reply_sem_r);
		//msleep(1);
	}

	if (down_interruptible(&jinniSockets[index].threads_sem)) {
		;
	}
	jinniSockets[index].threads--;
	up(&jinniSockets[index].threads_sem);

	if (count >= LOOP_LIMIT) {
		return print_exit(__FUNCTION__, -1);
	}

	return print_exit(__FUNCTION__, index);
}

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
	int rc = -ESOCKTNOSUPPORT;
	unsigned long long uniqueSockID;
	struct sock *sk;
	int index;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	printk(KERN_INFO "FINS: %s: Entered\n", __FUNCTION__);

	// Required stuff for kernel side	
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_FINS, GFP_KERNEL, &FINS_proto);

	if (!sk) {
		printk(KERN_ERR "FINS: %s: allocation failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, rc);
		// if allocation failed
	}
	sk_refcnt_debug_inc(sk);
	sock_init_data(sock, sk);

	sk->sk_no_check = 1;
	sock->ops = &FINS_proto_ops;

	rc = 0;
	uniqueSockID = getUniqueSockID(sock);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
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

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, socket_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = insertjinniSocket(uniqueSockID, sock->type, protocol);
	printk(KERN_INFO "FINS: %s: insert index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, socket_call);
	printk(KERN_INFO "FINS: %s: after index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
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
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;
	int index;
	struct sock *sk = sock->sk;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk (KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
	pt = buf;

	*(u_int *) pt = release_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, release_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, release_call);
	printk(KERN_INFO "FINS: %s: after index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	ret = removejinniSocket(uniqueSockID);
	if (ret == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	if (!sk)
		return print_exit(__FUNCTION__, rc);

	printk(KERN_INFO "FINS: %s: FINS_release -- sk was set.\n", __FUNCTION__);

	lock_sock(sk);
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_state_change(sk);

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	FINS_destroy_socket(sk);
	sock_put(sk);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	printk(KERN_INFO "FINS: %s: addr_len=%d.\n", __FUNCTION__, addr_len);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
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

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, bind_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, bind_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_connect(struct socket *sock, struct sockaddr *addr,
		int addr_len, int flags) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);
	printk(KERN_INFO "FINS: %s: addr_len=%d\n", __FUNCTION__, addr_len);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
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

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, connect_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, connect_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_socketpair(struct socket *sock1, struct socket *sock2) {
	unsigned long long uniqueSockID1, uniqueSockID2;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID1 = getUniqueSockID(sock1);
	uniqueSockID2 = getUniqueSockID(sock2);

	printk(KERN_INFO "FINS: %s: Entered for %llu, %llu.\n", __FUNCTION__, uniqueSockID1, uniqueSockID2);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_socketpair() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
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

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockIDoriginal);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_accept() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_getname(struct socket *sock, struct sockaddr *saddr, int *len,
		int peer) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;
	int calltype;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
	pt = buf;

	if (peer == 0) {
		calltype = getsockname_call;
	} else if (peer == 1) {
		calltype = getpeername_call;
	} else {
		printk(KERN_ERR "FINS: %s: unhanlded type: %d", __FUNCTION__, peer);
		calltype = getsockname_call; //???
	}

	*(u_int *) pt = calltype;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	//todo: finish, incorporate peers

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, getsockname_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, getsockname_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static unsigned int FINS_poll(struct file *file, struct socket *sock,
		poll_table *pt) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_poll() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	return 0;
}

static int FINS_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	switch (cmd) {
	case TIOCOUTQ:
		printk(KERN_INFO "FINS: %s: cmd=%d ==TIOCOUTQ", __FUNCTION__, cmd);
		break;
	case TIOCINQ:
		printk(KERN_INFO "FINS: %s: cmd=%d ==TIOCINQ", __FUNCTION__, cmd);
		break;
	case SIOCADDRT:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCADDRT", __FUNCTION__, cmd);
		break;
	case SIOCDELRT:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCDELRT", __FUNCTION__, cmd);
		break;
	case SIOCSIFADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCSIFADDR", __FUNCTION__, cmd);
		break;
	case SIOCAIPXITFCRT:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCAIPXITFCRT", __FUNCTION__, cmd);
		break;
	case SIOCAIPXPRISLT:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCAIPXPRISLT", __FUNCTION__, cmd);
		break;
	case SIOCGIFADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCGIFADDR", __FUNCTION__, cmd);
		break;
	case SIOCIPXCFGDATA:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCIPXCFGDATA", __FUNCTION__, cmd);
		break;
	case SIOCIPXNCPCONN:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCIPXNCPCONN", __FUNCTION__, cmd);
		break;
	case SIOCGSTAMP:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCGSTAMP", __FUNCTION__, cmd);
		break;
	case SIOCGIFDSTADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCGIFDSTADDR", __FUNCTION__, cmd);
		break;
	case SIOCSIFDSTADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCSIFDSTADDR", __FUNCTION__, cmd);
		break;
	case SIOCGIFBRDADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCGIFBRDADDR", __FUNCTION__, cmd);
		break;
	case SIOCSIFBRDADDR:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCSIFBRDADDR", __FUNCTION__, cmd);
		break;
	case SIOCGIFNETMASK:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCGIFNETMASK", __FUNCTION__, cmd);
		break;
	case SIOCSIFNETMASK:
		printk(KERN_INFO "FINS: %s: cmd=%d ==SIOCSIFNETMASK", __FUNCTION__, cmd);
		break;
	default:
		printk(KERN_INFO "FINS: %s: cmd=%d default", __FUNCTION__, cmd);
		break;
	}

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
	// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(u_long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
	pt = buf;

	*(u_int *) pt = ioctl_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = cmd;
	pt += sizeof(u_int);

	*(u_long *) pt = arg;
	pt += sizeof(u_long);

	//we have not supported this before
	//TODO: find out what else needs to be sent/done
	//http://lxr.linux.no/#linux+v2.6.39.4/net/ipx/af_ipx.c#L1858

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, ioctl_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, ioctl_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
			// do some stuff....
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_listen(struct socket *sock, int backlog) {
	int rc = 0;
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_listen() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	return print_exit(__FUNCTION__, rc);
}

static int FINS_shutdown(struct socket *sock, int how) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
	pt = buf;

	*(u_int *) pt = shutdown_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = how;
	pt += sizeof(int);

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, shutdown_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, shutdown_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = 2*sizeof(u_int) + sizeof(unsigned long long) + 2*sizeof(int) + optlen;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
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
	if (ret) {
		kfree(buf);
		return -1;
	}

	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, setsockopt_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, setsockopt_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if (jinniSockets[index].replies==0 && jinniSockets[index].reply_sem_w.count==0) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	// Build the message
	buf_len = sizeof(u_int) + sizeof(unsigned long long) + 3*sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		printk(KERN_ERR "FINS: %s: buffer allocation error", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}
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
	*(int *)pt = *optlen;//this function isn't actually implemented but this should be a pointer
	pt += sizeof(int);

	/*
	 *(char **)pt = optval;
	 *pt += sizeof (optval); //would this work?
	 */
	//could pass pointer of optlen & optval, have daemon trasnfer the info, would still need to block
	if (pt - (u_char *)buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, getsockopt_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);

	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	index = waitjinniSocket(uniqueSockID, getsockopt_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);

			pt = jinniSockets[index].reply_buf;

			//seems like this should be binding as well
			//use copy_from_user(pt, buf, len) to get from daemon
			//use copy_to_user(pt, buf, len) to get back to user space app

		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if (jinniSockets[index].replies==0 && jinniSockets[index].reply_sem_w.count==0) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_sendmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t len) {
	int rc = 0;
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
	int index;
	char *temp;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	if (m->msg_controllen != 0)
		controlFlag = 1;

	for (i = 0; i < (m->msg_iovlen); i++) {
		data_len += m->msg_iov[i].iov_len;
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
		return print_exit(__FUNCTION__, -1);
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

	temp = pt;

	i = 0;
	for (i = 0; i < m->msg_iovlen; i++) {
		memcpy(pt, m->msg_iov[i].iov_base, m->msg_iov[i].iov_len);
		pt += m->msg_iov[i].iov_len;
		//PRINT_DEBUG("current element %d , element length = %d", i ,(msg->msg_iov[i]).iov_len );
	}

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: data_len=%d", __FUNCTION__, data_len);
	printk(KERN_INFO "FINS: %s: data='%s'", __FUNCTION__, temp);

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, sendmsg_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
		// pick an appropriate errno
	}

	index = waitjinniSocket(uniqueSockID, sendmsg_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	//exract msg from jinniSockets[index].reply_buf
	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len == 0)) {
		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);
			rc = data_len;
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0)
			&& (jinniSockets[index].reply_sem_w.count == 0)) {
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_recvmsg(struct kiocb *iocb, struct socket *sock,
		struct msghdr *m, size_t len, int flags) {
	int rc = 0;
	unsigned long long uniqueSockID;
	int symbol = 1; //default value unless passes msg->msg_name equal NULL
	int controlFlag = 0;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;
	int i;

	struct sockaddr_in *addr_in;

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
	}

	if ((m->msg_controllen != 0) && m->msg_control)
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
		return print_exit(__FUNCTION__, -1);
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

	if (pt - (u_char *) buf != buf_len) {
		printk(KERN_ERR "FINS: %s: write error: diff=%d len=%d\n", __FUNCTION__, pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: socket_call=%d uniqueSockID=%llu buf_len=%d", __FUNCTION__, recvmsg_call, uniqueSockID, buf_len);
	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		printk(KERN_ERR "FINS: %s: nl_send failed\n", __FUNCTION__);
		return print_exit(__FUNCTION__, -1);
		// pick an appropriate errno
	}

	index = waitjinniSocket(uniqueSockID, recvmsg_call);
	printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
	if (index == -1) {
		return print_exit(__FUNCTION__, -1);
	}

	printk(KERN_INFO "FINS: %s: relocked my semaphore\n", __FUNCTION__);

	if (jinniSockets[index].reply_buf && (jinniSockets[index].reply_len
			>= sizeof(int))) {
		pt = jinniSockets[index].reply_buf;

		if (jinniSockets[index].reply_ret == ACK) {
			printk(KERN_INFO "FINS: %s: recv ACK\n", __FUNCTION__);

			if (symbol == 1) {
				//TODO: find out if this is right! udpHandling writes sockaddr_in here
				m->msg_namelen = *(u_int *) pt;
				pt += sizeof(u_int);

				printk(KERN_INFO "FINS: %s: msg_namelen=%d\n", __FUNCTION__, m->msg_namelen);

				if (m->msg_namelen > 0) {
					m->msg_name = kmalloc(m->msg_namelen, GFP_KERNEL);
					if (m->msg_name) {
						memcpy(m->msg_name, pt, m->msg_namelen);
						pt += m->msg_namelen;

						//########
						addr_in = (struct sockaddr_in *) m->msg_name;
						printk(KERN_INFO "FINS: %s: address: %d/%d", __FUNCTION__, (addr_in->sin_addr).s_addr, ntohs(addr_in->sin_port));
						//########
					} else {
						printk(KERN_ERR "FINS: %s: m->msg_name alloc failure\n", __FUNCTION__);
						rc = -1;
					}
				} else {
					printk(KERN_ERR "FINS: %s: address problem, msg_namelen=%d\n", __FUNCTION__, m->msg_namelen);
					rc = -1;
				}
			} else if (symbol) {
				printk(KERN_ERR "FINS: %s: symbol error, symbol=%d\n", __FUNCTION__, symbol); //will remove
				rc = -1;
			}

			buf_len = *(int *) pt; //reuse var since not needed anymore
			pt += sizeof(int);

			if (buf_len >= 0) {
				printk(KERN_ERR "FINS: %s: msg='%s'\n", __FUNCTION__, pt);

				ret = buf_len; //reuse as counter
				i = 0;
				while (ret > 0 && i < m->msg_iovlen) {
					if (ret > m->msg_iov[i].iov_len) {
						copy_to_user(m->msg_iov[i].iov_base, pt, m->msg_iov[i].iov_len);
						pt += m->msg_iov[i].iov_len;
						ret -= m->msg_iov[i].iov_len;
						i++;
					} else {
						copy_to_user(m->msg_iov[i].iov_base, pt, ret);
						pt += ret;
						ret = 0;
						break;
					}
				}
				if (ret) {
					//throw buffer overflow error?
					printk(KERN_ERR "FINS: %s: user buffer overflow error, overflow=%d\n", __FUNCTION__, ret);
				}
				rc = buf_len;
			} else {
				printk(KERN_ERR "FINS: %s: iov_base alloc failure\n", __FUNCTION__);
				rc = -1;
			}

			if (pt - jinniSockets[index].reply_buf
					!= jinniSockets[index].reply_len) {
				printk(KERN_ERR "FINS: %s: READING ERROR! diff=%d len=%d\n", __FUNCTION__, pt - jinniSockets[index].reply_buf, jinniSockets[index].reply_len);
				rc = -1;
			}
		} else if (jinniSockets[index].reply_ret == NACK) {
			printk(KERN_INFO "FINS: %s: recv NACK\n", __FUNCTION__);
			rc = -1;
		} else {
			printk(KERN_ERR "FINS: %s: error, acknowledgement: %d\n", __FUNCTION__, jinniSockets[index].reply_ret);
			rc = -1;
		}
	} else {
		printk(KERN_ERR "FINS: %s: jinniSockets[index].reply_buf error, jinniSockets[index].reply_len=%d jinniSockets[index].reply_buf=%p\n", __FUNCTION__, jinniSockets[index].reply_len, jinniSockets[index].reply_buf);
		rc = -1;
	}
	printk(KERN_INFO "FINS: %s: shared used: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
	up(&jinniSockets[index].reply_sem_r);

	if (down_interruptible(&jinniSockets[index].replies_sem)) {
		;
	}
	if ((jinniSockets[index].replies == 0) && (jinniSockets[index].reply_sem_w.count == 0)) {
		jinniSockets[index].reply_call = 0;
		printk(KERN_INFO "FINS: %s: shared consumed: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_w);
	}
	up(&jinniSockets[index].replies_sem);
	printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, rc);
}

static int FINS_mmap(struct file *file, struct socket *sock,
		struct vm_area_struct *vma) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		printk(KERN_ERR "FINS: %s: daemon not connected\n", __FUNCTION__);
		return -1; // pick an appropriate errno
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_mmap() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
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

	printk(KERN_INFO "FINS: %s: Entered for %llu.\n", __FUNCTION__, uniqueSockID);

	//TODO: finish this & daemon side

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
	if (ret) {
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
static struct net_proto_family FINS_net_proto = { .family = PF_FINS, .create =
FINS_wedge_create_socket, // This function gets called when socket() is called from userspace
		.owner = THIS_MODULE, };

/* Defines which functions get called when corresponding calls are made from userspace */
static struct proto_ops FINS_proto_ops = { .family = PF_FINS, .owner =
THIS_MODULE, .release = FINS_release, .bind = FINS_bind, //sock_no_bind,
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
	printk(KERN_ERR "FINS: %s: netlink Failed to allocate new skb\n", __FUNCTION__);
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
		printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n", __FUNCTION__, seq);
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
	printk(KERN_ERR "FINS: %s: netlink error sending seq %d to user\n",__FUNCTION__, seq);
	return -1;
}

kfree(part_buf);

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
	unsigned long long uniqueSockID;
	int index;

	u_int reply_call; // a number corresponding to the type of socketcall this packet is in response to

	printk(KERN_INFO "FINS: %s: Entered\n", __FUNCTION__);

	if (skb == NULL) {
		printk("skb is NULL \n");
		printk(KERN_INFO "FINS: %s: exited", __FUNCTION__);
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

	reply_call = *(u_int *) pt;
	pt += sizeof(u_int);
	len -= sizeof(u_int);

	if (reply_call == daemonconnect_call) {
		FINS_daemon_pid = pid;
		printk(KERN_INFO "FINS: %s: Daemon connected, pid=%d\n", __FUNCTION__,FINS_daemon_pid);
	} else if (reply_call < MAX_calls) {
		printk(KERN_INFO "FINS: %s: got a daemon reply to a call (%d).\n", __FUNCTION__, reply_call);
		/*
		 * extract msg or pass to shared buffer
		 * jinniSockets[index].reply_call & shared_sockID, are to verify buf goes to the write sock & call
		 * This is preemptive as with multithreading we may have to add a shared queue
		 */

		uniqueSockID = *(unsigned long long *) pt;
		pt += sizeof(unsigned long long);

		printk(KERN_ERR "FINS: %s: reply for uniqueSockID=%llu call=%d", __FUNCTION__, uniqueSockID, reply_call);

		index = findjinniSocket(uniqueSockID);
		printk(KERN_INFO "FINS: %s: index=%d", __FUNCTION__, index);
		if (index == -1) {
			printk(KERN_ERR "FINS: %s: socket not found for uniqueSockID=%llu", __FUNCTION__, uniqueSockID);
			printk(KERN_INFO "FINS: %s: exited", __FUNCTION__);
			return;
		}

		//lock the semaphore so shared data can't be changed until it's consumed
		printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_w=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_w.count);
		if (down_interruptible(&jinniSockets[index].reply_sem_w)) {
			printk(KERN_INFO "FINS: %s: shared aquire fail, using hard down w=%d", __FUNCTION__, jinniSockets[index].reply_sem_w.count);
		}

		printk(KERN_INFO "FINS: %s: jinniSockets[%d].reply_sem_r=%d\n", __FUNCTION__, index, jinniSockets[index].reply_sem_r.count);
		if (down_interruptible(&jinniSockets[index].reply_sem_r)) {
			printk(KERN_INFO "FINS: %s: shared aquire fail, using hard down r=%d", __FUNCTION__, jinniSockets[index].reply_sem_r.count);
		}

		if (jinniSockets[index].uniqueSockID != uniqueSockID) {
			printk(KERN_INFO "FINS: %s: exited", __FUNCTION__);
			printk(KERN_ERR "FINS: %s: jinniSocket removed for uniqueSockID=%llu", __FUNCTION__, uniqueSockID);
			return;
		}

		write_lock(&jinnisockets_rwlock);

		jinniSockets[index].reply_call = reply_call;

		jinniSockets[index].reply_ret = *(int *) pt;
		pt += sizeof(int);

		jinniSockets[index].reply_buf = pt;

		len -= sizeof(unsigned long long) + sizeof(int);
		jinniSockets[index].reply_len = len;

		if (down_interruptible(&jinniSockets[index].replies_sem)) {
			;
		}
		if (1) { //
			jinniSockets[index].replies = 1;
		} else {
			if (down_interruptible(&jinniSockets[index].threads_sem)) {
				;
			}
			jinniSockets[index].replies = jinniSockets[index].threads;
			up(&jinniSockets[index].threads_sem);
		}
		up(&jinniSockets[index].replies_sem);

		write_unlock(&jinnisockets_rwlock);

		printk(KERN_INFO "FINS: %s: shared created: call=%d, sockID=%llu, ret=%d, len=%d\n", __FUNCTION__, jinniSockets[index].reply_call, jinniSockets[index].uniqueSockID, jinniSockets[index].reply_ret, jinniSockets[index].reply_len);
		up(&jinniSockets[index].reply_sem_r);

		up(&jinniSockets[index].call_sems[reply_call]);
	} else {
		printk(KERN_INFO "FINS: %s: got an unsupported/binding daemon reply (%d)\n", __FUNCTION__, reply_call);
	}
}
printk(KERN_INFO "FINS: %s: exited", __FUNCTION__);
}

/* Helper function to extract a unique socket ID from a given struct sock */
inline unsigned long long getUniqueSockID(struct socket *sock) {
	return (unsigned long long) &(sock->sk->__sk_common); // Pointer to sock_common struct as unique ident
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
	init_jinnisockets();
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
