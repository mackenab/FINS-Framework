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
#include <linux/if.h>

#include <asm/spinlock.h> //might be linux/spin... for rwlock
//#include <sys/socket.h> /* may need to be removed */
#include "FINS_stack_wedge.h"	/* Defs for this module */

#define RECV_BUFFER_SIZE	1024	// Same as userspace, Pick an appropriate value here
//for compiling in non mod kernel, will compile but not run
#ifndef PF_FINS
#define AF_FINS 2
#define PF_FINS AF_FINS
#endif
#ifndef NETLINK_FINS
#define NETLINK_FINS 20
#endif

//commenting stops debug printout
#define DEBUG
#define ERROR

#ifdef DEBUG
//#define PRINT_ERROR(format, args...) printk(KERN_DEBUG "FINS: DEBUG: %s, %s,  %d: "format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);
#define PRINT_DEBUG(format, args...) printk(KERN_DEBUG "FINS: DEBUG: %s, %d: "format"\n", __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printk(KERN_CRIT "FINS: ERROR: %s, %d: "format"\n", __FUNCTION__, __LINE__, ##args);
#else
#define PRINT_ERROR(format, args...)
#endif

// Create one semaphore here for every socketcall that is going to block
//struct semaphore FINS_semaphores[MAX_calls];
struct finssocket wedgeSockets[MAX_sockets];
rwlock_t wedgeSockets_rwlock;
struct semaphore link_sem;

int print_exit(const char *func, int line, int rc) {
#ifdef DEBUG
	printk(KERN_DEBUG "FINS: DEBUG: %s, %d: Exited: %d\n", func, line, rc);
#endif
	return rc;
}

void init_wedgeSockets(void) {
	int i;

	PRINT_DEBUG("Entered.");

	rwlock_init(&wedgeSockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		wedgeSockets[i].uniqueSockID = -1;
		wedgeSockets[i].type = -1;
		wedgeSockets[i].protocol = -1;
	}

	PRINT_DEBUG("Exited.");
}

int insert_wedgeSocket(unsigned long long uniqueSockID, int type, int protocol) {
	int i;
	int j;

	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	write_lock(&wedgeSockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if ((wedgeSockets[i].uniqueSockID == -1)) {
			wedgeSockets[i].uniqueSockID = uniqueSockID;
			wedgeSockets[i].type = type;
			wedgeSockets[i].protocol = protocol;

			for (j = 0; j < MAX_calls; j++) {
				sema_init(&wedgeSockets[i].call_sems[j], 0);
			}

			wedgeSockets[i].release_flag = 0;
			wedgeSockets[i].threads = 0;
			sema_init(&wedgeSockets[i].threads_sem, 1);

			sema_init(&wedgeSockets[i].reply_sem_w, 1);
			sema_init(&wedgeSockets[i].reply_sem_r, 1);
			wedgeSockets[i].reply_call = 0;
			wedgeSockets[i].reply_ret = -1;
			wedgeSockets[i].reply_buf = NULL;
			wedgeSockets[i].reply_len = -1;

			write_unlock(&wedgeSockets_rwlock);
			return print_exit(__FUNCTION__, __LINE__, i);
			//return (i);
		} else if (wedgeSockets[i].uniqueSockID == uniqueSockID) {

			write_unlock(&wedgeSockets_rwlock);
			return print_exit(__FUNCTION__, __LINE__, -1);
			//return (-1);
		}
	}

	write_unlock(&wedgeSockets_rwlock);
	return print_exit(__FUNCTION__, __LINE__, -1);
	//return (-1);
}

int find_wedgeSocket(unsigned long long uniqueSockID) {
	int i;

	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	read_lock(&wedgeSockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if (wedgeSockets[i].uniqueSockID == uniqueSockID) {
			read_unlock(&wedgeSockets_rwlock);
			return print_exit(__FUNCTION__, __LINE__, i);
			//return (i);
		}
	}
	read_unlock(&wedgeSockets_rwlock);
	return print_exit(__FUNCTION__, __LINE__, -1);
	//return (-1);
}

int remove_wedgeSocket(unsigned long long uniqueSockID) {
	int i;
	int j;
	int threads;

	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	write_lock(&wedgeSockets_rwlock);
	for (i = 0; i < MAX_sockets; i++) {
		if (wedgeSockets[i].uniqueSockID == uniqueSockID) {
			wedgeSockets[i].uniqueSockID = -1;
			wedgeSockets[i].type = -1;
			wedgeSockets[i].protocol = -1;

			threads = wedgeSockets[i].threads + 1;
			write_unlock(&wedgeSockets_rwlock);
			PRINT_DEBUG("wedgeSocket[%d] removed.", i);

			PRINT_DEBUG("wedgeSocket[%d].threads=%d", i, threads);
			for (j = 0; j < threads; j++) {
				up(&wedgeSockets[i].reply_sem_w);
				msleep(50); //may need to change
			}
			return (1);
		}
	}
	write_unlock(&wedgeSockets_rwlock);
	return (-1);
}

int threads_incr(int index) {
	int ret;

	if (down_interruptible(&wedgeSockets[index].threads_sem)) {
		PRINT_ERROR("threads aquire fail");
	}
	ret = ++wedgeSockets[index].threads;
	PRINT_DEBUG("wedgeSockets[%d].threads=%d", index, wedgeSockets[index].threads);
	up(&wedgeSockets[index].threads_sem);

	return ret;
}

int threads_decr(int index) {
	int ret;

	if (down_interruptible(&wedgeSockets[index].threads_sem)) {
		PRINT_ERROR("threads aquire fail");
	}
	ret = --wedgeSockets[index].threads;
	PRINT_DEBUG("wedgeSockets[%d].threads=%d", index, wedgeSockets[index].threads);
	up(&wedgeSockets[index].threads_sem);

	return ret;
}

int wait_wedgeSocket(unsigned long long uniqueSockID, int index, u_int calltype) {
	int error = 0;

	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	if (down_interruptible(&wedgeSockets[index].call_sems[calltype])) { // block until daemon replies
		PRINT_ERROR("call aquire fail, throwing error: sem[%d]=%d", calltype, wedgeSockets[index].call_sems[calltype].count);
		error = 1;
	}

	if (down_interruptible(&wedgeSockets[index].reply_sem_r)) {
		PRINT_ERROR("shared aquire fail, r=%d", wedgeSockets[index].reply_sem_r.count);
	}
	if (wedgeSockets[index].uniqueSockID != uniqueSockID) {
		up(&wedgeSockets[index].reply_sem_r);
		PRINT_ERROR("wedgeSocket removed for uniqueSockID=%llu", uniqueSockID);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	threads_decr(index);

	if (error) {
		PRINT_ERROR("wait fail");
		up(&wedgeSockets[index].reply_sem_r);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	return print_exit(__FUNCTION__, __LINE__, index);
}

int checkConfirmation(int index) {
	//exract msg from wedgeSockets[index].reply_buf
	PRINT_DEBUG("shared used: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	if (wedgeSockets[index].reply_buf && (wedgeSockets[index].reply_len == 0)) {
		if (wedgeSockets[index].reply_ret == ACK) {
			PRINT_DEBUG("recv ACK");
			return 0;
		} else if (wedgeSockets[index].reply_ret == NACK) {
			PRINT_DEBUG("recv NACK");
			return -1;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedgeSockets[index].reply_ret);
			return -1;
		}
	} else {
		PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
		return -1;
	}
}

/* FINS Netlink functions  */
/*
 * Sends len bytes from buffer buf to process pid, and sets the flags.
 * If buf is longer than RECV_BUFFER_SIZE, it's broken into sequential messages.
 * Returns 0 if successful or -1 if an error occurred.
 */

//assumes msg_buf is just the msg, does not have a prepended msg_len
//break msg_buf into parts of size RECV_BUFFER_SIZE with a prepended header (header part of RECV...)
//prepend msg header: total msg length, part length, part starting position
int nl_send_msg(int pid, unsigned int seq, int type, void *buf, ssize_t len, int flags) {
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	int ret_val;

//####################
	u_char *print_buf;
	u_char *print_pt;
	u_char *pt;
	int i;

	PRINT_DEBUG("pid=%d, seq=%d, type=%d, len=%d", pid, seq, type, len);

	print_buf = kmalloc(5 * len, GFP_KERNEL);
	if (!print_buf) {
		PRINT_ERROR("print_buf allocation fail");
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
		PRINT_DEBUG("buf='%s'", print_buf);
		kfree(print_buf);
	}
//####################

// Allocate a new netlink message
	skb = nlmsg_new(len, 0); // nlmsg_new(size_t payload, gfp_t flags)
	if (!skb) {
		PRINT_ERROR("netlink Failed to allocate new skb");
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
		PRINT_ERROR("netlink error sending to user");
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
//####################

	if (down_interruptible(&link_sem)) {
		PRINT_ERROR("link_sem aquire fail");
	}

//####################
	print_buf = kmalloc(5 * msg_len, GFP_KERNEL);
	if (!print_buf) {
		PRINT_ERROR("print_buf allocation fail");
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
		PRINT_DEBUG("nl_send: msg_buf='%s'", print_buf);
		kfree(print_buf);
	}
//####################

	part_buf = kmalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
	if (!part_buf) {
		PRINT_ERROR("part_buf allocation fail");
		up(&link_sem);
		return -1;
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
		PRINT_DEBUG("pos=%d", pos);

		*(int *) hdr_pos = pos;

		memcpy(msg_start, msg_pt, part_len);

		PRINT_DEBUG("seq=%d", seq);

		ret = nl_send_msg(pid, seq, 0x0, part_buf, RECV_BUFFER_SIZE, flags/*| NLM_F_MULTI*/);
		if (ret < 0) {
			PRINT_ERROR("netlink error sending seq %d to user", seq);
			up(&link_sem);
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

	ret = nl_send_msg(pid, seq, NLMSG_DONE, part_buf, header_size + part_len, flags);
	if (ret < 0) {
		PRINT_ERROR("netlink error sending seq %d to user", seq);
		up(&link_sem);
		return -1;
	}

	kfree(part_buf);
	up(&link_sem);

	return 0;
}

/*
 * This function is automatically called when the kernel receives a datagram on the corresponding netlink socket.
 */
void nl_data_ready(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	void *buf; // Pointer to data in payload
	u_char *pt;
	ssize_t len; // Payload length
	int pid; // pid of sending process
	unsigned long long uniqueSockID;
	int index;

	u_int reply_call; // a number corresponding to the type of socketcall this packet is in response to

	PRINT_DEBUG("Entered");

	if (skb == NULL) {
		PRINT_DEBUG("skb is NULL \n");
		PRINT_DEBUG("exited");
		return;
	}
	nlh = (struct nlmsghdr *) skb->data;
	pid = nlh->nlmsg_pid; // get pid from the header

// Get a pointer to the start of the data in the buffer and the buffer (payload) length
	buf = NLMSG_DATA(nlh);
	len = NLMSG_PAYLOAD(nlh, 0);

	PRINT_DEBUG("nl_len=%d", len);

// **** Remember the LKM must be up first, then the daemon,
// but the daemon must make contact before any applications try to use socket()

	if (pid == -1) { // if the socket daemon hasn't made contact before
		// Print what we received
		PRINT_DEBUG("Socket Daemon made contact: %s", (char *) buf);
	} else {
		// demultiplex to the appropriate call handler
		pt = buf;

		reply_call = *(u_int *) pt;
		pt += sizeof(u_int);
		len -= sizeof(u_int);

		if (reply_call == daemonconnect_call) {
			FINS_daemon_pid = pid;
			PRINT_DEBUG("Daemon connected, pid=%d\n",FINS_daemon_pid);
		} else if (reply_call < MAX_calls) {
			PRINT_DEBUG("got a daemon reply to a call (%d).", reply_call);
			/*
			 * extract msg or pass to shared buffer
			 * wedgeSockets[index].reply_call & shared_sockID, are to verify buf goes to the write sock & call
			 * This is preemptive as with multithreading we may have to add a shared queue
			 */

			uniqueSockID = *(unsigned long long *) pt;
			pt += sizeof(unsigned long long);

			PRINT_DEBUG("reply for uniqueSockID=%llu call=%d", uniqueSockID, reply_call);

			index = find_wedgeSocket(uniqueSockID);
			PRINT_DEBUG("index=%d", index);
			if (index == -1) {
				PRINT_ERROR("socket not found for uniqueSockID=%llu", uniqueSockID);
				goto end;
			}

			if (wedgeSockets[index].release_flag && (reply_call != release_call)) { //TODO: may be unnecessary & can be removed (flag, etc)
				PRINT_DEBUG("socket released, dropping for uniqueSockID=%llu call=%d", uniqueSockID, reply_call);
				goto end;
			}

			//lock the semaphore so shared data can't be changed until it's consumed
			PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);
			if (down_interruptible(&wedgeSockets[index].reply_sem_w)) {
				PRINT_ERROR("shared aquire fail, using hard down w=%d", wedgeSockets[index].reply_sem_w.count);
			}

			PRINT_DEBUG("wedgeSockets[%d].reply_sem_r=%d", index, wedgeSockets[index].reply_sem_r.count);
			if (down_interruptible(&wedgeSockets[index].reply_sem_r)) {
				PRINT_ERROR("shared aquire fail, using hard down r=%d", wedgeSockets[index].reply_sem_r.count);
			}

			if (wedgeSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_ERROR("wedgeSocket removed for uniqueSockID=%llu", uniqueSockID);
				up(&wedgeSockets[index].reply_sem_r);
				goto end;
			}

			write_lock(&wedgeSockets_rwlock);

			wedgeSockets[index].reply_call = reply_call;

			wedgeSockets[index].reply_ret = *(u_int *) pt; //NACK or ACK
			pt += sizeof(u_int);

			wedgeSockets[index].reply_msg = *(u_int *) pt; //return msg or error code
			pt += sizeof(u_int);

			wedgeSockets[index].reply_buf = pt;

			len -= sizeof(unsigned long long) + 2 * sizeof(u_int);
			wedgeSockets[index].reply_len = len;

			write_unlock(&wedgeSockets_rwlock);
			PRINT_DEBUG("shared created: call=%d, sockID=%llu, ret=%d, msg=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_msg, wedgeSockets[index].reply_len);
			up(&wedgeSockets[index].reply_sem_r);

			up(&wedgeSockets[index].call_sems[reply_call]);
		} else {
			PRINT_DEBUG("got an unsupported/binding daemon reply (%d)", reply_call);
		}
	}

	end:
	PRINT_DEBUG("exited");
}

/* This function is called from within FINS_release and is modeled after ipx_destroy_socket() */
static void FINS_destroy_socket(struct sock *sk) {
	PRINT_DEBUG("called.");
	skb_queue_purge(&sk->sk_receive_queue);
	sk_refcnt_debug_dec(sk);
}

/* Wedge core functions (Protocol Registration) */
/*
 * This function tests whether the FINS data passthrough has been enabled or if the original stack is to be used
 * and passes data through appropriately.  This function is called when socket() call is made from userspace 
 * (specified in struct net_proto_family FINS_net_proto) 
 */
static int FINS_wedge_create_socket(struct net *net, struct socket *sock, int protocol, int kern) {
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
static int FINS_create_socket(struct net *net, struct socket *sock, int protocol, int kern) {
	int rc = -ESOCKTNOSUPPORT;
	unsigned long long uniqueSockID;
	struct sock *sk;
	int index;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	PRINT_DEBUG("Entered");

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Required stuff for kernel side
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_FINS, GFP_KERNEL, &FINS_proto);

	if (!sk) {
		PRINT_ERROR("allocation failed");
		return print_exit(__FUNCTION__, __LINE__, rc);
		// if allocation failed
	}
	sk_refcnt_debug_inc(sk);
	sock_init_data(sock, sk);

	sk->sk_no_check = 1;
	sock->ops = &FINS_proto_ops;

	uniqueSockID = getUniqueSockID(sock);

	index = insert_wedgeSocket(uniqueSockID, sock->type, protocol);
	PRINT_DEBUG("insert index=%d", index);
	if (index == -1) {
		goto removeSocket;
	}

// Build the message
	buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		goto removeSocket;
	}
	pt = buf;

	*(u_int *) pt = socket_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = AF_FINS; //~2, since this overrides AF_INET (39)
	pt += sizeof(int);

	*(u_int *) pt = sock->type;
	pt += sizeof(u_int);

	*(int *) pt = protocol;
	pt += sizeof(int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		goto removeSocket;
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", socket_call, uniqueSockID, buf_len);
// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed\n");
		goto removeSocket;
	}

	index = wait_wedgeSocket(uniqueSockID, index, socket_call);
	PRINT_DEBUG("after index=%d", index);
	if (index == -1) {
		goto removeSocket;
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	if (rc != 0) {
		removeSocket: ret = remove_wedgeSocket(uniqueSockID);

		if (sk) {
			lock_sock(sk);
			if (!sock_flag(sk, SOCK_DEAD))
				sk->sk_state_change(sk);

			sock_set_flag(sk, SOCK_DEAD);
			sock->sk = NULL;
			sk_refcnt_debug_release(sk);
			FINS_destroy_socket(sk);
			sock_put(sk);
		}
	}

	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;
	struct sock *sk = sock->sk;

	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);
	PRINT_DEBUG("addr_len=%d.", addr_len);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = bind_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	*(u_int *) pt = sk->sk_reuse;
	pt += sizeof(u_int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", bind_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, bind_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_listen(struct socket *sock, int backlog) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;
	struct sock *sk = sock->sk;

	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = listen_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = backlog;
	pt += sizeof(int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", listen_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, listen_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	struct sock *sk = sock->sk;
	//lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);
	PRINT_DEBUG("addr_len=%d", addr_len);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int) + addr_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = connect_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, addr, addr_len);
	pt += addr_len;

	*(int *) pt = flags;
	pt += sizeof(int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", connect_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, connect_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	//release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_accept(struct socket *sock, struct socket *newsock, int flags) {
//accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	int rc = -ESOCKTNOSUPPORT;
	unsigned long long uniqueSockID, uniqueSockID_new;
	struct sock *sk_new;
	int index, index_new;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;

	struct sock *sk = sock->sk;
	//lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Required stuff for kernel side
	rc = -ENOMEM;
	sk_new = sk_alloc(sock_net(sock->sk), PF_FINS, GFP_KERNEL, &FINS_proto);

	if (!sk_new) {
		PRINT_ERROR("allocation failed");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, rc);
		// if allocation failed
	}
	sk_refcnt_debug_inc(sk_new);
	sock_init_data(newsock, sk_new);

	sk_new->sk_no_check = 1;
	newsock->ops = &FINS_proto_ops;

	uniqueSockID_new = getUniqueSockID(newsock);
	PRINT_DEBUG("Entered for new=%llu", uniqueSockID_new);

// Build the message
	buf_len = 2 * sizeof(u_int) + 2 * sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = accept_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID_new;
	pt += sizeof(unsigned long long);

	*(int *) pt = flags;
	pt += sizeof(int);

//sock->type //need?

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", listen_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, accept_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	if (rc == 0) {
		index_new = insert_wedgeSocket(uniqueSockID_new, newsock->type, wedgeSockets[index].protocol);
		PRINT_DEBUG("insert index_new=%d", index_new);
		if (index == -1) {
			rc = -1;
		}
	}

	if (rc != 0) {
		if (sk_new) {
			lock_sock(sk_new);
			if (!sock_flag(sk_new, SOCK_DEAD))
				sk->sk_state_change(sk_new);

			sock_set_flag(sk_new, SOCK_DEAD);
			newsock->sk = NULL;
			sk_refcnt_debug_release(sk_new);
			FINS_destroy_socket(sk_new);
			sock_put(sk_new);
		}
	}

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_getname(struct socket *sock, struct sockaddr *addr, int *len, int peer) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	struct sockaddr_in *addr_in;

	struct sock *sk = sock->sk;
	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = getname_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = peer;
	pt += sizeof(int);

//todo: finish, copy addr/len?

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", getname_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, getname_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	if (wedgeSockets[index].reply_buf && (wedgeSockets[index].reply_len >= sizeof(int))) {
		pt = wedgeSockets[index].reply_buf;

		if (wedgeSockets[index].reply_ret == ACK) {
			PRINT_DEBUG("recv ACK");

			//TODO: find out if this is right! udpHandling writes sockaddr_in here
			ret = *(int *) pt;
			pt += sizeof(int);

			if (peer == ret) {
				*len = sizeof(struct sockaddr);

				PRINT_DEBUG("len=%d", *len);
				memset(addr, 0, sizeof(struct sockaddr));
				memcpy(addr, pt, sizeof(struct sockaddr));
				pt += sizeof(struct sockaddr);

				//########
				addr_in = (struct sockaddr_in *) addr;
				//addr_in->sin_port = ntohs(4000); //causes end port to be 4000
				PRINT_DEBUG("address: %u/%d", (addr_in->sin_addr).s_addr, ntohs(addr_in->sin_port));
				//########

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
				rc = 0;
			} else {
				PRINT_DEBUG("different peer value=%d", ret);
				rc = -1;
			}
		} else if (wedgeSockets[index].reply_ret == NACK) {
			PRINT_DEBUG("recv NACK");
			rc = -1;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedgeSockets[index].reply_ret);
			rc = -1;
		}
	} else {
		PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
		rc = -1;
	}
	PRINT_DEBUG("shared used: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len) {
	int rc;
	unsigned long long uniqueSockID;
	int controlFlag = 0;
	int i = 0;
	u_int data_len = 0;
	int symbol = 1; //default value unless passes address equal NULL //TODO remove?

	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;
	char *temp;

	struct sock *sk = sock->sk;
	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	if (msg->msg_controllen != 0)
		controlFlag = 1;

	for (i = 0; i < (msg->msg_iovlen); i++) {
		data_len += msg->msg_iov[i].iov_len;
	}

	if (msg->msg_name == NULL)
		symbol = 0;

// Build the message
	buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + 3 * sizeof(int) + (symbol ? sizeof(u_int) + msg->msg_namelen : 0)
			+ (controlFlag ? sizeof(u_int) + msg->msg_controllen : 0) + data_len;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buf allocation failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = sendmsg_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = symbol;
	pt += sizeof(int);

	if (symbol) {
		*(u_int *) pt = msg->msg_namelen; //socklen_t is of type u_int
		pt += sizeof(u_int);

		memcpy(pt, msg->msg_name, msg->msg_namelen);
		pt += msg->msg_namelen;
	}

	*(int *) pt = msg->msg_flags; //stores sendmsg call flags
	pt += sizeof(int);

	*(int *) pt = controlFlag;
	pt += sizeof(int);

	if (controlFlag) {
		*(u_int *) pt = msg->msg_controllen;
		pt += sizeof(u_int);

		memcpy(pt, msg->msg_control, msg->msg_controllen);
		pt += msg->msg_controllen;
	}
//Notice that the compiler takes  (msg->msg_iov[i]) as a struct not a pointer to struct

	*(u_int *) pt = data_len;
	pt += sizeof(u_int);

	temp = pt;

	i = 0;
	for (i = 0; i < msg->msg_iovlen; i++) {
		memcpy(pt, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		pt += msg->msg_iov[i].iov_len;
		//PRINT_DEBUG("current element %d , element length = %d", i ,(msg->msg_iov[i]).iov_len );
	}

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("data_len=%d", data_len);
	PRINT_DEBUG("data='%s'", temp);

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", sendmsg_call, uniqueSockID, buf_len);
// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
		// pick an appropriate errno
	}

	index = wait_wedgeSocket(uniqueSockID, index, sendmsg_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	if (rc == 0) {
		rc = data_len;
	}
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t len, int flags) {
	int rc;
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

	struct sock *sk = sock->sk;
	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	if ((msg->msg_controllen != 0) && msg->msg_control)
		controlFlag = 1;
	if (msg->msg_name == NULL)
		symbol = 0;

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(ssize_t) + 4 * sizeof(int) + (controlFlag ? sizeof(u_int) + msg->msg_controllen : 0);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buf allocation failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = recvmsg_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(ssize_t *) pt = len;
	pt += sizeof(ssize_t);

	*(int *) pt = flags;
	pt += sizeof(int);

	*(int *) pt = symbol;
	pt += sizeof(int);

	*(int *) pt = msg->msg_flags;
	pt += sizeof(int);

	*(int *) pt = controlFlag;
	pt += sizeof(int);

	if (controlFlag) {
		*(u_int *) pt = msg->msg_controllen;
		pt += sizeof(u_int);

		memcpy(pt, msg->msg_control, msg->msg_controllen);
		pt += msg->msg_controllen;
	}

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", recvmsg_call, uniqueSockID, buf_len);
// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
		// pick an appropriate errno
	}

	index = wait_wedgeSocket(uniqueSockID, index, recvmsg_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	if (wedgeSockets[index].reply_buf && (wedgeSockets[index].reply_len >= 0)) {
		pt = wedgeSockets[index].reply_buf;

		if (wedgeSockets[index].reply_ret == ACK) {
			PRINT_DEBUG("recv ACK");

			if (symbol == 1) {
				//TODO: find out if this is right! udpHandling writes sockaddr_in here
				msg->msg_namelen = sizeof(struct sockaddr_in);
				memcpy(msg->msg_name, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//########
				addr_in = (struct sockaddr_in *) msg->msg_name;
				//addr_in->sin_port = ntohs(4000); //causes end port to be 4000
				PRINT_DEBUG("address: %d/%d", (addr_in->sin_addr).s_addr, ntohs(addr_in->sin_port));
				//########

			} else if (symbol) {
				PRINT_ERROR("symbol error, symbol=%d", symbol); //will remove
				rc = -1;
			}

			buf_len = *(int *) pt; //reuse var since not needed anymore
			pt += sizeof(int);

			if (buf_len >= 0) {
				u_char *temp = (u_char *) kmalloc(buf_len + 1, GFP_KERNEL);
				memcpy(temp, pt, buf_len);
				temp[buf_len] = '\0';
				PRINT_DEBUG("msg='%s'", temp);

				ret = buf_len; //reuse as counter
				i = 0;
				while (ret > 0 && i < msg->msg_iovlen) {
					if (ret > msg->msg_iov[i].iov_len) {
						copy_to_user(msg->msg_iov[i].iov_base, pt, msg->msg_iov[i].iov_len);
						pt += msg->msg_iov[i].iov_len;
						ret -= msg->msg_iov[i].iov_len;
						i++;
					} else {
						copy_to_user(msg->msg_iov[i].iov_base, pt, ret);
						pt += ret;
						ret = 0;
						break;
					}
				}
				if (ret) {
					//throw buffer overflow error?
					PRINT_ERROR("user buffer overflow error, overflow=%d", ret);
				}
				rc = buf_len;
			} else {
				PRINT_ERROR("iov_base alloc failure");
				rc = -1;
			}

			if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
				PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
				rc = -1;
			}
		} else if (wedgeSockets[index].reply_ret == NACK) {
			PRINT_DEBUG("recv NACK");
			rc = -1;
		} else {
			PRINT_ERROR("error, acknowledgement: %d", wedgeSockets[index].reply_ret);
			rc = -1;
		}
	} else {
		PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
		rc = -1;
	}
	PRINT_DEBUG("shared used: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg) {
	int rc = 0;
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;
	int index;

	struct ifconf ifc;
	struct ifreq ifr;
	struct ifreq *ifr_pt;

	void __user
	*arg_pt = (void __user *)arg;

	int len;
	char __user
	*pos;

	//char *name;
	struct sockaddr_in *addr;

	//http://lxr.linux.no/linux+v2.6.39.4/net/core/dev.c#L4905 - ioctl

	struct sock *sk = sock->sk;
	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	switch (cmd) {
	case SIOCGIFCONF:
		PRINT_DEBUG("cmd=%d ==SIOCGIFCONF", cmd);

		if (copy_from_user(&ifc, arg_pt, sizeof(struct ifconf))) {
			PRINT_ERROR("ERROR: cmd=%d ==SIOCGIFDSTADDR", cmd);
			//TODO error
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}

		pos = ifc.ifc_buf;
		if (ifc.ifc_buf == NULL) {
			len = 0;
		} else {
			len = ifc.ifc_len;
		}
		ifr_pt = ifc.ifc_req; //TODO figure out what this is used for

		PRINT_DEBUG("len=%d, pos=%d, ifr=%d", len, (int)pos, (int)ifr_pt);

		// Build the message
		buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf) {
			PRINT_ERROR("buffer allocation error");
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		pt = buf;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = threads_incr(index);
		pt += sizeof(u_int);

		*(u_int *) pt = cmd;
		pt += sizeof(u_int);

		*(int *) pt = len;
		pt += sizeof(int);

		if (pt - (u_char *) buf != buf_len) {
			PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
			kfree(buf);
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		break;
	case SIOCGIFADDR:
	case SIOCGIFDSTADDR:
	case SIOCGIFBRDADDR:
	case SIOCGIFNETMASK:
		if (copy_from_user(&ifr, arg_pt, sizeof(struct ifreq))) {
			PRINT_ERROR("ERROR: cmd=%d ==SIOCGIFDSTADDR", cmd);
			//TODO error
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}

		PRINT_DEBUG("cmd=%d name='%s'", cmd, ifr.ifr_name);

		// Build the message
		buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + IFNAMSIZ;
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf) {
			PRINT_ERROR("buffer allocation error");
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		pt = buf;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = threads_incr(index);
		pt += sizeof(u_int);

		*(u_int *) pt = cmd;
		pt += sizeof(u_int);

		*(int *) pt = IFNAMSIZ;
		pt += sizeof(int);

		memcpy(pt, ifr.ifr_name, IFNAMSIZ);
		pt += IFNAMSIZ;

		if (pt - (u_char *) buf != buf_len) {
			PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
			kfree(buf);
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		break;
	case FIONREAD:
		PRINT_DEBUG("cmd=FIONREAD");

		// Build the message
		buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long);
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf) {
			PRINT_ERROR("buffer allocation error");
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		pt = buf;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = threads_incr(index);
		pt += sizeof(u_int);

		*(u_int *) pt = cmd;
		pt += sizeof(u_int);

		if (pt - (u_char *) buf != buf_len) {
			PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
			kfree(buf);
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		break;
	case TIOCOUTQ:
		//case TIOCINQ: //equiv to FIONREAD??
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCSIFADDR:
	case SIOCAIPXITFCRT:
	case SIOCAIPXPRISLT:
	case SIOCIPXCFGDATA:
	case SIOCIPXNCPCONN:
	case SIOCGSTAMP:
	case SIOCSIFDSTADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
		//TODO implement
		PRINT_DEBUG("cmd=%d not implemented", cmd);
		buf_len = 3 * sizeof(u_int) + sizeof(unsigned long long);
		buf = kmalloc(buf_len, GFP_KERNEL);
		if (!buf) {
			PRINT_ERROR("buffer allocation error");
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		pt = buf;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = threads_incr(index);
		pt += sizeof(u_int);

		*(u_int *) pt = cmd;
		pt += sizeof(u_int);

		if (pt - (u_char *) buf != buf_len) {
			PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
			kfree(buf);
			release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}
		break;
	default:
		PRINT_DEBUG("cmd=%d default", cmd);
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", ioctl_call, uniqueSockID, buf_len);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, ioctl_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	if (wedgeSockets[index].reply_ret == ACK) {
		PRINT_DEBUG("ioctl ACK");
		switch (cmd) {
		case SIOCGIFCONF:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len >= sizeof(int)) {
				//values stored in ifr.ifr_addr
				pt = wedgeSockets[index].reply_buf;

				len = *(int *) pt;
				pt += sizeof(int);

				PRINT_DEBUG("SIOCGIFCONF len=%d ifc_len=%d", len, ifc.ifc_len);
				ifc.ifc_len = len;
				PRINT_DEBUG("SIOCGIFCONF len=%d ifc_len=%d", len, ifc.ifc_len);

				if (copy_to_user(ifc.ifc_buf, pt, len)) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}
				pt += len;

				//len = ifc.ifc_len;
				//pos = ifc.ifc_buf;
				//ifr_pt = ifc.ifc_req;

				if (copy_to_user(arg_pt, &ifc, sizeof(struct ifconf))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			//rc = -1;
			break;
		case SIOCGIFADDR:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len == sizeof(struct sockaddr_in)) {
				pt = wedgeSockets[index].reply_buf;

				memcpy(&ifr.ifr_addr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_addr;
				//memcpy(addr, pt, sizeof(struct sockaddr));
				PRINT_DEBUG("name=%s, addr=%d (%d/%d)", ifr.ifr_name, (int)addr, addr->sin_addr.s_addr, addr->sin_port);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
		case SIOCGIFDSTADDR:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len == sizeof(struct sockaddr_in)) {
				pt = wedgeSockets[index].reply_buf;

				memcpy(&ifr.ifr_dstaddr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_dstaddr;
				PRINT_DEBUG("name=%s, addr=%d (%d/%d)", ifr.ifr_name, (int)addr, addr->sin_addr.s_addr, addr->sin_port);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
		case SIOCGIFBRDADDR:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len == sizeof(struct sockaddr_in)) {
				pt = wedgeSockets[index].reply_buf;

				memcpy(&ifr.ifr_broadaddr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_broadaddr;
				PRINT_DEBUG("name=%s, addr=%d (%d/%d)", ifr.ifr_name, (int)addr, addr->sin_addr.s_addr, addr->sin_port);
				//#################

				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
		case SIOCGIFNETMASK:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len == sizeof(struct sockaddr_in)) {
				pt = wedgeSockets[index].reply_buf;

				memcpy(&ifr.ifr_addr, pt, sizeof(struct sockaddr_in));
				pt += sizeof(struct sockaddr_in);

				//#################
				addr = (struct sockaddr_in *) &ifr.ifr_addr;
				PRINT_DEBUG("name=%s, addr=%d (%d/%d)", ifr.ifr_name, (int)addr, addr->sin_addr.s_addr, addr->sin_port);
				//#################
				if (copy_to_user(arg_pt, &ifr, sizeof(struct ifreq))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}

			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
		case FIONREAD:
			if (wedgeSockets[index].reply_buf && wedgeSockets[index].reply_len == sizeof(int)) {
				pt = wedgeSockets[index].reply_buf;

				len = *(int *) pt;
				pt += sizeof(int);

				//#################
				PRINT_DEBUG("len=%d", len);
				//#################

				if (copy_to_user(arg_pt, &len, sizeof(int))) {
					PRINT_ERROR("ERROR: cmd=%d", cmd);
					//TODO error
					rc = -1;
				}

				if (pt - wedgeSockets[index].reply_buf != wedgeSockets[index].reply_len) {
					PRINT_ERROR("READING ERROR! diff=%d len=%d", pt - wedgeSockets[index].reply_buf, wedgeSockets[index].reply_len);
					rc = -1;
				}
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
			//-----------------------------------
		case TIOCOUTQ:
			//case TIOCINQ: //equiv to FIONREAD??
		case SIOCADDRT:
		case SIOCDELRT:
		case SIOCSIFADDR:
		case SIOCAIPXITFCRT:
		case SIOCAIPXPRISLT:
		case SIOCIPXCFGDATA:
		case SIOCIPXNCPCONN:
		case SIOCGSTAMP:
		case SIOCSIFDSTADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
			//TODO implement cases above
			if (wedgeSockets[index].reply_buf && (wedgeSockets[index].reply_len == 0)) {
			} else {
				PRINT_ERROR("wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p", wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
				rc = -1;
			}
			break;
		default:
			PRINT_DEBUG("cmd=%d default", cmd);
			rc = -1;
			break;
		}
	} else if (wedgeSockets[index].reply_ret == NACK) {
		PRINT_DEBUG("ioctl NACK");
		rc = -1;
	} else {
		PRINT_ERROR("error, acknowledgement: %d", wedgeSockets[index].reply_ret);
		rc = -1;
	}
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	release_sock(sk);
	return print_exit(__FUNCTION__, __LINE__, rc);
}

/*
 * This function is called automatically to cleanup when a program that 
 * created a socket terminates.
 * Or manually via close()?????
 * Modeled after ipx_release().
 */
static int FINS_release(struct socket *sock) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len; // used for test
	void *buf; // used for test
	u_char *pt;
	int ret;
	int index;

	struct sock *sk = sock->sk;
	//lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = release_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", release_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	wedgeSockets[index].release_flag = 1;

	index = wait_wedgeSocket(uniqueSockID, index, release_call);
	PRINT_DEBUG("after index=%d", index);
	if (index == -1) {
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	ret = remove_wedgeSocket(uniqueSockID);
	if (ret == -1) {
		PRINT_ERROR("removewedgeSocket fail");
		//release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	if (!sk) {
		PRINT_ERROR("sk null");
		return print_exit(__FUNCTION__, __LINE__, rc);
	}

	PRINT_DEBUG("FINS_release -- sk was set.");

	lock_sock(sk);
	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_state_change(sk);
	}

	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	FINS_destroy_socket(sk);
	sock_put(sk);

	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_socketpair(struct socket *sock1, struct socket *sock2) {
	unsigned long long uniqueSockID1, uniqueSockID2;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	uniqueSockID1 = getUniqueSockID(sock1);
	uniqueSockID2 = getUniqueSockID(sock2);

	PRINT_DEBUG("Entered for %llu, %llu.", uniqueSockID1, uniqueSockID2);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

//TODO: finish this & daemon side

// Build the message
	buf = "FINS_socketpair() called.";
	buffer_length = strlen(buf) + 1;

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	return 0;
}

static unsigned int FINS_poll(struct file *file, struct socket *sock, poll_table *pt) {
	unsigned long long uniqueSockID;
	int ret;
	char *buf; // used for test
	ssize_t buffer_length; // used for test

	struct sock *sk = sock->sk;
	lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

	// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	//TODO: finish this & daemon side

	// Build the message
	buf = "FINS_poll() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	release_sock(sk);
	return 0;
}

//TODO figure out when this is called
static int FINS_shutdown(struct socket *sock, int how) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
	if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

// Build the message
	buf_len = 2 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *) pt = shutdown_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *) pt = how;
	pt += sizeof(int);

	if (pt - (u_char *) buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
		kfree(buf);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", shutdown_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, shutdown_call);
	PRINT_DEBUG("index=%d", index);
	if (index == -1) {
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

	rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG("shared consumed: call=%d, sockID=%llu, ret=%d, len=%d", wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
	wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

	return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int index;

	struct sock *sk = sock->sk;
		lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
		PRINT_ERROR("daemon not connected");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
if (index == -1) {
	release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	// Build the message
	buf_len = 3*sizeof(u_int) + sizeof(unsigned long long) + 2*sizeof(int) + optlen;
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *)pt = setsockopt_call;
	pt += sizeof(u_int);

	*(unsigned long long *)pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

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
		release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	if (pt - (u_char *)buf != buf_len) {
		PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
kfree(buf);
release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", setsockopt_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
	kfree(buf);
	if (ret) {
		PRINT_ERROR("nl_send failed");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = wait_wedgeSocket(uniqueSockID, index, setsockopt_call);
	PRINT_DEBUG("index=%d", index);
if (index == -1) {
	release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	PRINT_DEBUG("relocked my semaphore");

rc = checkConfirmation(index);
	up(&wedgeSockets[index].reply_sem_r);

	PRINT_DEBUG( "shared consumed: call=%d, sockID=%llu, ret=%d, len=%d",
		wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
wedgeSockets[index].reply_call = 0;
	up(&wedgeSockets[index].reply_sem_w);
	PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen) {
	int rc;
	unsigned long long uniqueSockID;
	ssize_t buf_len;
	void *buf;
	u_char *pt;
	int ret;
	int len;
	int index;

	struct sock *sk = sock->sk;
			lock_sock(sk);

	uniqueSockID = getUniqueSockID(sock);
	PRINT_DEBUG("Entered for %llu.", uniqueSockID);

//SO_REUSEADDR
//SO_ERROR
//SO_PRIORITY
//SO_SNDBUF
//SO_RCVBUF

// Notify FINS daemon
if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
			PRINT_ERROR("daemon not connected");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}

	index = find_wedgeSocket(uniqueSockID);
	PRINT_DEBUG("index=%d", index);
if (index == -1) {
	release_sock(sk);
		return print_exit(__FUNCTION__, __LINE__, -1);
	}

	ret = copy_from_user(&len, optlen, sizeof(int));
	if (ret) {
		PRINT_ERROR("copy_from_user fail ret=%d", ret);
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}
	PRINT_DEBUG("len=%d", len);

// Build the message
buf_len = 2*sizeof(u_int) + sizeof(unsigned long long) + 3*sizeof(int) + (len>0?len:0);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf) {
		PRINT_ERROR("buffer allocation error");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
	}
	pt = buf;

	*(u_int *)pt = getsockopt_call;
	pt += sizeof(u_int);

	*(unsigned long long *)pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = threads_incr(index);
	pt += sizeof(u_int);

	*(int *)pt = level;
	pt += sizeof(int);

	*(int *)pt = optname;
	pt += sizeof(int);

	*(int *)pt = len;
	pt += sizeof(int);

	if (len > 0) { //TODO prob don't need
		ret = copy_from_user(pt, optval, len);
		pt += len;
		if (ret) {
			PRINT_ERROR("copy_from_user fail ret=%d", ret);
kfree(buf);
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
		}
	}

		if (pt - (u_char *)buf != buf_len) {
			PRINT_ERROR("write error: diff=%d len=%d", pt-(u_char *)buf, buf_len);
kfree(buf);
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
		}

		PRINT_DEBUG("socket_call=%d uniqueSockID=%llu buf_len=%d", getsockopt_call, uniqueSockID, buf_len);

// Send message to FINS_daemon
ret = nl_send(FINS_daemon_pid, buf, buf_len, 0);
		kfree(buf);
		if (ret) {
			PRINT_ERROR("nl_send failed");
release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, -1);
		}

		index = wait_wedgeSocket(uniqueSockID, index, getsockopt_call);
		PRINT_DEBUG("index=%d", index);
if (index == -1) {
	release_sock(sk);
			return print_exit(__FUNCTION__, __LINE__, -1);
		}

		PRINT_DEBUG("relocked my semaphore");

//exract msg from wedgeSockets[index].reply_buf
if (wedgeSockets[index].reply_buf && (wedgeSockets[index].reply_len >= sizeof(int))) {
			if (wedgeSockets[index].reply_ret == ACK) {
				PRINT_DEBUG("recv ACK");
pt = wedgeSockets[index].reply_buf;
				rc = 0;

				//re-using len var
				len = *(int *)pt;
				pt += sizeof(int);
				ret = copy_to_user(optlen, &len, sizeof(int));
				if (ret) {
					PRINT_ERROR("copy_from_user fail ret=%d", ret);
rc = -1;
				}

				if (len > 0) {
					ret = copy_to_user(optval, pt, len);
					if (ret) {
						PRINT_ERROR("copy_from_user fail ret=%d", ret);
rc = -1;
					}
				}
			} else if (wedgeSockets[index].reply_ret == NACK) {
				PRINT_DEBUG("recv NACK");
rc = -1;
			} else {
				PRINT_ERROR("error, acknowledgement: %d", wedgeSockets[index].reply_ret);
rc = -1;
			}
		} else {
			PRINT_ERROR( "wedgeSockets[index].reply_buf error, wedgeSockets[index].reply_len=%d wedgeSockets[index].reply_buf=%p",
		wedgeSockets[index].reply_len, wedgeSockets[index].reply_buf);
rc = -1;
		}
		PRINT_DEBUG( "shared used: call=%d, sockID=%llu, ret=%d, len=%d",
		wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
up(&wedgeSockets[index].reply_sem_r);

		PRINT_DEBUG( "shared consumed: call=%d, sockID=%llu, ret=%d, len=%d",
		wedgeSockets[index].reply_call, wedgeSockets[index].uniqueSockID, wedgeSockets[index].reply_ret, wedgeSockets[index].reply_len);
wedgeSockets[index].reply_call = 0;
		up(&wedgeSockets[index].reply_sem_w);
		PRINT_DEBUG("wedgeSockets[%d].reply_sem_w=%d", index, wedgeSockets[index].reply_sem_w.count);

release_sock(sk);
return print_exit(__FUNCTION__, __LINE__, rc);
}

static int FINS_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma) {
unsigned long long uniqueSockID;
int index;
int ret;
char *buf; // used for test
ssize_t buffer_length; // used for test

uniqueSockID = getUniqueSockID(sock);
PRINT_DEBUG("Entered for %llu.", uniqueSockID);

// Notify FINS daemon
if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
	PRINT_ERROR("daemon not connected");
	return print_exit(__FUNCTION__, __LINE__, -1);
}

index = find_wedgeSocket(uniqueSockID);
PRINT_DEBUG("index=%d", index);
if (index == -1) {
	return print_exit(__FUNCTION__, __LINE__, -1);
}

//TODO: finish this & daemon side

// Build the message
buf = "FINS_mmap() called.";
buffer_length = strlen(buf) + 1;

// Send message to FINS_daemon
ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
if (ret) {
	PRINT_ERROR("nl_send failed");
	return print_exit(__FUNCTION__, __LINE__, -1);
}

/* Mirror missing mmap method error code */
return -ENODEV;
}

static ssize_t FINS_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags) {
unsigned long long uniqueSockID;
int ret;
char *buf; // used for test
ssize_t buffer_length; // used for test

uniqueSockID = getUniqueSockID(sock);
PRINT_DEBUG("Entered for %llu.", uniqueSockID);

//TODO: finish this & daemon side

// Notify FINS daemon
if (FINS_daemon_pid == -1) { // FINS daemon has not made contact yet, no idea where to send message
	PRINT_ERROR("daemon not connected");
	return print_exit(__FUNCTION__, __LINE__, -1);
}

// Build the message
buf = "FINS_sendpage() called.";
buffer_length = strlen(buf) + 1;

// Send message to FINS_daemon
ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
if (ret) {
	PRINT_ERROR("nl_send failed");
	return print_exit(__FUNCTION__, __LINE__, -1);
}

/* See sock_no_sendpage() in /net/core/sock.c for more information of what maybe should go here? */
return 0;
}

/* Data structures needed for protocol registration */
/* A proto struct for the dummy protocol */
static struct proto FINS_proto = { .name = "FINS_PROTO", .owner = THIS_MODULE, .obj_size = sizeof(struct FINS_sock), };

/* see IPX struct net_proto_family ipx_family_ops for comparison */
static struct net_proto_family FINS_net_proto = { .family = PF_FINS, .create = FINS_wedge_create_socket, // This function gets called when socket() is called from userspace
	.owner = THIS_MODULE, };

/* Defines which functions get called when corresponding calls are made from userspace */
static struct proto_ops FINS_proto_ops = { .owner = THIS_MODULE, .family = PF_FINS, .release = FINS_release, .bind = FINS_bind, //sock_no_bind,
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
PRINT_DEBUG("proto_register returned: %d", rc);
PRINT_DEBUG("Made it through FINS proto_register()");

/* Call sock_register to register the handler with the socket layer */
rc = sock_register(&FINS_net_proto);
PRINT_DEBUG("sock_register returned: %d", rc);
PRINT_DEBUG("Made it through FINS sock_register()");
}

static void teardown_FINS_protocol(void) {
/* Call sock_unregister to unregister the handler with the socket layer */
sock_unregister(FINS_net_proto.family);
PRINT_DEBUG("Made it through FINS sock_unregister()");

/* Call proto_unregister and report debugging info */
proto_unregister(&FINS_proto);
PRINT_DEBUG("Made it through FINS proto_unregister()");
}

/* Functions to initialize and teardown the netlink socket */
static int setup_FINS_netlink(void) {
// nl_data_ready is the name of the function to be called when the kernel receives a datagram on this netlink socket.
FINS_nl_sk = netlink_kernel_create(&init_net, NETLINK_FINS, 0, nl_data_ready, NULL, THIS_MODULE);
if (!FINS_nl_sk) {
	PRINT_ERROR("Error creating socket.");
	return -10;
}

sema_init(&link_sem, 1);

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
	PRINT_DEBUG("############################################");
PRINT_DEBUG("Loading the FINS_stack_wedge module");
setup_FINS_protocol();
	setup_FINS_netlink();
	init_wedgeSockets();
	PRINT_DEBUG("Made it through the FINS_stack_wedge initialization");
return 0;
}

static void __exit FINS_stack_wedge_exit(void) {
	PRINT_DEBUG("Unloading the FINS_stack_wedge module");
teardown_FINS_netlink();
	teardown_FINS_protocol();
	PRINT_DEBUG("Made it through the FINS_stack_wedge removal");
// the system call wrapped by rmmod frees all memory that is allocated in the module
}

/* Macros defining the init and exit functions */
module_init( FINS_stack_wedge_init);
module_exit( FINS_stack_wedge_exit);

/* Set the license and signing info for the module */
MODULE_LICENSE(M_LICENSE);
MODULE_DESCRIPTION(M_DESCRIPTION);
MODULE_AUTHOR(M_AUTHOR);
