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

#include "FINS_stack_wedge.h"	/* Defs for this module */


// Create one semaphore here for every socketcall that is going to block
struct semaphore FINS_socket_sem;
struct semaphore FINS_bind_sem;
struct semaphore FINS_recvmsg_sem;

/* Wedge core functions (Protocol Registration) */
/*
 * This function tests whether the FINS data passthrough has been enabled or if the original stack is to be used
 * and passes data through appropriately.  This function is called when socket() call is made from userspace 
 * (specified in struct net_proto_family FINS_net_proto) 
 */
static int FINS_wedge_create_socket(struct net *net, struct socket *sock, int protocol, int kern){
	if(FINS_stack_passthrough_enabled == 1){
		return FINS_create_socket(net, sock, protocol, kern);
	}
	else{	// Use original inet stack
	//	return inet_create(net, sock, protocol, kern);
	}
	return 0;
}

/* 
 * If the FINS stack passthrough is enabled, this function is called when socket() is called from userspace.
 * See FINS_wedge_create_socket for details.
 */
static int FINS_create_socket(struct net *net, struct socket *sock, int protocol, int kern){
	unsigned long long uniqueSockID;
	int rc = -ESOCKTNOSUPPORT;
	struct sock *sk;
	int ret;

	int buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS: Entering %s\n", __FUNCTION__);

	// Required stuff for kernel side	
	rc = -ENOMEM;
	sk = sk_alloc(net, PF_FINS, GFP_KERNEL, &FINS_proto);
	
	if(!sk)	goto out;	// if allocation failed
	
	sk_refcnt_debug_inc(sk);
	sock_init_data(sock, sk);	
	
	sk->sk_no_check = 1;
	sock->ops = &FINS_proto_ops;		

	rc = 0;


	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		rc = -1;		// pick an appropriate errno 
		goto out;
	}

	// Build the message
	buf = socket_call; //SYS_SOCKET;
	buffer_length = sizeof(int);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, &buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		rc = -1;	// pick an appropriate errno
		goto out;
	}

	// ONLY FOR BLOCKING CALLS: must get a semaphore and go to sleep until daemon sends response and netlink handler unlocks semaphore
	// get semaphore before continuing - unlocked by netlink handler
	if(down_interruptible(&FINS_socket_sem)){;}	// Should be locked at start

	// If we get here, the semaphore was unlocked by the handler (daemon's response received)
	printk(KERN_INFO "%s: got a daemon reply to a socket() call\n", __FUNCTION__);	

	// relock the semaphore so it is locked next time around
	sema_init(&FINS_socket_sem, 0);	
	printk(KERN_INFO "%s: relocked my semaphore\n", __FUNCTION__);

out:	
	printk(KERN_INFO "FINS: Exiting %s\n", __FUNCTION__);
	return rc;
}

/* This function is called from within FINS_release and is modeled after ipx_destroy_socket() */
static void FINS_destroy_socket(struct sock *sk){
	printk("FINS_destroy_socket called.\n");
	skb_queue_purge(&sk->sk_receive_queue);
	sk_refcnt_debug_dec(sk);
}

/*
 * This function is called automatically to cleanup when a program that 
 * created a socket terminates.
 * Or manually via close()?????
 * Modeled after ipx_release().
 */
static int FINS_release(struct socket *sock){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;		// used for test
	ssize_t buffer_length;	// used for test
	struct sock *sk = sock->sk;
	
	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "FINS_release() called.\n");
       	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_release() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	if(!sk)	goto out;
	
	printk(KERN_INFO "FINS: FINS_release -- sk was set.\n");	

	lock_sock(sk);
	if(!sock_flag(sk, SOCK_DEAD))	sk->sk_state_change(sk);
	
	sock_set_flag(sk, SOCK_DEAD);
	sock->sk = NULL;
	sk_refcnt_debug_release(sk);
	FINS_destroy_socket(sk);
	sock_put(sk);
out:	
	return 0;
}

static int FINS_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len){
	unsigned long long uniqueSockID;
	int ret;
	int buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = bind_call; //SYS_BIND;
	buffer_length = sizeof(int);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, &buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	if(down_interruptible(&FINS_bind_sem)){;}	// block until daemon replies
	sema_init(&FINS_bind_sem, 0);	// relock semaphore

	return 0;
}

static int FINS_connect(struct socket *sock, struct sockaddr *uaddr, int addr_len, int flags){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_connect() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_socketpair(struct socket *sock1, struct socket *sock2){
	unsigned long long uniqueSockID1, uniqueSockID2;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID1 = getUniqueSockID(sock1);
	uniqueSockID2 = getUniqueSockID(sock2);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_socketpair() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}
	
	return 0;
}

static int FINS_accept(struct socket *sock, struct socket *newsock, int flags){
	unsigned long long uniqueSockIDoriginal, uniqueSockIDnew;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockIDoriginal = getUniqueSockID(sock);
	uniqueSockIDnew = getUniqueSockID(newsock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_accept() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}
	
	return 0;
}

static int FINS_getname(struct socket *sock, struct sockaddr *saddr, int *len, int peer){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_getname() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static unsigned int FINS_poll(struct file *file, struct socket *sock, poll_table *pt){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);
	
	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_poll() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_ioctl() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_listen(struct socket *sock, int backlog){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_listen() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_shutdown(struct socket *sock, int how){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_shutdown() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_setsockopt() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_getsockopt() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_sendmsg() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	return 0;
}

static int FINS_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len, int flags){
	unsigned long long uniqueSockID;
	int ret;
	int buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = SYS_RECV;
	buffer_length = sizeof(int);

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, &buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	if(down_interruptible(&FINS_bind_sem)){;}	// block until daemon replies
	sema_init(&FINS_bind_sem, 0);	// relock semaphore

	return 0;
}

static int FINS_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_mmap() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	/* Mirror missing mmap method error code */
	return -ENODEV;
}

static ssize_t FINS_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags){
	unsigned long long uniqueSockID;
	int ret;
	char *buf;	// used for test
	ssize_t buffer_length;	// used for test

	uniqueSockID = getUniqueSockID(sock);

	printk(KERN_INFO "%s called.\n", __FUNCTION__);
	
	// Notify FINS daemon
	if(FINS_daemon_pid == -1){	// FINS daemon has not made contact yet, no idea where to send message
		return -1;		// pick an appropriate errno 
	}

	// Build the message
	buf = "FINS_sendpage() called.";
	buffer_length = strlen(buf) + 1;

	// Send message to FINS_daemon
	ret = nl_send(FINS_daemon_pid, buf, buffer_length, 0);
	if(ret != 0){
		printk(KERN_ERR "%s: nl_send failed\n", __FUNCTION__);
		return -1;	// pick an appropriate errno
	}

	/* See sock_no_sendpage() in /net/core/sock.c for more information of what maybe should go here? */
	return 0;
}

/* Data structures needed for protocol registration */
/* A proto struct for the dummy protocol */
static struct proto FINS_proto = {
        .name                   = "FINS_PROTO",
        .owner                  = THIS_MODULE,
        .obj_size               = sizeof(struct FINS_sock),
};

/* see IPX struct net_proto_family ipx_family_ops for comparison */
static struct net_proto_family FINS_net_proto = {
	.family = PF_FINS,
	.create = FINS_wedge_create_socket,	// This function gets called when socket() is called from userspace
	.owner = THIS_MODULE,
};

/* Defines which functions get called when corresponding calls are made from userspace */
static struct proto_ops FINS_proto_ops = {
	.family = PF_FINS,
	.owner = THIS_MODULE,
	.release = FINS_release,
	.bind = FINS_bind, 			//sock_no_bind,
	.connect = FINS_connect,		//sock_no_connect,
	.socketpair = FINS_socketpair,		//sock_no_socketpair,
	.accept = FINS_accept,			//sock_no_accept,
	.getname = FINS_getname,		//sock_no_getname,
	.poll = FINS_poll,			//sock_no_poll,
	.ioctl = FINS_ioctl,			//sock_no_ioctl,
	.listen = FINS_listen,			//sock_no_listen,
	.shutdown = FINS_shutdown, 		//sock_no_shutdown,
	.setsockopt = FINS_setsockopt,		//sock_no_setsockopt,
	.getsockopt = FINS_getsockopt, 		//sock_no_getsockopt,
	.sendmsg = FINS_sendmsg,		//sock_no_sendmsg,
	.recvmsg = FINS_recvmsg,		//sock_no_recvmsg,
	.mmap = FINS_mmap, 			//sock_no mmap,
	.sendpage = FINS_sendpage, 		//sock_no_sendpage,
};


/* FINS Netlink functions  */
/*
 * Sends len bytes from buffer buf to process pid, and sets the flags.
 * Returns 0 if successful or -1 if an error occurred.
 */
int nl_send(int pid, void *buf, ssize_t len, int flags){
        struct nlmsghdr *nlh;
        struct sk_buff *skb;
        int ret_val;

        // Allocate a new netlink message
        skb = nlmsg_new(len, 0);        // nlmsg_new(size_t payload, gfp_t flags)
        if(!skb){
                printk(KERN_ERR "netlink - %s: Failed to allocate new skb\n", __FUNCTION__);
                return -1;
        }

        // Load nlmsg header
        // nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int payload, int flags)
        nlh = nlmsg_put(skb, KERNEL_PID, 0, NLMSG_DONE, len, flags);
        NETLINK_CB(skb).dst_group = 0;  // not in a multicast group

        // Copy data into buffer
        memcpy(NLMSG_DATA(nlh), buf, len);

        // Send the message
        ret_val = nlmsg_unicast(FINS_nl_sk, skb, pid);
        if(ret_val < 0){
                printk(KERN_ERR "netlink - %s: Error sending to user\n", __FUNCTION__);
                return -1;
        }

        return 0;
}

/*
 * This function is automatically called when the kernel receives a datagram on the corresponding netlink socket. 
 */
void nl_data_ready(struct sk_buff *skb){
        struct nlmsghdr *nlh = NULL;
        void *buf;      // Pointer to data in payload
        ssize_t len;    // Payload length       
        int pid;        // pid of sending process

	int socketDaemonResponseType;	// a number corresponding to the type of socketcall this packet is in response to

        if(skb == NULL) {
                printk("skb is NULL \n");
                return ;
        }
        nlh = (struct nlmsghdr *) skb->data;
        pid = nlh->nlmsg_pid;   // get pid from the header      

        // Get a pointer to the start of the data in the buffer and the buffer (payload) length
        buf = NLMSG_DATA(nlh);
        len = NLMSG_PAYLOAD(nlh, 0);


	// **** Remember the LKM must be up first, then the daemon, 
	// but the daemon must make contact before any applications try to use socket()
	
	if(pid == -1){	// if the socket daemon hasn't made contact before
	        // Print what we received
        	printk(KERN_INFO "Socket Daemon made contact: %s\n", (char *) buf);
	}else{
		// demultiplex to the appropriate call handler
		socketDaemonResponseType = *(int *) buf;
		switch(socketDaemonResponseType){
			case SYS_SOCKET:
				// do whatever you need to here as a handler
				printk(KERN_INFO "%s: got a daemon reply to a socket() call\n",__FUNCTION__);
				up(&FINS_socket_sem);	// unblock the socket call
				break;
			case SYS_BIND:
				printk(KERN_INFO "%s: got a daemon reply to a bind() call\n",__FUNCTION__);
				up(&FINS_bind_sem);	// unblock the bind call
				break;
			case SYS_RECV:
			case SYS_RECVFROM:
			case SYS_RECVMSG:
				printk(KERN_INFO "%s: got a daemon reply to a recv(), recvfrom(), or recvmsg() call\n", __FUNCTION__);
				up(&FINS_recvmsg_sem);  // unblock the recvmsg call
				break;
			default:
				break;		
		}
	}
	
	FINS_daemon_pid = pid;
        // Ok to process netlink message here if fast, otherwise use another kernel thread and wake it up here 
}


/* Helper function to extract a unique socket ID from a given struct sock */
inline unsigned long long getUniqueSockID(struct socket *sock){
	return (unsigned long long) &(sock->sk->__sk_common);	// Pointer to sock_common struct as unique ident
}

static void setup_FINS_blocking_semaphores(void){
	// initialize all semaphores used for blocking calls to locked state at first	
	sema_init(&FINS_socket_sem, 0);	
	sema_init(&FINS_bind_sem, 0);	
	sema_init(&FINS_recvmsg_sem, 0);	
}

/* Functions to initialize and teardown the protocol */
static void setup_FINS_protocol(void){
	int rc; // used for reporting return value

	// Changing this value to 0 disables the FINS passthrough by default
	// Changing this value to 1 enables the FINS passthrough by default
	FINS_stack_passthrough_enabled = 1;	// Initialize kernel wide FINS data passthrough

	/* Call proto_register and report debugging info */
	rc = proto_register(&FINS_proto, 1);
	printk(KERN_INFO "proto_register returned: %d\n", rc);
	printk(KERN_INFO "Made it through FINS proto_register()\n");	

	/* Call sock_register to register the handler with the socket layer */
	rc = sock_register(&FINS_net_proto);
	printk(KERN_INFO "sock_register returned: %d\n", rc);	
	printk(KERN_INFO "Made it through FINS sock_register()\n");	
}

static void teardown_FINS_protocol(void){
	/* Call sock_unregister to unregister the handler with the socket layer */
	sock_unregister(FINS_net_proto.family);
	printk(KERN_INFO "Made it through FINS sock_unregister()\n");

	/* Call proto_unregister and report debugging info */
	proto_unregister(&FINS_proto);
	printk(KERN_INFO "Made it through FINS proto_unregister()\n");	
}

/* Functions to initialize and teardown the netlink socket */
static int setup_FINS_netlink(void){
        // nl_data_ready is the name of the function to be called when the kernel receives a datagram on this netlink socket.
        FINS_nl_sk = netlink_kernel_create(&init_net, NETLINK_FINS, 0, nl_data_ready, NULL, THIS_MODULE);
        if(!FINS_nl_sk){
                printk(KERN_ALERT "Error creating socket.\n");
                return -10;
        }
        return 0;
}

static void teardown_FINS_netlink(void){
        // closes the netlink socket
        if(FINS_nl_sk != NULL){
                sock_release(FINS_nl_sk->sk_socket);
        }
}

/* LKM specific functions */
/* 
 * Note: the init and exit functions must be defined (or declared/declared in header file) before the macros are called
 */
static int __init FINS_stack_wedge_init(void){
	printk(KERN_INFO "Loading the FINS_stack_wedge module\n");
	setup_FINS_protocol();
	setup_FINS_netlink();
	setup_FINS_blocking_semaphores();
	printk(KERN_INFO "Made it through the FINS_stack_wedge initialization\n");	
	return 0;
}

static void __exit FINS_stack_wedge_exit(void){
	printk(KERN_INFO "Unloading the FINS_stack_wedge module\n");
	teardown_FINS_netlink();
	teardown_FINS_protocol();
	printk(KERN_INFO "Made it through the FINS_stack_wedge removal\n");
	// the system call wrapped by rmmod frees all memory that is allocated in the module
}

/* Macros defining the init and exit functions */
module_init(FINS_stack_wedge_init);
module_exit(FINS_stack_wedge_exit);

/* Set the license and signing info for the module */
MODULE_LICENSE(M_LICENSE);
MODULE_DESCRIPTION(M_DESCRIPTION);
MODULE_AUTHOR(M_AUTHOR);
