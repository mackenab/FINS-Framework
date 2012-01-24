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
#define socket_call 1
#define socketpair_call 2
#define bind_call 3
#define getsockname_call 4
#define connect_call 5
#define getpeername_call 6
#define send_call 7
#define recv_call 8
#define sendto_call 9
#define recvfrom_call 10
#define sendmsg_call 11
#define recvmsg_call 12
#define getsockopt_call 13
#define setsockopt_call 14
#define listen_call 15
#define accept_call 16
#define accept4_call 17
#define shutdown_call 18
/** Additional calls
 * To hande special cases
 * overwriting the generic functions which write to a socket descriptor
 * in order to make sure that we cover as many applications as possible
 * This range of these functions will start from 30
 */
#define close_call 19
#define release_call 20
#define ioctl_call 21
#define daemonconnect_call 22

#define MAX_calls 23

#define write_call 30

#define ACK 	200
#define NACK 	6666

#define LOOP_LIMIT 10

// Data declarations
/* Data for netlink sockets */
struct sock *FINS_nl_sk = NULL;
int FINS_daemon_pid = -1; // holds the pid of the FINS daemon so we know who to send back to

/* Data for protocol registration */
static struct proto_ops FINS_proto_ops;
static struct proto FINS_proto;
static struct net_proto_family FINS_net_proto;
/* Protocol specific socket structure */
struct FINS_sock {
	/* struct sock MUST be the first member of FINS_sock */
	struct sock sk;
/* Add the protocol implementation specific members per socket here from here on */
// Other stuff might go here, maybe look at IPX or IPv4 registration process
};

// Function prototypes:
static int FINS_create_socket(struct net *net, struct socket *sock, int protocol, int kern);
/*
static int FINS_release(struct socket *sock);
static int FINS_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
static int FINS_connect(struct socket *sock, struct sockaddr *addr, int addr_len, int flags);
static int FINS_socketpair(struct socket *sock1, struct socket *sock2);
static int FINS_accept(struct socket *sock, struct socket *newsock, int flags);
static int FINS_getname(struct socket *sock, struct sockaddr *saddr, int *len, int peer);
static unsigned int FINS_poll(struct file *file, struct socket *sock, poll_table *pt);
static int FINS_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
static int FINS_listen(struct socket *sock, int backlog);
static int FINS_shutdown(struct socket *sock, int how);
static int FINS_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen);
static int FINS_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen);
static int FINS_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len);
static int FINS_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *m, size_t len, int flags);
static int FINS_mmap(struct file *file, struct socket *sock, struct vm_area_struct *vma);
static ssize_t FINS_sendpage(struct socket *sock, struct page *page, int offset, size_t size, int flags);
*/
/* FINS netlink functions*/
int nl_send(int pid, void *buf, ssize_t len, int flags);
int nl_send_msg(int pid, unsigned int seq, int type, void *buf, ssize_t len,
		int flags);
void nl_data_ready(struct sk_buff *skb);

// This function extracts a unique ID from the kernel-space perspective for each socket
inline unsigned long long getUniqueSockID(struct socket *sock);

#define MAX_sockets 100
#define MAX_calls 23

struct finssocket {
	unsigned long long uniqueSockID;
	int type;
	int protocol;

	struct semaphore call_sems[MAX_calls];
	int release_flag;

	int threads;
	struct semaphore threads_sem;
	int replies;
	struct semaphore replies_sem;

	struct semaphore reply_sem_w;
	struct semaphore reply_sem_r; //reassuring, but might not be necessary
	u_int reply_call;
	int reply_ret;
	u_char *reply_buf;
	int reply_len;
};

/*
 void init_jinnisockets();
 int insertjinniSocket(unsigned long long uniqueSockID, int type, int protocol);
 int findjinniSocket(unsigned long long uniqueSockID);
 int removejinniSocket(unsigned long long uniqueSockID);
 */

/* This is my initial example recommended datagram to pass over the netlink socket between daemon and kernel via the nl_send() function */
//struct FINS_nl_dgram {
//	int socketCallType;	// used for identifying what socketcall was made and who the response is intended for
//	unsigned long long uniqueSockID1;
//	unsigned long long uniqueSockID2;	// some calls need to pass second ID such as accept and socketpair 
//	void *buf;	// pointer to a buffer with whatever other data is important
//	ssize_t len;	// length of the buffer	
//};

/* 
 * The current version of this module does not support selective redirection through the original inet stack (IPv4)
 * If that functionality were required, the kernel would have to export inet_create, among other changes, and this 
 * function prototype would need to be declared.
 */
//static int inet_create(struct net *net, struct socket *sock, int protocol, int kern);

/* This is a flag to enable or disable the FINS stack passthrough */
int FINS_stack_passthrough_enabled;
EXPORT_SYMBOL( FINS_stack_passthrough_enabled);
