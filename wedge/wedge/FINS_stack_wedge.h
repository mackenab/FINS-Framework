/*
 * NETLINK_FINS must match a corresponding constant in the userspace daemon program that is to talk to this module.  
 * NETLINK_ constants are normally defined in <linux/netlink.h> although adding a constant here would necessitate a 
 * full kernel rebuild in order to change it.  This is not necessary, as long as the constant matches in both LKM and
 * userspace program.  To choose an appropriate value, view the linux/netlink.h file and find an unused value 
 * (probably best to choose one under 32) following the list of NETLINK_ constants and define the constant here to
 * match that value as well as in the userspace program.
 */
#define NETLINK_FINS    20	// must match userspace definition
#define KERNEL_PID      0	// This is used to identify netlink traffic into and out of the kernel

// Data declarations
/* Data for netlink sockets */
struct sock *FINS_nl_sk = NULL;
int FINS_daemon_pid = -1;	// holds the pid of the FINS daemon so we know who to send back to

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

/* FINS netlink functions*/ 
int nl_send(int pid, void *buf, ssize_t len, int flags);
void nl_data_ready(struct sk_buff *skb);

// This function extracts a unique ID from the kernel-space perspective for each socket
inline unsigned long long getUniqueSockID(struct socket *sock);


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
EXPORT_SYMBOL(FINS_stack_passthrough_enabled);
