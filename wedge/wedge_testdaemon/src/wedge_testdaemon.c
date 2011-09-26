#include <stdlib.h>	
#include <stdio.h>	
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#define TRUE	1
#define FALSE	0

#define NETLINK_FINS	20		// Pick an appropriate protocol or define a new one in include/linux/netlink.h
#define RECV_BUFFER_SIZE	10000	// Pick an appropriate value here

struct sockaddr_nl local_sockaddress;	// sockaddr_nl for this process (source)
struct sockaddr_nl kernel_sockaddress;	// sockaddr_nl for the kernel (destination)

/* 
 * Intializes the netlink socket to talk to the FINS LKM
 * Returns the socket descriptor if successful or -1 if an error occurred
 */
int init_fins_nl(){
	int sockfd;
	int ret_val;

	// Get a netlink socket descriptor
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FINS);
	if(sockfd == -1){
		return -1;
	}

	// Populate local_sockaddress
	memset(&local_sockaddress, 0, sizeof(local_sockaddress));
	local_sockaddress.nl_family = AF_NETLINK;
	local_sockaddress.nl_pad = 0;
	local_sockaddress.nl_pid = getpid(); 	//pthread_self() << 16 | getpid(),	// use second option for multi-threaded process
	local_sockaddress.nl_groups = 0;	// unicast

	// Bind the local netlink socket
	ret_val = bind(sockfd, (struct sockaddr*) &local_sockaddress, sizeof(local_sockaddress));
	if(ret_val == -1){	
		return -1;
	}

	// Populate kernel_sockaddress
	memset(&kernel_sockaddress, 0, sizeof(kernel_sockaddress));
	kernel_sockaddress.nl_family = AF_NETLINK;
	kernel_sockaddress.nl_pad = 0;
	kernel_sockaddress.nl_pid = 0;		// to kernel
	kernel_sockaddress.nl_groups = 0;	// unicast

	return sockfd;
}


/* 
 * Sends len bytes from buf on the sockfd.  Returns 0 if successful.  Returns -1 if an error occurred, errno set appropriately.
 */
int sendfins(int sockfd, void *buf, size_t len, int flags){
	int ret_val;	// Holds system call return values for error checking	
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;

	// Begin send message section		
	// Build a message to send to the kernel
	nlh = (struct nlmsghdr *) malloc(NLMSG_LENGTH(len));	// malloc(NLMSG_SPACE(len));	// TODO: Test and remove
	memset(nlh, 0, NLMSG_LENGTH(len));			// NLMSG_SPACE(len));		// TODO: Test and remove

	nlh->nlmsg_len = NLMSG_LENGTH(len);
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0;		// arbitrary value 
	nlh->nlmsg_seq = 0; 		// sequence number 
	nlh->nlmsg_pid = getpid();	// pthread_self() << 16 | getpid();	// use the second one for multiple threads
	nlh->nlmsg_flags = flags;		 

	// Insert payload (memcpy)
	memcpy(NLMSG_DATA(nlh), buf, len);

	// finish message packing
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *) &kernel_sockaddress;
	msg.msg_namelen = sizeof(kernel_sockaddress);	
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the message
	printf("Sending message to kernel\n");
	ret_val = sendmsg(sockfd, &msg, 0);
	if(ret_val == -1){
		return -1;
	}

	free(nlh);
	return 0;
}

int main(){
	int ret_val;	
	int nl_sockfd;	

	nl_sockfd = init_fins_nl();
	if(nl_sockfd == -1){	// if you get an error here, check to make sure you've inserted the FINS LKM first.
		perror("init_fins_nl() caused an error");
		exit(-1);
	}

	char *mystring = "FINS TestSocket Daemon Up";
	int stringlength = strlen(mystring) + 1;	// includes null terminating character

	ret_val = sendfins(nl_sockfd, (void *) mystring, stringlength, 0); 
	if(ret_val != 0){
		perror("sendfins() caused an error");
		exit(-1);
	}


	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	void *buf;
	buf = malloc(RECV_BUFFER_SIZE);
	if(buf == NULL){
		fprintf(stderr, "buffer allocation failed\n");
		exit(-1);
	}

	struct sockaddr sockaddr_sender;	// Needed for recvfrom
	socklen_t sockaddr_senderlen;		// Needed for recvfrom

	void *realdata;				// Pointer to your actual data payload
	ssize_t realdata_len;			// Size of your actual data payload
	int socketCallType;			// Integer representing what socketcall type was placed (for testing purposes)

	while(TRUE){
		printf("Waiting for message from kernel\n");

		ret_val = recvfrom(nl_sockfd, buf, RECV_BUFFER_SIZE, 0, &sockaddr_sender, &sockaddr_senderlen);
		if(ret_val == -1){
			perror("recvfrom() caused an error");
			exit(-1);
		}

		// Extract the payload from the buffer (or rather get a pointer to the payload in place)
		// Make sure you remember to wrap your buf in NLMSG_DATA((struct nlmsghdr *) buf) or you won't get your data
		// To get the size of the actual payload, use:  NLMSG_PAYLOAD((struct nlmsghdr *) buf, 0); 
		realdata = NLMSG_DATA((struct nlmsghdr *) buf);
		realdata_len = NLMSG_PAYLOAD((struct nlmsghdr *) buf, 0);	

		//or if you need to copy the data out of the buffer that was allocated before recvmsg, use
		//memcpy(void *dest, NLMSG_DATA((struct nlmsghdr *) buf), NLMSG_PAYLOAD((struct nlmsghdr *) buf, 0));

		
		// get the type of call that was made and store it
		socketCallType = *(int *)realdata;

		// if you want to see how the semaphore locking works, uncomment the following code block.
		// this will hang each reply message to the kernel from this daemon until the user enters an integer
		//int number;
		//printf("The daemon received call number %d from the LKM. To send a response to the LKM and unblock the call, press enter.\n");
		//scanf("%d", &number);
	
		// send the reply message
		ret_val = sendfins(nl_sockfd, &socketCallType, sizeof(int), 0);
		if(ret_val != 0){
			perror("sendfins() caused an error");
			exit(-1);
		}
	}

	free(buf);
	close(nl_sockfd);
	exit(0);
}
