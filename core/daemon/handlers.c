/*
 * @file handlers.c
 *
 * @date Mar 6, 2011
 *      @author Abdallah Abdallah
 *      @brief  The DeMux which redirects every request to its appropriate
 *      protocol alternative socket interface. This initial basic
 *      version includes UDP handlers and TCP handlers). It also has the functions
 *      which manage and maintain our socket database
 */

#include "handlers.h"

extern sem_t daemonSockets_sem;
extern struct finssocket daemonSockets[MAX_sockets];

extern int recv_thread_index;
extern int thread_count;
extern sem_t thread_sem;

/** The queues might be moved later to another Master file */

extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;
extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

int init_fins_nl() {
	int sockfd;
	int ret_val;

	// Get a netlink socket descriptor
	sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FINS);
	if (sockfd == -1) {
		return -1;
	}

	// Populate local_sockaddress
	memset(&local_sockaddress, 0, sizeof(local_sockaddress));
	local_sockaddress.nl_family = AF_NETLINK;
	local_sockaddress.nl_pad = 0;
	local_sockaddress.nl_pid = getpid(); //pthread_self() << 16 | getpid(),	// use second option for multi-threaded process
	local_sockaddress.nl_groups = 0; // unicast

	// Bind the local netlink socket
	ret_val = bind(sockfd, (struct sockaddr*) &local_sockaddress, sizeof(local_sockaddress));
	if (ret_val == -1) {
		return -1;
	}

	// Populate kernel_sockaddress
	memset(&kernel_sockaddress, 0, sizeof(kernel_sockaddress));
	kernel_sockaddress.nl_family = AF_NETLINK;
	kernel_sockaddress.nl_pad = 0;
	kernel_sockaddress.nl_pid = 0; // to kernel
	kernel_sockaddress.nl_groups = 0; // unicast

	return sockfd;
}

/*
 * Sends len bytes from buf on the sockfd.  Returns 0 if successful.  Returns -1 if an error occurred, errno set appropriately.
 */
int send_wedge(int sockfd, void *buf, size_t len, int flags) {
	int ret_val; // Holds system call return values for error checking

	// Begin send message section
	// Build a message to send to the kernel
	int nlmsg_len = NLMSG_LENGTH(len);
	struct nlmsghdr *nlh = (struct nlmsghdr *) malloc(nlmsg_len);
	memset(nlh, 0, nlmsg_len);

	nlh->nlmsg_len = nlmsg_len;
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0; // arbitrary value
	nlh->nlmsg_seq = 0; // sequence number
	nlh->nlmsg_pid = getpid(); // pthread_self() << 16 | getpid();	// use the second one for multiple threads
	nlh->nlmsg_flags = flags;

	// Insert payload (memcpy)
	memcpy(NLMSG_DATA(nlh), buf, len);

	// finish message packing
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &kernel_sockaddress;
	msg.msg_namelen = sizeof(kernel_sockaddress);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the message
	PRINT_DEBUG("Sending message to kernel\n");
	ret_val = sendmsg(sockfd, &msg, 0);
	if (ret_val == -1) {
		return -1;
	}

	free(nlh);
	return 0;
}

/**
 * @brief find a daemon socket among the daemon sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int find_daemonSocket(unsigned long long targetID) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].uniqueSockID == targetID)
			return (i);
	}
	return (-1);
}

int match_daemonSocket(uint16_t dstport, uint32_t dstip, int protocol) {

	int i;

	PRINT_DEBUG("matchdaemonSocket: %d/%d: %d, ", dstip, dstport, protocol);

	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].uniqueSockID != -1) {
			if (protocol == IPPROTO_ICMP) {
				if ((daemonSockets[i].protocol == protocol) && (daemonSockets[i].dst_IP == dstip)) {
					PRINT_DEBUG("ICMP");
					return (i);
				}
			} else {
				if (daemonSockets[i].host_IP == INADDR_ANY) {
					if (daemonSockets[i].hostport == dstport) {
						PRINT_DEBUG("hostport == dstport");
						return (i);
					}
				} else if ((daemonSockets[i].hostport == dstport) && (daemonSockets[i].host_IP == dstip)/** && (daemonSockets[i].protocol == protocol)*/) {
					PRINT_DEBUG("host_IP == dstip");
					return (i);
				} else {
					PRINT_DEBUG("default");
				}
			}

			if (0) {
				if (daemonSockets[i].host_IP == INADDR_ANY && (protocol != IPPROTO_ICMP)) {
					if ((daemonSockets[i].hostport == dstport))
						return (i);
				} else if ((daemonSockets[i].hostport == dstport) && (daemonSockets[i].host_IP == dstip) && ((protocol != IPPROTO_ICMP))
				/** && (daemonSockets[i].protocol == protocol)*/) {
					return (i);
				}

				/** Matching for ICMP incoming datagrams
				 * In this case the IP passes is actually the source IP of that incoming message (Or called the host)
				 */
				else if ((daemonSockets[i].protocol == protocol) && (protocol == IPPROTO_ICMP) && (daemonSockets[i].dst_IP == dstip)) {
					return (i);

				} else {
				}
			}
		}
	} // end of for loop

	return (-1);

}

int match_daemon_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("match_daemon_socket: %d/%d to %d/%d", host_ip, host_port, rem_ip, rem_port);

	int i;
	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].uniqueSockID != -1 && daemonSockets[i].host_IP == host_ip && daemonSockets[i].hostport == host_port
				&& daemonSockets[i].dst_IP == rem_ip && daemonSockets[i].dstport == rem_port) {
			PRINT_DEBUG("Matched connection");
			return (i);
		}
	}

	//TODO add check for INADDR_ANY & INPORT_ANY

	return (-1);
}

/**
 * @brief insert new daemon socket in the first empty location
 * in the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int insert_daemonSocket(unsigned long long uniqueSockID, int type, int protocol) {
	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].uniqueSockID == -1) {
			daemonSockets[i].uniqueSockID = uniqueSockID;
			sem_init(&daemonSockets[i].sem, 0, 1);

			daemonSockets[i].blockingFlag = 1;
			/**
			 * bind the socket by default to the default IP which is assigned
			 * to the Interface which was already started by the Capturing and Injecting process
			 * The IP default value it supposed to be acquired from the configuration file
			 * The allowable ports range is supposed also to be aquired the same way
			 */
			daemonSockets[i].host_IP = 0;
			/**
			 * The host port is initially assigned randomly and stay the same unless
			 * binding explicitly later
			 */
			daemonSockets[i].hostport = 0;
			daemonSockets[i].dst_IP = 0;
			daemonSockets[i].dstport = 0;
			/** Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM
			 * it has nothing to do with layer 4 protocols like TCP, UDP , etc
			 */

			daemonSockets[i].type = type;

			daemonSockets[i].protocol = protocol;
			daemonSockets[i].backlog = DEFAULT_BACKLOG;
			daemonSockets[i].controlQueue = init_queue(NULL, MAX_Queue_size);
			daemonSockets[i].dataQueue = init_queue(NULL, MAX_Queue_size);
			sem_init(&daemonSockets[i].Qs, 0, 1);

			sprintf(daemonSockets[i].name, "socket# %llu", daemonSockets[i].uniqueSockID);

			errno = 0;
			PRINT_DEBUG("errno is %d", errno);

			daemonSockets[i].threads = 0;
			daemonSockets[i].replies = 0;

			daemonSockets[i].sockopts.FSO_REUSEADDR = 0;

			return i;
		}
	}
	PRINT_DEBUG("reached maximum # of processes to be served, FINS is out of sockets");
	return (-1);
}

/**
 * @brief remove a daemon socket from
 * the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */

int remove_daemonSocket(unsigned long long targetID) {

	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].uniqueSockID == targetID) {
			daemonSockets[i].uniqueSockID = -1;

			//TODO stop all threads related to

			daemonSockets[i].connection_status = 0;
			term_queue(daemonSockets[i].controlQueue);
			term_queue(daemonSockets[i].dataQueue);
			return (1);

		}
	}
	return 0;
} // end of removedaemonSocket

/**
 * @brief check if this host port is free or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found previously-allocated)
 */

int check_daemon_ports(uint16_t hostport, uint32_t hostip) {

	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if (daemonSockets[i].host_IP == INADDR_ANY) {
			if (daemonSockets[i].hostport == hostport)
				return (0);

		} else {
			if ((daemonSockets[i].hostport == hostport) && (daemonSockets[i].host_IP == hostip))
				return (0);

		}
	}
	return (1);

}

/**
 * @brief check if this destination port and address has been contacted as
 * destinations earlier or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found pre-allocated)
 */

int check_daemon_dstports(uint16_t dstport, uint32_t dstip) {

	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if ((daemonSockets[i].dstport == dstport) && (daemonSockets[i].dst_IP == dstip))
			return (-1);

	}
	return (1);

}

/** ----------------------------------------------------------
 * end of functions that handle finsdaemonsockets
 */

/**
 * @brief generate a random integer between min and max
 * @param minimum value of the range, maximum value of the range
 * @return the random integer value
 *
 */

int randoming(int min, int max) {

	srand((unsigned) time(NULL));
	return (min + (int) (max - min + 1) * (rand() / (RAND_MAX + 1.0)));

}

int nack_send(unsigned long long uniqueSockID, int socketCallType, int ret_msg) {
	int nack = NACK;
	int buf_len;
	void *buf;
	u_char *pt;
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d nack %d", uniqueSockID, socketCallType, nack);

	buf_len = sizeof(unsigned int) + sizeof(unsigned long long) + 2 * sizeof(int);
	buf = malloc(buf_len);
	pt = buf;

	*(unsigned int *) pt = socketCallType;
	pt += sizeof(unsigned int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = nack;
	pt += sizeof(int);

	*(int *) pt = ret_msg;
	pt += sizeof(int);

	ret_val = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret_val == 1;
}

int ack_send(unsigned long long uniqueSockID, int socketCallType, int ret_msg) {
	int ack = ACK;
	int buf_len;
	void *buf;
	u_char *pt;
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d ack %d", uniqueSockID, socketCallType, ack);

	buf_len = sizeof(unsigned int) + sizeof(unsigned long long) + 2 * sizeof(int);
	buf = malloc(buf_len);
	pt = buf;

	*(unsigned int *) pt = socketCallType;
	pt += sizeof(unsigned int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ack;
	pt += sizeof(int);

	*(int *) pt = ret_msg;
	pt += sizeof(int);

	ret_val = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret_val == 1;
}

int nack_write(int pipe_desc, unsigned long long uniqueSockID) {
	return (1);
}
int ack_write(int pipe_desc, unsigned long long uniqueSockID) {
	return (1);
}

struct finsFrame *get_fdf(int index, unsigned long long uniqueSockID, int block_flag) {
	struct finsFrame *ff;

	/**
	 * It keeps looping as a bad method to implement the blocking feature
	 * of recvfrom. In case it is not blocking then the while loop should
	 * be replaced with only a single trial !
	 *
	 */
	if (index < 0) {
		return NULL;
	}

	PRINT_DEBUG("");
	if (block_flag) {
		/**
		 * WE Must FINS another way to emulate the blocking.
		 * The best suggestion is to use a pipeline to push the data in
		 * instead of the data queue
		 */
		do {
			sem_wait(&daemonSockets_sem);
			if (daemonSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&daemonSockets_sem);
				return NULL;
			}

			sem_wait(&(daemonSockets[index].Qs));
			ff = read_queue(daemonSockets[index].dataQueue);
			//	ff = get_fake_frame();
			sem_post(&(daemonSockets[index].Qs));
			sem_post(&daemonSockets_sem);
		} while (ff == NULL);
	} else {
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&daemonSockets_sem);
			return NULL;
		}
		sem_wait(&(daemonSockets[index].Qs));
		ff = read_queue(daemonSockets[index].dataQueue);
		//ff = get_fake_frame();
		//print_finsFrame(ff);
		sem_post(&(daemonSockets[index].Qs));
		sem_post(&daemonSockets_sem);
	}
	PRINT_DEBUG("");

	return ff;
}

struct finsFrame *get_fcf(int index, unsigned long long uniqueSockID, int block_flag) {
	struct finsFrame *ff;

	/**
	 * It keeps looping as a bad method to implement the blocking feature
	 * of recvfrom. In case it is not blocking then the while loop should
	 * be replaced with only a single trial !
	 *
	 */
	PRINT_DEBUG("");
	if (block_flag) {
		/**
		 * WE Must FINS another way to emulate the blocking.
		 * The best suggestion is to use a pipeline to push the data in
		 * instead of the data queue
		 */
		do {
			sem_wait(&daemonSockets_sem);
			if (daemonSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&daemonSockets_sem);
				return NULL;
			}

			sem_wait(&(daemonSockets[index].Qs));
			ff = read_queue(daemonSockets[index].controlQueue);
			//	ff = get_fake_frame();
			sem_post(&(daemonSockets[index].Qs));
			sem_post(&daemonSockets_sem);
		} while (ff == NULL);
	} else {
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&daemonSockets_sem);
			return NULL;
		}
		sem_wait(&(daemonSockets[index].Qs));
		ff = read_queue(daemonSockets[index].controlQueue);
		//ff = get_fake_frame();
		//print_finsFrame(ff);
		sem_post(&(daemonSockets[index].Qs));
		sem_post(&daemonSockets_sem);
	}

	PRINT_DEBUG("");

	return ff;
}

void socket_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int domain;
	unsigned int type;
	int protocol;
	u_char *pt;

	PRINT_DEBUG("socket_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	domain = *(int *) pt;
	pt += sizeof(int);

	type = *(unsigned int *) pt;
	pt += sizeof(unsigned int);

	protocol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, socket_call, 0);
		return;
	}

	PRINT_DEBUG("socket call handler: domain=%d, type=%d, protocol=%d", domain, type, protocol);

	PRINT_DEBUG("%d,%d,%d", domain, protocol, type);
	if (domain != AF_INET) {
		PRINT_DEBUG("Wrong domain, only AF_INET us supported");
		nack_send(uniqueSockID, socket_call, 0);
		return;
	}

	if (type == SOCK_DGRAM) {
		socket_udp(domain, type, protocol, uniqueSockID);
	} else if (type == SOCK_STREAM) {
		socket_tcp(domain, type, protocol, uniqueSockID);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		socket_icmp(domain, type, protocol, uniqueSockID);
	} else {
		PRINT_DEBUG("non supported socket type");
		nack_send(uniqueSockID, socket_call, 0);
	}
}

/** ----------------------------------------------------------
 * End of socket_call_handler
 */

void bind_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;
	u_char *pt;
	int reuseaddr;

	PRINT_DEBUG("bind_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(uniqueSockID, bind_call, 0);
		return;
	} else {
		PRINT_DEBUG("addrlen=%d", addrlen);
	}

	addr = (struct sockaddr_in *) malloc(addrlen);
	memcpy(addr, pt, addrlen);
	pt += addrlen;

	reuseaddr = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, bind_call, 0);
		return;
	}

	PRINT_DEBUG("bind_call_handler: addr=%u/%d family=%d, reuseaddr=%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, reuseaddr);

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, bind_call, 0);
		return;
	}

	daemonSockets[index].sockopts.FSO_REUSEADDR |= reuseaddr; //TODO: when sockopts fully impelmented just set to '='

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM)
		bind_udp(index, uniqueSockID, addr);
	else if (type == SOCK_STREAM)
		bind_tcp(index, uniqueSockID, addr);
	else
		PRINT_DEBUG("unknown socket type has been read !!!");

	return;

} //end of bind_call_handler()
/** ----------------------------------------------------------
 * ------------------End of bind_call_handler-----------------
 */

void listen_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	int backlog;
	u_char *pt;

	PRINT_DEBUG("listen_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	backlog = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, listen_call, 0);
		return;
	}

	PRINT_DEBUG("listen_call_handler: backlog=%d", backlog);

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, listen_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);
	PRINT_DEBUG("");

	if (type == SOCK_DGRAM)
		listen_udp(index, uniqueSockID, backlog);
	else if (type == SOCK_STREAM)
		listen_tcp(index, uniqueSockID, backlog);
	else if (type == SOCK_RAW) {
		listen_icmp(index, uniqueSockID, backlog);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, listen_call, 0);
	}
}

void connect_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;
	u_char *pt;

	PRINT_DEBUG("connect_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);
	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(uniqueSockID, connect_call, 0);
		return;
	}

	addr = (struct sockaddr_in *) malloc(addrlen);

	memcpy(addr, pt, addrlen);
	pt += addrlen;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, connect_call, 0);
		return;
	}

	PRINT_DEBUG("connect_call_handler: addr=%u/%d family=%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family);

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		nack_send(uniqueSockID, connect_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM) {
		connect_udp(index, uniqueSockID, addr);
	} else if (type == SOCK_STREAM) {
		connect_tcp(index, uniqueSockID, addr);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, connect_call, 0);
	}
}

void accept_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	int index;
	unsigned long long uniqueSockID_new;
	int flags;
	u_char *pt;

	PRINT_DEBUG("accept_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	uniqueSockID_new = *(unsigned long long *) pt;
	pt += sizeof(unsigned long long);

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, accept_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, accept_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);
	PRINT_DEBUG("");

	if (type == SOCK_DGRAM)
		accept_udp(index, uniqueSockID, uniqueSockID_new, flags);
	else if (type == SOCK_STREAM)
		accept_tcp(index, uniqueSockID, uniqueSockID_new, flags);
	else if (type == SOCK_RAW) {
		accept_icmp(index, uniqueSockID, uniqueSockID_new, flags);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, accept_call, 0);
	}
}

void getname_call_handler(unsigned long long uniqueSockID, int threads, u_char *buf, ssize_t len) {
	int index;
	int peer;
	u_char *pt;

	PRINT_DEBUG("getname_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	peer = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);
	PRINT_DEBUG("");

	if (type == SOCK_DGRAM)
		getname_udp(index, uniqueSockID, peer);
	else if (type == SOCK_STREAM)
		getname_tcp(index, uniqueSockID, peer);
	else if (type == SOCK_RAW) {
		getname_icmp(index, uniqueSockID, peer);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, getname_call, 0);
	}
}

void sendmsg_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	int index;
	int data_len;
	int msg_flags;
	int symbol;
	int controlFlag = 0;
	u_char *data;
	socklen_t addrlen;
	void *msg_control;
	int msg_controlLength;
	struct sockaddr_in *addr;
	u_char *pt;

	PRINT_DEBUG("sendmsg_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	symbol = *(int *) pt;
	pt += sizeof(int);

	if (symbol) {
		addrlen = *(u_int *) pt;
		pt += sizeof(u_int);

		addr = (struct sockaddr_in *) malloc(addrlen);
		memcpy(addr, pt, addrlen);
		pt += addrlen;
		PRINT_DEBUG("addr=%s/%d", inet_ntoa(addr->sin_addr), addr->sin_port);
	}

	msg_flags = *(int *) pt;
	pt += sizeof(int);

	controlFlag = *(int *) pt;
	pt += sizeof(int);

	if (controlFlag) {
		msg_controlLength = *(u_int *) pt;
		pt += sizeof(u_int);

		msg_control = malloc(msg_controlLength);
		memcpy(msg_control, pt, msg_controlLength);
		pt += msg_controlLength;
	}

	data_len = *(u_int *) pt;
	pt += sizeof(u_int);

	if (data_len <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	data = (u_char *) malloc(data_len);
	PRINT_DEBUG("");

	memcpy(data, pt, data_len);
	pt += data_len;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is notfound too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	int status = daemonSockets[index].connection_status;
	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;
	sem_post(&daemonSockets_sem);
	PRINT_DEBUG("");

	/**
	 * In case of connected sockets
	 */
	if (status > 0) {
		if (type == SOCK_DGRAM) {
			send_udp(index, uniqueSockID, data, data_len, msg_flags);
		} else if (type == SOCK_STREAM) {
			send_tcp(index, uniqueSockID, data, data_len, msg_flags);
		} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
			//TODO finish icmp case?
		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			nack_send(uniqueSockID, sendmsg_call, 0);
		}
	} else {
		/**
		 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
		 * Process. Check if an address has been passed or not is required
		 */
		if (symbol) { // check that the passed address is not NULL
			if (type == SOCK_DGRAM) {
				sendto_udp(index, uniqueSockID, data, data_len, msg_flags, addr, addrlen);
			} else if (type == SOCK_STREAM) {
				//TODO implement or error?
				sendto_tcp(index, uniqueSockID, data, data_len, msg_flags, addr, addrlen);
				//nack_send(uniqueSockID, sendmsg_call);
			} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
				sendto_icmp(index, uniqueSockID, data, data_len, msg_flags, addr, addrlen);
			} else {
				PRINT_DEBUG("unknown target address !!!");
				nack_send(uniqueSockID, sendmsg_call, 0);
			}
		} else {
			PRINT_DEBUG("unknown target address !!!");
			nack_send(uniqueSockID, sendmsg_call, 0);
		}
	}

	PRINT_DEBUG();
}

void recvmsg_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	int index;
	int data_len;
	int flags;
	int symbol;
	int msg_flags;
	int control_flag;
	ssize_t msg_control_len;
	void *msg_control;
	u_char *pt;

	PRINT_DEBUG("recvmsg_call_handler: Entered: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	data_len = *(ssize_t *) pt; //check on not in original socket_interceptor: recvmsg
	pt += sizeof(ssize_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	symbol = *(int *) pt;
	pt += sizeof(int);

	msg_flags = *(int *) pt;
	pt += sizeof(int);

	control_flag = *(int *) pt;
	pt += sizeof(int);

	if (control_flag) {
		msg_control_len = *(u_int *) pt;
		pt += sizeof(u_int);

		if (msg_control_len <= 0) {
			PRINT_DEBUG("READING ERROR! CRASH, msgControl_Length=%d", msg_control_len);
			nack_send(uniqueSockID, recvmsg_call, 0);
			return;
		}
		msg_control = (u_char *) malloc(msg_control_len);
		if (msg_control) {
			memcpy(msg_control, pt, msg_control_len); //??? originally had &msgControl
			pt += msg_control_len;
		} else {
			PRINT_DEBUG("allocation error");
			nack_send(uniqueSockID, recvmsg_call, 0);
			return;
		}
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, recvmsg_call, 0);
		return;
	}

	PRINT_DEBUG("");

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is notfound too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, recvmsg_call, 0);
		return;
	}

	daemonSockets[index].threads = threads;

	int status = daemonSockets[index].connection_status;
	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;
	sem_post(&daemonSockets_sem);

	if (status > 0) {
		if (type == SOCK_DGRAM) {
			//recv_udp(index, uniqueSockID, datalen, data, flags);
			recvfrom_udp(index, uniqueSockID, data_len, flags, msg_flags);
		} else if (type == SOCK_STREAM) {
			//recv_tcp(index, uniqueSockID, data_len, flags, msg_flags);
			recvfrom_tcp(index, uniqueSockID, data_len, flags, msg_flags);
		} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
			nack_send(uniqueSockID, recvmsg_call, 0); //TODO implement?
		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			nack_send(uniqueSockID, recvmsg_call, 0);
		}
	} else {
		/**
		 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
		 * Process. Check if an address has been passed or not is required
		 */
		if (symbol) { // check that the passed address is not NULL
			if (type == SOCK_DGRAM) {
				recvfrom_udp(index, uniqueSockID, data_len, flags, msg_flags);
			} else if (type == SOCK_STREAM) {
				//sendto_tcp(index, uniqueSockID, datalen, data, flags, addr, addrlen);
				nack_send(uniqueSockID, recvmsg_call, 0);
			} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
				//sendto_icmp(uniqueSockID, datalen, data, flags, addr, addrlen);
				nack_send(uniqueSockID, recvmsg_call, 0); //TODO what should this be?
			} else {
				PRINT_DEBUG("unknown target address !!!");
				nack_send(uniqueSockID, recvmsg_call, 0);
			}
		} else {
			PRINT_DEBUG("unknown target address !!!");
			nack_send(uniqueSockID, recvmsg_call, 0);
		}
	}
}

void release_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	int index;
	u_char *pt;
	pt = buf;

	PRINT_DEBUG("release_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, release_call, 0);
		return;
	}

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is notfound too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, release_call, 0);
		return;
	}
	//daemonSockets[index].threads = threads;

	int type = daemonSockets[index].type;
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM)
		release_udp(index, uniqueSockID);
	else if (type == SOCK_STREAM)
		release_tcp(index, uniqueSockID);
	else if (type == SOCK_RAW) {
		release_icmp(index, uniqueSockID);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, release_call, 0);
	}
}

void getsockopt_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char *pt;

	PRINT_DEBUG("getsockopt_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = *(int *) pt;
	pt += sizeof(int);

	if (optlen > 0) { //TODO remove?
		optval = (u_char *) malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM)
		getsockopt_udp(index, uniqueSockID, level, optname, optlen, optval);
	else if (type == SOCK_STREAM)
		getsockopt_tcp(index, uniqueSockID, level, optname, optlen, optval);
	else if (type == SOCK_RAW) {
		getsockopt_icmp(index, uniqueSockID, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, getsockopt_call, 0);
	}
}

void setsockopt_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char *pt;

	PRINT_DEBUG("setsockopt_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = (int) *(unsigned int *) pt;
	pt += sizeof(unsigned int);

	if (optlen > 0) {
		optval = (u_char *) malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, setsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM)
		setsockopt_udp(index, uniqueSockID, level, optname, optlen, optval);
	else if (type == SOCK_STREAM)
		setsockopt_tcp(index, uniqueSockID, level, optname, optlen, optval);
	else if (type == SOCK_RAW) {
		setsockopt_icmp(index, uniqueSockID, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, setsockopt_call, 0);
	}
}

void ioctl_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	int index;
	u_int cmd;
	u_long arg;
	u_char *pt;

	PRINT_DEBUG("ioctl_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	cmd = *(u_int *) pt;
	pt += sizeof(u_int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, ioctl_call, 0);
		return;
	}

	PRINT_DEBUG("");
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into daemon sockets SO pipe descriptor to reply is not found too ");
		nack_send(uniqueSockID, ioctl_call, 0);
		return;
	}
	PRINT_DEBUG("uniqueSockID=%llu, index=%d, cmd=%d, arg=%lu", uniqueSockID, index, cmd, arg);

	if (daemonSockets[index].type == SOCK_DGRAM) {
		//ioctl_udp(uniqueSockID, cmd, pt);
	} else if (daemonSockets[index].type == SOCK_STREAM) {
		//ioctl_tcp(uniqueSockID, cmd, pt);
	} else if (daemonSockets[index].type == SOCK_RAW) {
		//ioctl_icmp(uniqueSockID, cmd, pt);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, ioctl_call, 0);
	}
	ack_send(uniqueSockID, ioctl_call, 0);
}

void accept4_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {
	PRINT_DEBUG("accept4_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);
}

void shutdown_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	int how;
	u_char *pt;

	PRINT_DEBUG("shutdown_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	pt = buf;

	how = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, shutdown_call, 0);
		return;
	}

	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into daemon sockets");
		nack_send(uniqueSockID, shutdown_call, 0);
		return;
	}

	if (daemonSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */
		shutdown_udp(uniqueSockID, how);

	} else if (daemonSockets[index].type == SOCK_STREAM) {
		shutdown_tcp(index, uniqueSockID, how);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, shutdown_call, 0);
	}

}

void close_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	PRINT_DEBUG("close_call_handler: uniqueSockID=%llu threads=%d len=%d", uniqueSockID, threads, len);

	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into daemon sockets");
		nack_send(uniqueSockID, close_call, 0);
		return;
	}

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
	if (remove_daemonSocket(uniqueSockID)) {
		ack_send(uniqueSockID, close_call, 0);
	} else {
		nack_send(uniqueSockID, close_call, 0);
	}

}

void getsockname_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	index = find_daemonSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		//nack_send(uniqueSockID, getsockname_call);
		return;
	}

	PRINT_DEBUG("getsockname_handler called");
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = daemonSockets[index].host_IP;
	addr->sin_port = daemonSockets[index].hostport;
	PRINT_DEBUG("%d , %d", daemonSockets[index].host_IP, daemonSockets[index].hostport);

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + addrlen;
	msg = malloc(msg_len);
	pt = msg;

	//*(u_int *) pt = getsockname_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = addrlen;
	pt += sizeof(int);

	memcpy(pt, addr, addrlen);
	pt += addrlen;

	if (pt - (u_char *) msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
		free(msg);
		//nack_send(uniqueSockID, getsockname_call);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);

	PRINT_DEBUG("getsockname DONE");

	return;

}

void getpeername_call_handler(unsigned long long uniqueSockID, int threads, unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	index = find_daemonSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		//nack_send(uniqueSockID, getpeername_call);
		return;
	}

	PRINT_DEBUG("getpeername_handler called");
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = ntohl(daemonSockets[index].dst_IP);
	addr->sin_port = daemonSockets[index].dstport;
	PRINT_DEBUG("%d , %d", daemonSockets[index].dst_IP, daemonSockets[index].dstport);

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + addrlen;
	msg = malloc(msg_len);
	pt = msg;

	//*(u_int *) pt = getpeername_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = addrlen;
	pt += sizeof(int);

	memcpy(pt, addr, addrlen);
	pt += addrlen;

	if (pt - (u_char *) msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
		free(msg);
		//nack_send(uniqueSockID, getpeername_call);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);

	PRINT_DEBUG("getpeername DONE");

	return;

}

void socketpair_call_handler() {

}

void recvthread_exit(struct recvfrom_data *thread_data) {
	sem_wait(&thread_sem);
	thread_count--;
	sem_post(&thread_sem);

	PRINT_DEBUG("Exiting recv thread:%d", thread_data->id);
	free(thread_data);

	pthread_exit(NULL);
}
