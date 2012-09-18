/*
 * @file daemon.c
 *
 * @date Mar 6, 2011
 *      @author Abdallah Abdallah
 *      @brief  The DeMux which redirects every request to its appropriate
 *      protocol alternative socket interface. This initial basic
 *      version includes UDP handlers and TCP handlers). It also has the functions
 *      which manage and maintain our socket database
 */

#include "daemon.h"

int daemon_running;
pthread_t wedge_to_daemon_thread;
pthread_t switch_to_daemon_thread;

sem_t Daemon_to_Switch_Qsem;
finsQueue Daemon_to_Switch_Queue;

sem_t Switch_to_Daemon_Qsem;
finsQueue Switch_to_Daemon_Queue;

sem_t daemonSockets_sem;
struct fins_daemon_socket daemonSockets[MAX_SOCKETS];

int recv_thread_index;
int thread_count;
sem_t thread_sem;

int init_fins_nl(void) {
	int sockfd;
	int ret_val;

	sem_init(&nl_sem, 0, 1);

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
int send_wedge(int sockfd, u_char *buf, size_t len, int flags) {
	int ret_val; // Holds system call return values for error checking

	// Begin send message section
	// Build a message to send to the kernel
	int nlmsg_len = NLMSG_LENGTH(len);
	struct nlmsghdr *nlh = (struct nlmsghdr *) malloc(nlmsg_len);
	if (nlh == NULL) {
		PRINT_ERROR("nlh malloc error");
		return -1;
	}
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
	sem_wait(&nl_sem);
	ret_val = sendmsg(sockfd, &msg, 0);
	sem_post(&nl_sem);
	free(nlh);

	if (ret_val == -1) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * @brief find a daemon socket among the daemon sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int find_daemonSocket(uint64_t targetID) {
	int i = 0;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].uniqueSockID == targetID)
			return (i);
	}
	return (-1);
}

int match_daemonSocket(uint16_t dstport, uint32_t dstip, int protocol) {

	int i;

	PRINT_DEBUG("Entered: %u/%u: %d, ", dstip, dstport, protocol);

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].uniqueSockID != -1) {
			if (protocol == IPPROTO_ICMP) {
				if ((daemonSockets[i].protocol == protocol) && (daemonSockets[i].dst_ip == dstip)) {
					PRINT_DEBUG("ICMP");
					return (i);
				}
			} else {
				if (daemonSockets[i].host_ip == INADDR_ANY) {
					if (daemonSockets[i].host_port == dstport) {
						PRINT_DEBUG("hostport == dstport");
						return (i);
					}
				} else if ((daemonSockets[i].host_port == dstport) && (daemonSockets[i].host_ip == dstip)/** && (daemonSockets[i].protocol == protocol)*/) {
					PRINT_DEBUG("host_IP == dstip");
					return (i);
				} else {
					PRINT_DEBUG("default");
				}
			}

			if (0) {
				if (daemonSockets[i].host_ip == INADDR_ANY && (protocol != IPPROTO_ICMP)) {
					if ((daemonSockets[i].host_port == dstport))
						return (i);
				} else if ((daemonSockets[i].host_port == dstport) && (daemonSockets[i].host_ip == dstip) && ((protocol != IPPROTO_ICMP))
				/** && (daemonSockets[i].protocol == protocol)*/) {
					return (i);
				}

				/** Matching for ICMP incoming datagrams
				 * In this case the IP passes is actually the source IP of that incoming message (Or called the host)
				 */
				else if ((daemonSockets[i].protocol == protocol) && (protocol == IPPROTO_ICMP) && (daemonSockets[i].dst_ip == dstip)) {
					return (i);

				} else {
				}
			}
		}
	} // end of for loop

	return (-1);

}

int match_daemon_connection(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, int protocol) {
	PRINT_DEBUG("Entered: %u/%u to %u/%u", host_ip, host_port, rem_ip, rem_port);

	int i;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].uniqueSockID != -1 && daemonSockets[i].host_ip == host_ip && daemonSockets[i].host_port == host_port
				&& daemonSockets[i].dst_ip == rem_ip && daemonSockets[i].dst_port == rem_port && daemonSockets[i].protocol == protocol) {
			PRINT_DEBUG("Matched connection index=%d", i);
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
int insert_daemonSocket(uint64_t uniqueSockID, int index, int type, int protocol) {
	if (daemonSockets[index].uniqueSockID == -1) {
		daemonSockets[index].uniqueSockID = uniqueSockID;
		daemonSockets[index].state = SS_UNCONNECTED;

		sem_init(&daemonSockets[index].sem, 0, 1);

		/**
		 * bind the socket by default to the default IP which is assigned
		 * to the Interface which was already started by the Capturing and Injecting process
		 * The IP default value it supposed to be acquired from the configuration file
		 * The allowable ports range is supposed also to be aquired the same way
		 */
		daemonSockets[index].host_ip = 0;
		/**
		 * The host port is initially assigned randomly and stay the same unless
		 * binding explicitly later
		 */
		daemonSockets[index].host_port = 0;
		daemonSockets[index].dst_ip = 0;
		daemonSockets[index].dst_port = 0;
		/** Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM
		 * it has nothing to do with layer 4 protocols like TCP, UDP , etc
		 */

		daemonSockets[index].type = type; // & (SOCK_DGRAM | SOCK_STREAM);
		daemonSockets[index].blockingFlag = 1;
		daemonSockets[index].protocol = protocol;
		daemonSockets[index].backlog = DEFAULT_BACKLOG;

		sem_init(&daemonSockets[index].Qs, 0, 1);

		daemonSockets[index].controlQueue = init_queue(NULL, MAX_Queue_size);
		sem_init(&daemonSockets[index].control_sem, 0, 0);

		daemonSockets[index].dataQueue = init_queue(NULL, MAX_Queue_size);
		sem_init(&daemonSockets[index].data_sem, 0, 0);
		daemonSockets[index].buf_data = 0;

		sprintf(daemonSockets[index].name, "socket# %llu", daemonSockets[index].uniqueSockID);

		errno = 0;
		PRINT_DEBUG("errno is %d", errno);

		daemonSockets[index].threads = 0;
		daemonSockets[index].replies = 0;

		daemonSockets[index].sockopts.FSO_REUSEADDR = 0;

		return 0;
	} else {
		PRINT_DEBUG("index in use: index=%d", index);
		return (-1);
	}
}

/**
 * @brief remove a daemon socket from
 * the daemon sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int remove_daemonSocket(uint64_t uniqueSockID, int index) {

	int i = 0;
	int THREADS = 100;

	if (daemonSockets[index].uniqueSockID == uniqueSockID) {
		daemonSockets[index].uniqueSockID = -1;

		//TODO stop all threads related to

		for (i = 0; i < THREADS; i++) {
			sem_post(&daemonSockets[index].control_sem);
		}

		for (i = 0; i < THREADS; i++) {
			sem_post(&daemonSockets[index].data_sem);
		}

		daemonSockets[index].state = SS_FREE;
		term_queue(daemonSockets[index].controlQueue);
		term_queue(daemonSockets[index].dataQueue);
		return (1);
	} else {
		return 0;
	}
}

/**
 * @brief check if this host port is free or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found previously-allocated)
 */

int check_daemon_ports(uint16_t hostport, uint32_t hostip) {

	int i = 0;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].host_ip == INADDR_ANY) {
			if (daemonSockets[i].host_port == hostport)
				return (0);

		} else {
			if ((daemonSockets[i].host_port == hostport) && (daemonSockets[i].host_ip == hostip))
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

	for (i = 0; i < MAX_SOCKETS; i++) {
		if ((daemonSockets[i].dst_port == dstport) && (daemonSockets[i].dst_ip == dstip))
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

int nack_send(uint64_t uniqueSockID, int index, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d nack %d", uniqueSockID, call_type, NACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	u_char *buf = (u_char *) malloc(buf_len);
	if (buf == NULL) {
		PRINT_ERROR("ERROR: buf alloc fail");
		exit(-1);
	}

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = NACK;
	hdr->msg = msg;

	ret_val = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret_val == 1; //TODO change to ret_val ?
}

int ack_send(uint64_t uniqueSockID, int index, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra params
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d ack %d", uniqueSockID, call_type, ACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	u_char *buf = (u_char *) malloc(buf_len);
	if (buf == NULL) {
		PRINT_ERROR("ERROR: buf alloc fail");
		exit(-1);
	}

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = ACK;
	hdr->msg = msg;

	ret_val = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret_val == 1; //TODO change to ret_val ?
}

int get_fdf(int index, uint64_t uniqueSockID, struct finsFrame **ff, int non_blocking_flag) {
	if (index < 0) {
		return 0;
	}

	if (non_blocking_flag) {
		int val;
		sem_getvalue(&daemonSockets[index].data_sem, &val);
		//sem_trywait(daemonSockets[index].Qs);

		if (val) {
			sem_wait(&daemonSockets_sem);
			if (daemonSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&daemonSockets_sem);
				return 0;
			}
			sem_wait(&(daemonSockets[index].Qs));
			*ff = read_queue(daemonSockets[index].dataQueue);
			//ff = get_fake_frame();
			if (*ff) {
				daemonSockets[index].buf_data -= (*ff)->dataFrame.pduLength;
				//print_finsFrame(ff);
			}
			sem_post(&(daemonSockets[index].Qs));
			sem_post(&daemonSockets_sem);
		}
	} else {
		sem_wait(&daemonSockets[index].data_sem);

		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&daemonSockets_sem);
			return 0;
		}

		sem_wait(&(daemonSockets[index].Qs));
		*ff = read_queue(daemonSockets[index].dataQueue);
		//ff = get_fake_frame();

		if (*ff) {
			daemonSockets[index].buf_data -= (*ff)->dataFrame.pduLength;
			//print_finsFrame(ff);
		}
		sem_post(&(daemonSockets[index].Qs));
		sem_post(&daemonSockets_sem);
	}

	return 1;
}

int get_fcf(int index, uint64_t uniqueSockID, struct finsFrame **ff, int non_blocking_flag) {
	if (index < 0) {
		return 0;
	}

	if (non_blocking_flag) {
		int val = 0;
		sem_getvalue(&daemonSockets[index].control_sem, &val);

		if (val) {
			sem_wait(&daemonSockets_sem);
			if (daemonSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&daemonSockets_sem);
				return 0;
			}

			sem_wait(&(daemonSockets[index].Qs));
			*ff = read_queue(daemonSockets[index].controlQueue);
			//ff = get_fake_frame();
			//print_finsFrame(ff);
			sem_post(&(daemonSockets[index].Qs));
			sem_post(&daemonSockets_sem);
		}
	} else {
		sem_wait(&daemonSockets[index].control_sem);

		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&daemonSockets_sem);
			return 0;
		}

		sem_wait(&(daemonSockets[index].Qs));
		*ff = read_queue(daemonSockets[index].controlQueue);
		//ff = get_fake_frame();
		//print_finsFrame(ff);
		sem_post(&(daemonSockets[index].Qs));
		sem_post(&daemonSockets_sem);
	}

	return 1;
}

int daemon_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p meta=%p", ff, ff->metaData);
	if (sem_wait(&Daemon_to_Switch_Qsem)) {
		PRINT_ERROR("TCP_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, Daemon_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&Daemon_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&Daemon_to_Switch_Qsem);

	return 0;
}

void socket_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	int domain;
	int type;
	int protocol;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	domain = *(int *) pt;
	pt += sizeof(int);

	type = *(int *) pt;
	pt += sizeof(int);

	protocol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, socket_call, 0);
		return;
	}

	PRINT_DEBUG("domain=%d, type=%u, protocol=%d", domain, type, protocol);

	PRINT_DEBUG("%d,%d,%u", domain, protocol, type);
	if (domain != AF_INET) {
		PRINT_DEBUG("Wrong domain, only AF_INET us supported");
		nack_send(uniqueSockID, index, call_id, call_index, socket_call, 0);
		return;
	}

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		socket_udp(uniqueSockID, index, call_id, call_index, domain, type, protocol);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		socket_tcp(uniqueSockID, index, call_id, call_index, domain, type, protocol);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) { //is proto==icmp needed?
		socket_icmp(uniqueSockID, index, call_id, call_index, domain, type, protocol);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, socket_call, 0);
	}
}

/** ----------------------------------------------------------
 * End of socket_call_handler
 */

void bind_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	socklen_t addr_len;
	struct sockaddr_in *addr;
	u_char * pt;
	int reuseaddr;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addr_len);
		nack_send(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	} else {
		PRINT_DEBUG("addr_len=%d", addr_len);
	}

	addr = (struct sockaddr_in *) malloc(addr_len);
	if (addr == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}
	memcpy(addr, pt, addr_len);
	pt += addr_len;

	reuseaddr = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	PRINT_DEBUG("addr=%u/%d family=%d, reuseaddr=%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, reuseaddr);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	daemonSockets[index].sockopts.FSO_REUSEADDR |= reuseaddr; //TODO: when sockopts fully impelmented just set to '='

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		bind_udp(uniqueSockID, index, call_id, call_index, addr);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		bind_tcp(uniqueSockID, index, call_id, call_index, addr);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) { //is proto==icmp needed?
		bind_icmp(uniqueSockID, index, call_id, call_index, addr);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, bind_call, 0);
	}

	return;

} //end of bind_call_handler()
/** ----------------------------------------------------------
 * ------------------End of bind_call_handler-----------------
 */

void listen_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	int backlog;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	backlog = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, listen_call, 0);
		return;
	}

	PRINT_DEBUG("backlog=%d", backlog);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, listen_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		listen_udp(uniqueSockID, index, call_id, call_index, backlog);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		listen_tcp(uniqueSockID, index, call_id, call_index, backlog);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		listen_icmp(uniqueSockID, index, call_id, call_index, backlog);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, listen_call, 0);
	}
}

void connect_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	socklen_t addrlen;
	struct sockaddr_in *addr;
	int flags;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(uniqueSockID, index, call_id, call_index, connect_call, 0);
		return;
	}

	addr = (struct sockaddr_in *) malloc(addrlen);
	if (addr == NULL) {
		PRINT_ERROR("todo error");
		exit(-1);
	}

	memcpy(addr, pt, addrlen);
	pt += addrlen;

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, connect_call, 0);
		return;
	}

	PRINT_DEBUG("addr=%u/%d family=%d flags=%x", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, flags);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, connect_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		connect_udp(uniqueSockID, index, call_id, call_index, addr, flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		connect_tcp(uniqueSockID, index, call_id, call_index, addr, flags);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		connect_icmp(uniqueSockID, index, call_id, call_index, addr, flags);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, connect_call, 0);
	}
}

void accept_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	uint64_t uniqueSockID_new;
	int index_new;
	int flags;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	uniqueSockID_new = *(uint64_t *) pt;
	pt += sizeof(unsigned long long);

	index_new = *(int *) pt;
	pt += sizeof(int);

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		accept_udp(uniqueSockID, index, call_id, call_index, uniqueSockID_new, index_new, flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		accept_tcp(uniqueSockID, index, call_id, call_index, uniqueSockID_new, index_new, flags); //TODO finish
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		accept_icmp(uniqueSockID, index, call_id, call_index, uniqueSockID_new, index_new, flags);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, accept_call, 0);
	}
}

void getname_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	int peer;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	peer = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		getname_udp(uniqueSockID, index, call_id, call_index, peer);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		getname_tcp(uniqueSockID, index, call_id, call_index, peer);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getname_icmp(uniqueSockID, index, call_id, call_index, peer);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, getname_call, 0);
	}
}

void ioctl_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t buf_len) {
	uint32_t cmd;
	u_char * pt;
	u_char *temp;
	int len;
	int msg_len;
	u_char *msg = NULL;
	struct nl_daemon_to_wedge *hdr;
	struct sockaddr_in addr;
	struct ifreq ifr;
	int total;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, buf_len);

	pt = buf;

	cmd = *(uint32_t *) pt;
	pt += sizeof(u_int);

	switch (cmd) {
	case SIOCGIFCONF:
		//TODO implement: http://lxr.linux.no/linux+v2.6.39.4/net/core/dev.c#L3919, http://lxr.linux.no/linux+v2.6.39.4/net/ipv4/devinet.c#L926
		len = *(int *) pt;
		pt += sizeof(int);

		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFCONF), len=%d", cmd, len);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + 3 * sizeof(struct ifreq);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		temp = pt; //store ptr to where total should be stored
		pt += sizeof(int);

		//TODO implement a looped version of this that's taken from where interface/device info will be stored
		total = 0;
		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "lo");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(IP4_ADR_P2H(127, 0, 0, 1));
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "eth1");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(IP4_ADR_P2H(10, 0, 2, 15));
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "eth0");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(IP4_ADR_P2H(192, 168, 1, 20));
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		*(int *) temp = total;
		PRINT_DEBUG("total=%d (%d)", total, total/32);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	case SIOCGIFADDR:
		len = *(int *) pt;
		pt += sizeof(int);

		temp = malloc(len);
		if (temp == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFADDR), len=%d temp=%s", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(192, 168, 1, 20));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(10, 0, 2, 15));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(127, 0, 0, 1));
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("%s", temp);
		}

		PRINT_DEBUG("temp=%s addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (u_char *) malloc(msg_len);
		if (!msg) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	case SIOCGIFDSTADDR:
		len = *(int *) pt;
		pt += sizeof(int);

		temp = malloc(len);
		if (temp == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFDSTADDR), len=%d temp=%s", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(192, 168, 1, 20));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(10, 0, 2, 15));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(127, 0, 0, 1));
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("%s", temp);
		}

		PRINT_DEBUG("temp=%s addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	case SIOCGIFBRDADDR:
		len = *(int *) pt;
		pt += sizeof(int);

		temp = malloc(len);
		if (temp == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFBRDADDR), len=%d temp=%s", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(192, 168, 1, 255));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(10, 0, 2, 255));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(0, 0, 0, 0));
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("%s", temp);
		}

		PRINT_DEBUG("temp=%s addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	case SIOCGIFNETMASK:
		len = *(int *) pt;
		pt += sizeof(int);

		temp = malloc(len);
		if (temp == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFNETMASK), len=%d temp=%s", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, "eth0") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(255, 255, 255, 0));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "eth1") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(255, 255, 255, 0));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(IP4_ADR_P2H(255, 0, 0, 0));
			addr.sin_port = 0;
		} else {
			PRINT_DEBUG("%s", temp);
		}

		PRINT_DEBUG("temp=%s addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			exit(-1);
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	case FIONREAD:
		msg_len = 0; //handle per socket/protocol
		break;
	case TIOCOUTQ:
		//case TIOCINQ: //equiv to FIONREAD??
	case SIOCADDRT:
	case SIOCDELRT:
	case SIOCSIFADDR:
		//case SIOCAIPXITFCRT:
		//case SIOCAIPXPRISLT:
		//case SIOCIPXCFGDATA:
		//case SIOCIPXNCPCONN:
	case SIOCGSTAMP:
	case SIOCSIFDSTADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
		//TODO
		PRINT_DEBUG("not implemented: cmd=%d", cmd);
		if (pt - buf != buf_len) {
			PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, buf_len);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	default:
		PRINT_DEBUG("cmd=%d default", cmd);
		break;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exiting, fail send_wedge: uniqueSockID=%llu", uniqueSockID);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
		}
		free(msg);
	} else {
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
			sem_post(&daemonSockets_sem);

			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		int type = daemonSockets[index].type;
		int protocol = daemonSockets[index].protocol;

		PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
		sem_post(&daemonSockets_sem);

		if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
			ioctl_udp(uniqueSockID, index, call_id, call_index, cmd, buf, buf_len);
		} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
			ioctl_tcp(uniqueSockID, index, call_id, call_index, cmd, buf, buf_len);
		} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
			ioctl_icmp(uniqueSockID, index, call_id, call_index, cmd, buf, buf_len);
		} else {
			PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
			nack_send(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
		}
	}
}

void sendmsg_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	int addr_len;
	struct sockaddr_in *addr;
	uint32_t msg_flags;
	uint32_t msg_controllen;
	void *msg_control;
	uint32_t data_len;
	u_char *data;
	u_char *pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len > 0) {
		if (addr_len >= sizeof(struct sockaddr_in)) {
			addr = (struct sockaddr_in *) malloc(addr_len);
			if (addr == NULL) {
				PRINT_ERROR("allocation fail");
				nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
				exit(-1);
			}

			memcpy(addr, pt, addr_len);
			pt += addr_len;

			PRINT_DEBUG("addr_len=%d addr=%s/%d", addr_len, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		} else {
			//TODO error?
			PRINT_DEBUG("addr_len=%d", addr_len);
		}
	}

	msg_flags = *(uint32_t *) pt;
	pt += sizeof(u_int);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(u_int);

	msg_control = malloc(msg_controllen);
	if (msg_control == NULL) {
		PRINT_ERROR("allocation fail");
		nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		exit(-1);
	}

	memcpy(msg_control, pt, msg_controllen);
	pt += msg_controllen;

	data_len = *(uint32_t *) pt;
	pt += sizeof(u_int);

	data = (u_char *) malloc(data_len);
	if (data == NULL) {
		PRINT_ERROR("allocation fail");
		nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		exit(-1);
	}

	memcpy(data, pt, data_len);
	pt += data_len;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	//#########################
	u_char *temp = (u_char *) malloc(data_len + 1);
	memcpy(temp, data, data_len);
	temp[data_len] = '\0';
	PRINT_DEBUG("data='%s'", temp);
	free(temp);
	//#########################
	u_char *temp2 = (u_char *) malloc(msg_controllen + 1);
	memcpy(temp2, msg_control, msg_controllen);
	temp2[msg_controllen] = '\0';
	PRINT_DEBUG("msg_control='%s'", temp2);
	free(temp2);
	//#########################

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		sendmsg_udp(uniqueSockID, index, call_id, call_index, data, data_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		sendmsg_tcp(uniqueSockID, index, call_id, call_index, data, data_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		sendmsg_icmp(uniqueSockID, index, call_id, call_index, data, data_len, msg_flags, addr, addr_len);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	}
}

void recvmsg_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	int data_len;
	int flags;
	uint32_t msg_flags;
	uint32_t msg_controllen;
	void *msg_control;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	data_len = *(int *) pt; //check on not in original socket_interceptor: recvmsg
	pt += sizeof(int);

	flags = *(int *) pt;
	pt += sizeof(int);

	msg_flags = *(uint32_t *) pt;
	pt += sizeof(u_int);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(u_int);

	msg_control = (u_char *) malloc(msg_controllen);
	if (msg_control == NULL) {
		PRINT_ERROR("allocation error");
		nack_send(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		exit(-1);
	}

	memcpy(msg_control, pt, msg_controllen);
	pt += msg_controllen;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		return;
	}

	PRINT_DEBUG("flags=0x%x msg_flags=0x%x msg_controllen=%u", flags, msg_flags, msg_controllen);

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		recvmsg_udp(uniqueSockID, index, call_id, call_index, data_len, flags, msg_flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		recvmsg_tcp(uniqueSockID, index, call_id, call_index, data_len, flags, msg_flags);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		recvmsg_icmp(uniqueSockID, index, call_id, call_index, data_len, flags, msg_flags);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
	}
}

void getsockopt_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = *(int *) pt;
	pt += sizeof(int);

	if (optlen > 0) { //TODO remove?
		optval = (u_char *) malloc(optlen);
		if (optval == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			exit(-1);
		}
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		getsockopt_udp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		getsockopt_tcp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getsockopt_icmp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
	}
}

void setsockopt_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = (int) *(unsigned int *) pt;
	pt += sizeof(unsigned int);

	if (optlen > 0) {
		optval = (u_char *) malloc(optlen);
		if (optval == NULL) {
			PRINT_ERROR("todo error");
			nack_send(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
			exit(-1);
		}
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		return;
	}

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		setsockopt_udp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		setsockopt_tcp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		setsockopt_icmp(uniqueSockID, index, call_id, call_index, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
	}
}

void release_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, release_call, 0);
		return;
	}

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, release_call, 0);
		return;
	}
	//daemonSockets[index].threads = threads;

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		release_udp(uniqueSockID, index, call_id, call_index);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		release_tcp(uniqueSockID, index, call_id, call_index);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		release_icmp(uniqueSockID, index, call_id, call_index);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, release_call, 0);
	}
}

void poll_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	u_char * pt;
	int events;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);
	pt = buf;

	events = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, poll_call, 0);
		return;
	}

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, poll_call, 0);
		return;
	}
	//daemonSockets[index].threads = threads;

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		poll_udp_out(uniqueSockID, index, call_id, call_index, events);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		poll_tcp(uniqueSockID, index, call_id, call_index, events);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		poll_icmp(uniqueSockID, index, call_id, call_index, events);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, poll_call, 0);
	}
}

void mmap_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {
	u_char * pt;
	pt = buf;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
		return;
	}

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
		return;
	}
	//daemonSockets[index].threads = threads;

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		//mmap_udp(uniqueSockID, index, call_id, call_index);
		PRINT_DEBUG("implement mmap_udp");
		ack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		//mmap_tcp(uniqueSockID, index, call_id, call_index);
		PRINT_DEBUG("implement mmap_tcp");
		ack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		//mmap_icmp(uniqueSockID, index, call_id, call_index);
		PRINT_DEBUG("implement mmap_icmp");
		ack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
	} else {
		PRINT_DEBUG("non supported socket type=%d protocol=%d", type, protocol);
		nack_send(uniqueSockID, index, call_id, call_index, mmap_call, 0);
	}
}

void socketpair_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

}

void shutdown_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	int how;
	u_char * pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	pt = buf;

	how = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, index, call_id, call_index, shutdown_call, 0);
		return;
	}

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, shutdown_call, 0);
		return;
	}
	//daemonSockets[index].threads = threads;

	int type = daemonSockets[index].type;
	int protocol = daemonSockets[index].protocol;

	PRINT_DEBUG("uniqueSockID=%llu, index=%d, type=%d, proto=%d", uniqueSockID, index, type, protocol);
	sem_post(&daemonSockets_sem);

	if (type == SOCK_DGRAM && protocol == IPPROTO_IP) {
		shutdown_udp(uniqueSockID, index, call_id, call_index, how);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		shutdown_tcp(uniqueSockID, index, call_id, call_index, how);
	} else if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		shutdown_icmp(uniqueSockID, index, call_id, call_index, how);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, index, call_id, call_index, shutdown_call, 0);
	}
}

void close_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into daemon sockets! Bind failed on Daemon Side ");
		//sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, index, call_id, call_index, close_call, 0);
		return;
	}

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
	if (remove_daemonSocket(uniqueSockID, index)) {
		ack_send(uniqueSockID, index, call_id, call_index, close_call, 0);
	} else {
		nack_send(uniqueSockID, index, call_id, call_index, close_call, 0);
	}
}

void sendpage_call_handler(uint64_t uniqueSockID, int index, int call_threads, uint32_t call_id, int call_index, u_char *buf, ssize_t len) {

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d threads=%d id=%u index=%d len=%d", uniqueSockID, index, call_threads, call_id, call_index, len);

}

int daemon_setNonblocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int daemon_setBlocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0; //TODO verify is right?
	return ioctl(fd, FIOBIO, &flags);
#endif
}

void *wedge_to_daemon(void *local) {
	int ret_val;

	// Begin receive message section
	// Allocate a buffer to hold contents of recvfrom call
	void *recv_buf;
	recv_buf = malloc(RECV_BUFFER_SIZE + 16); //16 = NLMSGHDR size
	if (recv_buf == NULL) {
		PRINT_ERROR("buffer allocation failed");
		exit(-1);
	}

	struct sockaddr sockaddr_sender; // Needed for recvfrom
	socklen_t sockaddr_senderlen = sizeof(sockaddr_sender); // Needed for recvfrom
	memset(&sockaddr_sender, 0, sockaddr_senderlen);

	struct nlmsghdr *nlh;
	void *nl_buf; // Pointer to your actual data payload
	ssize_t nl_len, part_len; // Size of your actual data payload
	u_char *part_pt;

	u_char *msg_buf = NULL;
	ssize_t msg_len = -1;
	u_char *msg_pt = NULL;

	struct nl_wedge_to_daemon *hdr;
	int okFlag, doneFlag = 0;
	ssize_t test_msg_len;

	int pos;

	uint64_t uniqueSockID;
	int index;
	uint32_t call_type; //Integer representing what socketcall type was placed (for testing purposes)
	int call_threads;
	uint32_t call_id;
	int call_index;

	PRINT_DEBUG("Waiting for message from kernel\n");

	int counter = 0;
	while (daemon_running) {
		PRINT_DEBUG("NL counter = %d", counter++);

		daemon_setNonblocking(nl_sockfd);
		do {
			ret_val = recvfrom(nl_sockfd, recv_buf, RECV_BUFFER_SIZE + 16, 0, &sockaddr_sender, &sockaddr_senderlen); //TODO change to nonblocking in loop
		} while (daemon_running && ret_val <= 0);

		if (!daemon_running) {
			break;
		}

		daemon_setBlocking(nl_sockfd);

		if (ret_val == -1) {
			perror("recvfrom() caused an error");
			exit(-1);
		}
		//PRINT_DEBUG("%d", sockaddr_sender);

		nlh = (struct nlmsghdr *) recv_buf;

		if ((okFlag = NLMSG_OK(nlh, ret_val))) {
			switch (nlh->nlmsg_type) {
			case NLMSG_NOOP:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_NOOP");
				break;
			case NLMSG_ERROR:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_ERROR");
			case NLMSG_OVERRUN:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_OVERRUN");
				okFlag = 0;
				break;
			case NLMSG_DONE:
				PRINT_DEBUG("nlh->nlmsg_type=NLMSG_DONE");
				doneFlag = 1;
			default:
				PRINT_DEBUG("nlh->nlmsg_type=default");
				nl_buf = NLMSG_DATA(nlh);
				nl_len = NLMSG_PAYLOAD(nlh, 0);

				PRINT_DEBUG("nl_len= %d", nl_len);

				part_pt = nl_buf;
				test_msg_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);

				//PRINT_DEBUG("test_msg_len=%d, msg_len=%d", test_msg_len, msg_len);

				if (msg_len == -1) {
					msg_len = test_msg_len;
				} else if (test_msg_len != msg_len) {
					okFlag = 0;
					PRINT_DEBUG("test_msg_len != msg_len");
					//could just malloc msg_buff again
					break;//might comment out or make so start new
				}

				part_len = *(ssize_t *) part_pt;
				part_pt += sizeof(ssize_t);
				if (part_len > RECV_BUFFER_SIZE) {
					PRINT_DEBUG("part_len (%d) > RECV_BUFFER_SIZE (%d)", part_len, RECV_BUFFER_SIZE);
				}

				//PRINT_DEBUG("part_len=%d", part_len);

				pos = *(int *) part_pt;
				part_pt += sizeof(int);
				if (pos > msg_len || pos != msg_pt - msg_buf) {
					if (pos > msg_len) {
						PRINT_DEBUG("pos > msg_len");
					} else {
						PRINT_DEBUG("pos != msg_pt - msg_buf");
					}
				}

				//PRINT_DEBUG("pos=%d", pos);

				PRINT_DEBUG("msg_len=%d part_len=%d pos=%d seq=%d", msg_len, part_len, pos, nlh->nlmsg_seq);

				if (nlh->nlmsg_seq == 0) {
					if (msg_buf != NULL) {
						PRINT_DEBUG("error: msg_buf != NULL at new sequence, freeing");
						free(msg_buf);
					}
					msg_buf = (u_char *) malloc(msg_len);
					if (msg_buf == NULL) {
						PRINT_ERROR("msg buffer allocation failed");
						exit(-1);
					}
					msg_pt = msg_buf;
				}

				if (msg_pt != NULL) {
					msg_pt = msg_buf + pos; //atm redundant, is for if out of sync msgs
					memcpy(msg_pt, part_pt, part_len);
					msg_pt += part_len;
				} else {
					PRINT_DEBUG("error: msg_pt is NULL");
				}

				if ((nlh->nlmsg_flags & NLM_F_MULTI) == 0) {
					//doneFlag = 1; //not multi-part msg //removed multi
				}
				break;
			}
		}

		if (okFlag != 1) {
			doneFlag = 0;
			PRINT_DEBUG("okFlag != 1");
			//send kernel a resend request
			//with pos of part being passed can store msg_buf, then recopy new part when received
		}

		if (doneFlag) {
			if (msg_len < sizeof(struct nl_wedge_to_daemon)) {
				//TODOD error
				PRINT_DEBUG("todo error");
			}

			hdr = (struct nl_wedge_to_daemon *) msg_buf;
			uniqueSockID = hdr->sock_id;
			index = hdr->sock_index;
			call_type = hdr->call_type;
			call_threads = hdr->call_threads;
			call_id = hdr->call_id;
			call_index = hdr->call_index;

			msg_pt = msg_buf + sizeof(struct nl_wedge_to_daemon);
			msg_len -= sizeof(struct nl_wedge_to_daemon);

			PRINT_DEBUG("callType=%d sockID=%llu", call_type, uniqueSockID);
			PRINT_DEBUG("msg_len=%d", msg_len);

			//############################### Debug
			unsigned char *temp;
			temp = (unsigned char *) malloc(msg_len + 1);
			memcpy(temp, msg_pt, msg_len);
			temp[msg_len] = '\0';
			PRINT_DEBUG("msg='%s'", temp);
			free(temp);

			unsigned char *pt;
			temp = (unsigned char *) malloc(3 * msg_len + 1);
			pt = temp;
			int i;
			for (i = 0; i < msg_len; i++) {
				if (i == 0) {
					sprintf((char *) pt, "%02x", msg_pt[i]);
					pt += 2;
				} else if (i % 4 == 0) {
					sprintf((char *) pt, ":%02x", msg_pt[i]);
					pt += 3;
				} else {
					sprintf((char *) pt, " %02x", msg_pt[i]);
					pt += 3;
				}
			}
			temp[3 * msg_len] = '\0';
			PRINT_DEBUG("msg='%s'", temp);
			free(temp);
			//###############################

			PRINT_DEBUG("uniqueSockID=%llu, calltype=%d, threads=%d", uniqueSockID, call_type, call_threads);

			switch (call_type) {
			case socket_call:
				socket_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case bind_call:
				bind_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case listen_call:
				listen_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case connect_call:
				connect_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case accept_call:
				accept_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case getname_call:
				getname_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case ioctl_call:
				ioctl_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case sendmsg_call:
				sendmsg_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO finish
				break;
			case recvmsg_call:
				recvmsg_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case getsockopt_call:
				getsockopt_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case setsockopt_call:
				setsockopt_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case release_call:
				release_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case poll_call:
				poll_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case mmap_call:
				mmap_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
				break;
			case socketpair_call:
				socketpair_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
				break;
			case shutdown_call:
				shutdown_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len); //TODO dummy
				break;
			case close_call:
				/**
				 * TODO fix the problem into remove daemonsockets
				 * the Queue Terminate function has a bug as explained into it
				 */
				close_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			case sendpage_call:
				sendpage_call_handler(uniqueSockID, index, call_threads, call_id, call_index, msg_pt, msg_len);
				break;
			default:
				PRINT_DEBUG("unknown opcode received (%d), dropping", call_type);
				/** a function must be called to clean and reset the pipe
				 * to original conditions before crashing
				 */
				//exit(1);
				break;
			}

			free(msg_buf);
			doneFlag = 0;
			msg_buf = NULL;
			msg_pt = NULL;
			msg_len = -1;
		}
	}

	free(recv_buf);
	close(nl_sockfd);

	PRINT_DEBUG("Exiting");
	pthread_exit(NULL);
}

void *switch_to_daemon(void *local) {
	while (daemon_running) {
		daemon_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_DEBUG("Exiting");
	pthread_exit(NULL);
}

void daemon_get_ff(void) {
	struct finsFrame *ff;

	do {
		sem_wait(&Switch_to_Daemon_Qsem);
		ff = read_queue(Switch_to_Daemon_Queue);
		sem_post(&Switch_to_Daemon_Qsem);
	} while (daemon_running && ff == NULL);

	if (!daemon_running) {
		return;
	}

	if (ff->dataOrCtrl == CONTROL) {
		daemon_fcf(ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		if (ff->dataFrame.directionFlag == UP) {
			daemon_in_fdf(ff);
			PRINT_DEBUG("");
		} else { //directionFlag==DOWN
			//daemon_out_fdf(ff); //TODO remove?
			PRINT_DEBUG("todo error");
		}
	} else {
		PRINT_DEBUG("todo error");
	}
}

void daemon_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p", ff);

	//TODO fill out
	switch (ff->ctrlFrame.opcode) {
	case CTRL_ALERT:
		PRINT_DEBUG("opcode=CTRL_ALERT (%d)", CTRL_ALERT);
		break;
	case CTRL_ALERT_REPLY:
		PRINT_DEBUG("opcode=CTRL_ALERT_REPLY (%d)", CTRL_ALERT_REPLY);
		break;
	case CTRL_READ_PARAM:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM (%d)", CTRL_READ_PARAM);
		break;
	case CTRL_READ_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_READ_PARAM_REPLY (%d)", CTRL_READ_PARAM_REPLY);
		daemon_read_param_reply(ff);
		break;
	case CTRL_SET_PARAM:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM (%d)", CTRL_SET_PARAM);
		break;
	case CTRL_SET_PARAM_REPLY:
		PRINT_DEBUG("opcode=CTRL_SET_PARAM_REPLY (%d)", CTRL_SET_PARAM_REPLY);
		break;
	case CTRL_EXEC:
		PRINT_DEBUG("opcode=CTRL_EXEC (%d)", CTRL_EXEC);
		break;
	case CTRL_EXEC_REPLY:
		PRINT_DEBUG("opcode=CTRL_EXEC_REPLY (%d)", CTRL_EXEC_REPLY);
		daemon_exec_reply(ff);
		break;
	case CTRL_ERROR:
		PRINT_DEBUG("opcode=CTRL_ERROR (%d)", CTRL_ERROR);
		break;
	default:
		PRINT_DEBUG("opcode=default (%d)", ff->ctrlFrame.opcode);
		break;
	}
}

void daemon_read_param_reply(struct finsFrame *ff) {
	int protocol = 0;
	int index = 0;
	socket_state state = 0;
	//uint32_t exec_call = 0;
	//uint16_t dstport, hostport = 0;
	//uint32_t dstport_buf = 0, hostport_buf = 0;
	//uint32_t dstip = 0, hostip = 0;
	uint32_t host_ip = 0, host_port = 0, rem_ip = 0, rem_port = 0;

	if (ff->metaData) {
		metadata *params = ff->metaData;
		int ret = 0;
		ret += metadata_readFromElement(params, "state", &state) == CONFIG_FALSE;

		if (state > SS_UNCONNECTED) {
			ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "rem_port", &rem_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

			if (ret) {
				//TODO error
				PRINT_DEBUG("error ret=%d", ret);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("");
			sem_wait(&daemonSockets_sem);
			index = match_daemon_connection(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, protocol);
			if (index != -1) {
				PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
				sem_wait(&daemonSockets[index].Qs);

				/**
				 * TODO Replace The data Queue with a pipeLine at least for
				 * the RAW DATA in order to find a natural way to support
				 * Blocking and Non-Blocking mode
				 */
				if (write_queue(ff, daemonSockets[index].controlQueue)) {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].control_sem);
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
					freeFinsFrame(ff);
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&daemonSockets_sem);

				PRINT_DEBUG("No socket found, dropping");
				freeFinsFrame(ff);
			}
		} else {
			ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

			if (ret) {
				//TODO error
				PRINT_DEBUG("error ret=%d", ret);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("");
			sem_wait(&daemonSockets_sem);
			index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
			if (index != -1) {
				PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
				sem_wait(&daemonSockets[index].Qs);

				/**
				 * TODO Replace The data Queue with a pipeLine at least for
				 * the RAW DATA in order to find a natural way to support
				 * Blocking and Non-Blocking mode
				 */
				if (write_queue(ff, daemonSockets[index].controlQueue)) {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].control_sem);
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
					freeFinsFrame(ff);
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&daemonSockets_sem);

				PRINT_DEBUG("No socket found, dropping");
				freeFinsFrame(ff);
			}
		}
	} else {
		//TODO error
		PRINT_DEBUG("error");
		freeFinsFrame(ff);
	}
}

void daemon_exec_reply(struct finsFrame *ff) {
	int protocol = 0;
	int index = 0;
	socket_state state = 0;
	uint32_t exec_call = 0;
	//uint16_t dstport, hostport = 0;
	//uint32_t dstport_buf = 0, hostport_buf = 0;
	//uint32_t dstip = 0, hostip = 0;
	uint32_t host_ip = 0, host_port = 0, rem_ip = 0, rem_port = 0;

	if (ff->metaData) {
		metadata *params = ff->metaData;
		int ret = 0;
		ret += metadata_readFromElement(params, "state", &state) == CONFIG_FALSE;

		if (state > SS_UNCONNECTED) {
			ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "rem_ip", &rem_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "rem_port", &rem_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

			if (ret) {
				//TODO error
				PRINT_DEBUG("error ret=%d", ret);
				freeFinsFrame(ff);
				return;
			}

			//##################
			struct sockaddr_in *temp = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
			//memset(temp->sin_addr, 0, sizeof(struct sockaddr_in));
			if (host_ip) {
				temp->sin_addr.s_addr = (int) htonl(host_ip);
			} else {
				temp->sin_addr.s_addr = 0;
			}
			//temp->sin_port = 0;
			struct sockaddr_in *temp2 = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
			//memset(temp2, 0, sizeof(struct sockaddr_in));
			if (rem_ip) {
				temp2->sin_addr.s_addr = (int) htonl(rem_ip);
			} else {
				temp2->sin_addr.s_addr = 0;
			}
			//temp2->sin_port = 0;
			PRINT_DEBUG("host=%s/%d (%u)", inet_ntoa(temp->sin_addr), (host_port), temp->sin_addr.s_addr);
			PRINT_DEBUG("dst=%s/%d (%u)", inet_ntoa(temp2->sin_addr), (rem_port), temp2->sin_addr.s_addr);
			free(temp);
			free(temp2);
			//##################

			PRINT_DEBUG("");
			sem_wait(&daemonSockets_sem);
			index = match_daemon_connection(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, protocol);
			if (index != -1) {
				PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
				sem_wait(&daemonSockets[index].Qs);

				/**
				 * TODO Replace The data Queue with a pipeLine at least for
				 * the RAW DATA in order to find a natural way to support
				 * Blocking and Non-Blocking mode
				 */
				if (write_queue(ff, daemonSockets[index].controlQueue)) {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].control_sem);
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
					freeFinsFrame(ff);
				}
			} else {
				ret += metadata_readFromElement(params, "exec_call", &exec_call) == CONFIG_FALSE;
				ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

				if (ret == 0 && (exec_call == EXEC_TCP_CONNECT || exec_call == EXEC_TCP_ACCEPT)) {
					index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
					if (index != -1) {
						PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
						sem_wait(&daemonSockets[index].Qs);

						/**
						 * TODO Replace The data Queue with a pipeLine at least for
						 * the RAW DATA in order to find a natural way to support
						 * Blocking and Non-Blocking mode
						 */
						if (write_queue(ff, daemonSockets[index].controlQueue)) {
							PRINT_DEBUG("");
							sem_post(&daemonSockets[index].control_sem);
							PRINT_DEBUG("");
							sem_post(&daemonSockets[index].Qs);
							PRINT_DEBUG("");
							sem_post(&daemonSockets_sem);
						} else {
							PRINT_DEBUG("");
							sem_post(&daemonSockets[index].Qs);
							PRINT_DEBUG("");
							sem_post(&daemonSockets_sem);
							freeFinsFrame(ff);
						}
					} else {
						PRINT_DEBUG("");
						sem_post(&daemonSockets_sem);

						PRINT_DEBUG("No socket found, dropping");
						freeFinsFrame(ff);
					}
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);

					PRINT_DEBUG("No socket found, dropping");
					freeFinsFrame(ff);
				}
			}
		} else {
			ret += metadata_readFromElement(params, "host_ip", &host_ip) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "host_port", &host_port) == CONFIG_FALSE;
			ret += metadata_readFromElement(params, "protocol", &protocol) == CONFIG_FALSE;

			if (ret) {
				//TODO error
				PRINT_DEBUG("error ret=%d", ret);
				freeFinsFrame(ff);
				return;
			}

			//##################
			struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
			if (host_ip) {
				temp->s_addr = host_ip;
			} else {
				temp->s_addr = 0;
			}
			PRINT_DEBUG("NETFORMAT host=%s/%d", inet_ntoa(*temp), (host_port));
			PRINT_DEBUG("NETFORMAT host=%u/%d", (*temp).s_addr, (host_port));
			free(temp);
			//##################

			PRINT_DEBUG("");
			sem_wait(&daemonSockets_sem);
			index = match_daemon_connection(host_ip, (uint16_t) host_port, 0, 0, protocol);
			if (index != -1) {
				PRINT_DEBUG("Matched: ff=%p index=%d", ff, index);
				sem_wait(&daemonSockets[index].Qs);

				/**
				 * TODO Replace The data Queue with a pipeLine at least for
				 * the RAW DATA in order to find a natural way to support
				 * Blocking and Non-Blocking mode
				 */
				if (write_queue(ff, daemonSockets[index].controlQueue)) {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].control_sem);
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
				} else {
					PRINT_DEBUG("");
					sem_post(&daemonSockets[index].Qs);
					PRINT_DEBUG("");
					sem_post(&daemonSockets_sem);
					freeFinsFrame(ff);
				}
			} else {
				PRINT_DEBUG("");
				sem_post(&daemonSockets_sem);

				PRINT_DEBUG("No socket found, dropping");
				freeFinsFrame(ff);
			}
		}
	} else {
		//TODO error
		PRINT_DEBUG("error");
		freeFinsFrame(ff);
	}
}

void daemon_in_fdf(struct finsFrame *ff) {
	int protocol = 0;
	int index = 0;
	uint16_t dstport, hostport = 0;
	uint32_t dstport_buf = 0, hostport_buf = 0;
	uint32_t dstip = 0, hostip = 0;

	PRINT_DEBUG("data ff: ff=%p meta=%p len=%d", ff, ff->metaData, ff->dataFrame.pduLength);

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "src_ip", &hostip) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "src_port", &hostport_buf) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "dst_ip", &dstip) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "dst_port", &dstport_buf) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "protocol", &protocol) == CONFIG_FALSE;

	if (ret) {
		PRINT_ERROR("prob reading metadata ret=%d", ret);
		if (ff->dataFrame.pdu)
			free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	dstport = (uint16_t) dstport_buf;
	hostport = (uint16_t) hostport_buf;

	//##############################################
	struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	if (hostip) {
		temp->s_addr = htonl(hostip);
	} else {
		temp->s_addr = 0;
	}
	struct in_addr *temp2 = (struct in_addr *) malloc(sizeof(struct in_addr));
	if (dstip) {
		temp2->s_addr = htonl(dstip);
	} else {
		temp2->s_addr = 0;
	}
	PRINT_DEBUG("prot=%d, ff=%p", protocol, ff);
	PRINT_DEBUG("host=%s:%d (%u)", inet_ntoa(*temp), (hostport), (*temp).s_addr);
	PRINT_DEBUG("dst=%s:%d (%u)", inet_ntoa(*temp2), (dstport), (*temp2).s_addr);

	free(temp);
	free(temp2);
	//##############################################

	/**
	 * check if this received datagram destIP and destport matching which socket hostIP
	 * and hostport insidee our sockets database
	 */
	sem_wait(&daemonSockets_sem);
	if (protocol == IPPROTO_ICMP) {
		index = match_daemonSocket(0, hostip, protocol);
	} else if (protocol == IPPROTO_TCP /*TCP_PROTOCOL*/) {
		index = match_daemon_connection(hostip, hostport, dstip, dstport, protocol);
		if (index == -1) {
			index = match_daemon_connection(hostip, hostport, 0, 0, protocol);
		}
	} else { //udp
		index = match_daemonSocket(dstport, dstip, protocol); //TODO change for multicast

		//if (index != -1 && daemonSockets[index].connection_status > 0) { //TODO review this logic might be bad
		if (index != -1 && daemonSockets[index].state > SS_UNCONNECTED) { //TODO review this logic might be bad
			PRINT_DEBUG("ICMP should not enter here at all ff=%p", ff);
			if ((hostport != daemonSockets[index].dst_port) || (hostip != daemonSockets[index].dst_ip)) {
				PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
				sem_post(&daemonSockets_sem);

				if (ff->dataFrame.pdu)
					free(ff->dataFrame.pdu);
				freeFinsFrame(ff);
				return;
			}
		}
	}

	PRINT_DEBUG("ff=%p index=%d", ff, index);
	if (index != -1 && daemonSockets[index].uniqueSockID != -1) {
		PRINT_DEBUG( "Matched: host=%u/%u, dst=%u/%u, prot=%u",
				daemonSockets[index].host_ip, daemonSockets[index].host_port, daemonSockets[index].dst_ip, daemonSockets[index].dst_port, daemonSockets[index].protocol);

		/**
		 * check if this datagram comes from the address this socket has been previously
		 * connected to it (Only if the socket is already connected to certain address)
		 */

		int value;
		sem_getvalue(&(daemonSockets[index].Qs), &value);
		PRINT_DEBUG("sem: ind=%d, val=%d", index, value);
		sem_wait(&daemonSockets[index].Qs);

		/**
		 * TODO Replace The data Queue with a pipeLine at least for
		 * the RAW DATA in order to find a natural way to support
		 * Blocking and Non-Blocking mode
		 */
		if (write_queue(ff, daemonSockets[index].dataQueue)) {
			daemonSockets[index].buf_data += ff->dataFrame.pduLength;
			PRINT_DEBUG("");
			sem_post(&daemonSockets[index].data_sem);
			PRINT_DEBUG("");
			sem_post(&daemonSockets[index].Qs);
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			//PRINT_DEBUG("pdu=\"%s\"", ff->dataFrame.pdu);

			char *buf;
			buf = (char *) malloc(ff->dataFrame.pduLength + 1);
			if (buf == NULL) {
				PRINT_ERROR("error allocation");
				exit(-1);
			}
			memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
			buf[ff->dataFrame.pduLength] = '\0';
			PRINT_DEBUG("pdu='%s'", buf);
			free(buf);

			PRINT_DEBUG("pdu length %d", ff->dataFrame.pduLength);
		} else {
			PRINT_DEBUG("");
			sem_post(&daemonSockets[index].Qs);
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			if (ff->dataFrame.pdu)
				free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}
	} else {
		PRINT_DEBUG("No match, freeing ff");
		sem_post(&daemonSockets_sem);

		if (ff->dataFrame.pdu)
			free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
	}
}

/**
 * @brief initialize the daemon sockets array by filling with value of -1
 * @param
 * @return nothing
 */
void init_daemonSockets(void) {
	int i;

	sem_init(&daemonSockets_sem, 0, 1);
	for (i = 0; i < MAX_SOCKETS; i++) {
		daemonSockets[i].uniqueSockID = -1;
		daemonSockets[i].state = SS_FREE;
	}

	sem_init(&thread_sem, 0, 1);
	recv_thread_index = 0;
	thread_count = 0;
}

void daemon_init(void) {
	PRINT_DEBUG("Entered");
	daemon_running = 1;

	init_daemonSockets();

	//############# //TODO move to Daemon
	//init the netlink socket connection to daemon
	nl_sockfd = init_fins_nl();
	if (nl_sockfd == -1) {
		perror("init_fins_nl() caused an error");
		exit(-1);
	}

	//prime the kernel to establish daemon's PID
	int daemoncode = daemon_start_call;
	int ret_val;
	ret_val = send_wedge(nl_sockfd, (u_char *) &daemoncode, sizeof(int), 0);
	if (ret_val != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_DEBUG("Connected to wedge at %d", nl_sockfd);
	//#############

}

void daemon_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Entered");

	pthread_create(&wedge_to_daemon_thread, fins_pthread_attr, wedge_to_daemon, fins_pthread_attr);
	pthread_create(&switch_to_daemon_thread, fins_pthread_attr, switch_to_daemon, fins_pthread_attr);
}

void daemon_shutdown(void) {
	PRINT_DEBUG("Entered");
	daemon_running = 0;

	//prime the kernel to establish daemon's PID
	int daemoncode = daemon_stop_call;
	int ret_val;
	ret_val = send_wedge(nl_sockfd, (u_char *) &daemoncode, sizeof(int), 0);
	if (ret_val != 0) {
		perror("sendfins() caused an error");
		exit(-1);
	}
	PRINT_DEBUG("Disconnecting to wedge at %d", nl_sockfd);

	pthread_join(switch_to_daemon_thread, NULL);
	PRINT_DEBUG("Here");
	pthread_join(wedge_to_daemon_thread, NULL);
	PRINT_DEBUG("Here");
	//TODO expand this
}

void daemon_release(void) {
	PRINT_DEBUG("Entered");
	//TODO free all module related mem
	int i = 0, j = 0;
	int THREADS = 100;

	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemonSockets[i].uniqueSockID != -1) {
			daemonSockets[i].uniqueSockID = -1;

			//TODO stop all threads related to

			for (j = 0; j < THREADS; j++) {
				sem_post(&daemonSockets[i].control_sem);
			}

			for (j = 0; j < THREADS; j++) {
				sem_post(&daemonSockets[i].data_sem);
			}

			daemonSockets[i].state = SS_FREE;
			term_queue(daemonSockets[i].controlQueue);
			term_queue(daemonSockets[i].dataQueue);
		}
	}
}
