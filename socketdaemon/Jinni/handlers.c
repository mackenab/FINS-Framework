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

extern sem_t jinniSockets_sem;
extern struct finssocket jinniSockets[MAX_sockets];

extern int recv_thread_index;
extern int recv_thread_count;
extern sem_t recv_thread_sem;

/** The queues might be moved later to another Master file */

extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;
extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;

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
	ret_val = bind(sockfd, (struct sockaddr*) &local_sockaddress,
			sizeof(local_sockaddress));
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
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;

	// Begin send message section
	// Build a message to send to the kernel
	nlh = (struct nlmsghdr *) malloc(NLMSG_LENGTH(len));
	memset(nlh, 0, NLMSG_LENGTH(len));

	nlh->nlmsg_len = NLMSG_LENGTH(len);
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0; // arbitrary value
	nlh->nlmsg_seq = 0; // sequence number
	nlh->nlmsg_pid = getpid(); // pthread_self() << 16 | getpid();	// use the second one for multiple threads
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
	PRINT_DEBUG("Sending message to kernel\n");
	ret_val = sendmsg(sockfd, &msg, 0);
	if (ret_val == -1) {
		return -1;
	}

	free(nlh);
	return 0;
}

/**
 * @brief find a jinni socket among the jinni sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int findjinniSocket(unsigned long long targetID) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == targetID)
			return (i);
	}
	return (-1);
}

int matchjinniSocket(uint16_t dstport, uint32_t dstip, int protocol) {

	int i;

	PRINT_DEBUG("matchjinniSocket: %d/%d: %d, ", dstip, dstport, protocol);

	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID != -1) {
			if (protocol == IPPROTO_ICMP) {
				if ((jinniSockets[i].protocol == protocol)
						&& (jinniSockets[i].dst_IP == dstip)) {
					PRINT_DEBUG("ICMP");
					return (i);
				}
			} else {
				if (jinniSockets[i].host_IP == INADDR_ANY) {
					if (jinniSockets[i].hostport == dstport) {
						PRINT_DEBUG("hostport == dstport");
						return (i);
					}
				} else if ((jinniSockets[i].hostport == dstport)
						&& (jinniSockets[i].host_IP == dstip)/** && (jinniSockets[i].protocol == protocol)*/) {
					PRINT_DEBUG("host_IP == dstip");
					return (i);
				} else {
					PRINT_DEBUG("default");
				}
			}

			if (0) {
				if (jinniSockets[i].host_IP == INADDR_ANY
						&& (protocol != IPPROTO_ICMP)) {
					if ((jinniSockets[i].hostport == dstport))
						return (i);
				} else if ((jinniSockets[i].hostport == dstport)
						&& (jinniSockets[i].host_IP == dstip)
						&& ((protocol != IPPROTO_ICMP))
						/** && (jinniSockets[i].protocol == protocol)*/) {
					return (i);
				}

				/** Matching for ICMP incoming datagrams
				 * In this case the IP passes is actually the source IP of that incoming message (Or called the host)
				 */
				else if ((jinniSockets[i].protocol == protocol)
						&& (protocol == IPPROTO_ICMP)
						&& (jinniSockets[i].dst_IP == dstip)) {
					return (i);

				} else {
				}
			}
		}
	} // end of for loop

	return (-1);

}

/**
 * @brief insert new jinni socket in the first empty location
 * in the jinni sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */
int insertjinniSocket(unsigned long long uniqueSockID, int type, int protocol) {
	int i = 0;
	sem_wait(&jinniSockets_sem);
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == -1) {
			jinniSockets[i].uniqueSockID = uniqueSockID;
			jinniSockets[i].blockingFlag = 1;
			/**
			 * bind the socket by default to the default IP which is assigned
			 * to the Interface which was already started by the Capturing and Injecting process
			 * The IP default value it supposed to be acquired from the configuration file
			 * The allowable ports range is supposed also to be aquired the same way
			 */
			jinniSockets[i].host_IP = 0;
			/**
			 * The host port is initially assigned randomly and stay the same unless
			 * binding explicitly later
			 */
			jinniSockets[i].hostport = -1;
			jinniSockets[i].dst_IP = 0;
			jinniSockets[i].dstport = 0;
			/** Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM
			 * it has nothing to do with layer 4 protocols like TCP, UDP , etc
			 */

			jinniSockets[i].type = type;

			jinniSockets[i].protocol = protocol;
			jinniSockets[i].backlog = -1;
			jinniSockets[i].dataQueue = init_queue(NULL, MAX_Queue_size);
			sem_init(&jinniSockets[i].Qs, 0, 1);

			sprintf(jinniSockets[i].name, "socket# %llu",
					jinniSockets[i].uniqueSockID);

			errno = 0;
			PRINT_DEBUG("errno is %d", errno);

			jinniSockets[i].threads = 0;
			jinniSockets[i].replies = 0;

			jinniSockets[i].sockopts.FSO_REUSEADDR = 0;

			sem_post(&jinniSockets_sem);
			return (1);
		}
	}
	PRINT_DEBUG(
			"reached maximum # of processes to be served, FINS is out of sockets");
	sem_post(&jinniSockets_sem);
	return (-1);
}

/**
 * @brief remove a jinni socket from
 * the jinni sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */

int removejinniSocket(unsigned long long targetID) {

	int i = 0;
	sem_wait(&jinniSockets_sem);
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == targetID) {
			jinniSockets[i].uniqueSockID = -1;
			jinniSockets[i].connection_status = 0;
			term_queue(jinniSockets[i].dataQueue);
			sem_post(&jinniSockets_sem);
			return (1);

		}
	}
	sem_post(&jinniSockets_sem);
	return (-1);
} // end of removejinniSocket

/**
 * @brief check if this host port is free or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found previously-allocated)
 */

int checkjinniports(uint16_t hostport, uint32_t hostip) {

	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].host_IP == INADDR_ANY) {
			if (jinniSockets[i].hostport == hostport)
				return (0);

		} else {
			if ((jinniSockets[i].hostport == hostport)
					&& (jinniSockets[i].host_IP == hostip))
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

int checkjinnidstports(uint16_t dstport, uint32_t dstip) {

	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if ((jinniSockets[i].dstport == dstport)
				&& (jinniSockets[i].dst_IP == dstip))
			return (-1);

	}
	return (1);

}

/** ----------------------------------------------------------
 * end of functions that handle finsjinnisockets
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

int nack_send(unsigned long long uniqueSockID, int socketCallType) {
	int nack = NACK;
	int buf_len;
	void *buf;
	u_char *pt;
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d nack %d", uniqueSockID,
			socketCallType, nack);

	buf_len = sizeof(unsigned int) + sizeof(unsigned long long) + sizeof(int);
	buf = malloc(buf_len);
	pt = buf;

	*(unsigned int *) pt = socketCallType;
	pt += sizeof(unsigned int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = nack;
	pt += sizeof(int);

	ret_val = send_wedge(nl_sockfd, buf, buf_len, 0);
	free(buf);

	return ret_val == 1;
}

int ack_send(unsigned long long uniqueSockID, int socketCallType) {
	int ack = ACK;
	int buf_len;
	void *buf;
	u_char *pt;
	int ret_val;

	PRINT_DEBUG("uniqueSockID %llu calltype %d ack %d", uniqueSockID,
			socketCallType, ack);

	buf_len = sizeof(unsigned int) + sizeof(unsigned long long) + sizeof(int);
	buf = malloc(buf_len);
	pt = buf;

	*(unsigned int *) pt = socketCallType;
	pt += sizeof(unsigned int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ack;
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

void socket_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int domain;
	unsigned int type;
	int protocol;
	u_char *pt;

	PRINT_DEBUG("socket call handler1");
	PRINT_DEBUG("%llu", uniqueSockID);

	pt = buf;

	domain = *(int *) pt;
	pt += sizeof(int);

	type = *(unsigned int *) pt;
	pt += sizeof(unsigned int);

	protocol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, socket_call);
		return;
	}

	PRINT_DEBUG("socket call handler2");

	PRINT_DEBUG("%d,%d,%d", domain, protocol, type);
	if (domain != AF_INET) {
		PRINT_DEBUG("Wrong domain, only AF_INET us supported");
		nack_send(uniqueSockID, socket_call);
		return;
	}
	if (type == SOCK_DGRAM) {
		socket_udp(domain, type, protocol, uniqueSockID);
		return;
	} else if (type == SOCK_STREAM) {
		socket_tcp(domain, type, protocol, uniqueSockID);
		return;
	} else if (type == SOCK_RAW && (protocol == IPPROTO_ICMP)) {
		socket_icmp(domain, type, protocol, uniqueSockID);
		return;
	}

	else {
		PRINT_DEBUG("non supported socket type");
		return;
	}

	return;
}

/** ----------------------------------------------------------
 * End of socket_call_handler
 */

void bind_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;
	u_char *pt;
	int reuseaddr;

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(uniqueSockID, bind_call);
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
		nack_send(uniqueSockID, bind_call);
		return;
	}

	PRINT_DEBUG("%d,%d,%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port),
			addr->sin_family);

	index = findjinniSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");
		nack_send(uniqueSockID, bind_call);
		return;
	}

	jinniSockets[index].sockopts.FSO_REUSEADDR |= reuseaddr; //TODO: when sockopts fully impelmented just set to '='

	if (jinniSockets[index].type == SOCK_DGRAM)
		bind_udp(uniqueSockID, addr);
	else if (jinniSockets[index].type == SOCK_STREAM)
		bind_tcp(uniqueSockID, addr);
	else
		PRINT_DEBUG("unknown socket type has been read !!!");

	return;

} //end of bind_call_handler()
/** ----------------------------------------------------------
 * ------------------End of bind_call_handler-----------------
 */

void send_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	datalen = *(ssize_t *) pt;
	pt += sizeof(ssize_t);

	PRINT_DEBUG("passed data len = %d", datalen);
	if (datalen <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		nack_send(uniqueSockID, send_call);
		return;
	}

	data = (u_char *) malloc(datalen);
	PRINT_DEBUG("");

	memcpy(data, pt, datalen);
	pt += datalen;

	PRINT_DEBUG("");

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, send_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		nack_send(uniqueSockID, send_call);
		return;
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].connection_status <= 0) {
		PRINT_DEBUG("Socket is not connected to any destination !!!");
		nack_send(uniqueSockID, send_call);
	}

	if (jinniSockets[index].type == SOCK_DGRAM)
		send_udp(uniqueSockID, send_call, datalen, data, flags);
	else if (jinniSockets[index].type == SOCK_STREAM)
		send_tcp(uniqueSockID, send_call, datalen, data, flags);
	else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, send_call);
	}
	PRINT_DEBUG();
	return;

} //end of send_call_handler()

/** ----------------------------------------------------------
 * ------------------End of send_call_handler-----------------
 */

void sendto_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr_in *addr;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	datalen = *(int *) pt;
	pt += sizeof(int);

	PRINT_DEBUG("passed data len = %d", datalen);
	if (datalen <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		nack_send(uniqueSockID, sendto_call);
		return;
	}

	data = (u_char *) malloc(datalen);
	PRINT_DEBUG("");

	memcpy(data, pt, datalen);
	pt += datalen;

	PRINT_DEBUG("");

	flags = *(int *) pt;
	pt += sizeof(int);

	PRINT_DEBUG("");

	addrlen = *(socklen_t *) pt;
	pt += sizeof(socklen_t);

	PRINT_DEBUG("");

	addr = (struct sockaddr_in *) malloc(addrlen);

	memcpy(addr, pt, addrlen);
	pt += addrlen;

	PRINT_DEBUG("");

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, sendto_call);
		return;
	}

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		nack_send(uniqueSockID, sendto_call);
		return;
	}
	PRINT_DEBUG("");

	/**
	 *
	 * In case a connected socket has been called by mistake using sendto
	 * (IGNORE THE ADDRESSES AND USET THE ADDRESS THE SOCKET IS CONNECTED TO IT)
	 */

	if (jinniSockets[index].connection_status > 0) {

		if (jinniSockets[index].type == SOCK_DGRAM)
			send_udp(uniqueSockID, sendto_call, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_STREAM)
			send_tcp(uniqueSockID, sendto_call, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_RAW) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			nack_send(uniqueSockID, sendto_call);
		}

	} else {
		/**
		 * The default case , the socket is not connected socket
		 */

		if (jinniSockets[index].type == SOCK_DGRAM)
			sendto_udp(uniqueSockID, sendto_call, datalen, data, flags, addr,
					addrlen);
		else if (jinniSockets[index].type == SOCK_STREAM)
			sendto_tcp(uniqueSockID, sendto_call, datalen, data, flags, addr,
					addrlen);
		else if (jinniSockets[index].type == SOCK_RAW) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			nack_send(uniqueSockID, sendto_call);
		}

	}
	PRINT_DEBUG();
	return;

} //end of sendto_call_handler()

/** ----------------------------------------------------------
 * ------------------End of sendto_call_handler-----------------
 */

void recv_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	u_char *pt;

	PRINT_DEBUG();

	pt = buf;

	datalen = *(size_t *) pt;
	pt += sizeof(size_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, recv_call);
		return;
	}

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		nack_send(uniqueSockID, recv_call);
		return;
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */

		recv_udp(uniqueSockID, datalen, flags);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		recv_tcp(uniqueSockID, datalen, flags);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, recv_call);
	}

} // end of recv_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recv_call_handler-----------------
 */

void recvfrom_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	int symbol;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;
	u_char *pt;

	struct recvfrom_data *thread_data;
	pthread_t *recvmsg_thread;
	int rc;

	PRINT_DEBUG();

	pt = buf;

	datalen = *(size_t *) pt;
	pt += sizeof(size_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	symbol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, recvfrom_call);
		return;
	}

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		nack_send(uniqueSockID, recvfrom_call);
		return;
	}

	if (recv_thread_count < MAX_recv_threads) {
		PRINT_DEBUG("recv_thread_count=%d", recv_thread_count);
		recvmsg_thread = (pthread_t *) malloc(sizeof(pthread_t));

		thread_data = (struct recvfrom_data *) malloc(
				sizeof(struct recvfrom_data));
		thread_data->id = recv_thread_index++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->socketCallType = recvfrom_call;
		thread_data->datalen = datalen;
		thread_data->flags = flags;
		thread_data->symbol = symbol;

		if (jinniSockets[index].type == SOCK_DGRAM) {
			/** Whenever we need to implement non_blocking mode using
			 * threads. We will call the function below using thread_create
			 */
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_udp, (void *) thread_data);
			//recvfrom_udp(uniqueSockID, recvfrom_call, datalen, flags, symbol);
		} else if (jinniSockets[index].type == SOCK_STREAM) {
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_tcp, (void *) thread_data);
			//recvfrom_tcp(uniqueSockID, recvfrom_call, datalen, flags, symbol);
		} else if ((jinniSockets[index].type == SOCK_RAW)
				&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_icmp, (void *) thread_data);
			//recvfrom_icmp(uniqueSockID, recvfrom_call, datalen, flags, symbol);
		} else {
			PRINT_DEBUG("This socket is of unknown type");
			nack_send(uniqueSockID, recvfrom_call);
			rc = 1;
		}

		if (rc) {
			PRINT_DEBUG("Problem starting recvmsg thread: %d, ret=%d",
					thread_data->id, rc);
		} else {
			sem_wait(&recv_thread_sem);
			recv_thread_count++;
			sem_post(&recv_thread_sem);
		}
		free(recvmsg_thread);
	} else {
		PRINT_DEBUG("Hit max allowed recv thread, count=%d", recv_thread_count);
		nack_send(uniqueSockID, recvfrom_call);
	}
} // end of recvfrom_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recvfrom_call_handler-----------------
 */

void sendmsg_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	int msg_flags;
	int symbol;
	int controlFlag = 0;
	u_char *data;
	socklen_t addrlen;
	void *msg_control;
	int msg_controlLength;
	struct sockaddr_in *addr;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	flags = *(int *) pt;
	pt += sizeof(int);

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

	datalen = *(u_int *) pt;
	pt += sizeof(u_int);

	if (datalen <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	data = (u_char *) malloc(datalen);
	PRINT_DEBUG("");

	memcpy(data, pt, datalen);
	pt += datalen;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		nack_send(uniqueSockID, sendmsg_call);
		return;
	}
	PRINT_DEBUG("");

	/**
	 * In case of connected sockets
	 */
	if (jinniSockets[index].connection_status > 0) {

		if (jinniSockets[index].type == SOCK_DGRAM)
			send_udp(uniqueSockID, sendmsg_call, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_STREAM)
			send_tcp(uniqueSockID, sendmsg_call, datalen, data, flags);
		else if ((jinniSockets[index].type == SOCK_RAW)
				&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			nack_send(uniqueSockID, sendmsg_call);
		}

	} else {

		/**
		 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
		 * Process. Check if an address has been passed or not is required
		 */
		if (symbol) { // check that the passed address is not NULL
			if (jinniSockets[index].type == SOCK_DGRAM)
				sendto_udp(uniqueSockID, sendmsg_call, datalen, data, flags,
						addr, addrlen);
			else if (jinniSockets[index].type == SOCK_STREAM)
				sendto_tcp(uniqueSockID, sendmsg_call, datalen, data, flags,
						addr, addrlen);
			else if ((jinniSockets[index].type == SOCK_RAW)
					&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {

				sendto_icmp(uniqueSockID, sendmsg_call, datalen, data, flags,
						addr, addrlen);

			} else {

				PRINT_DEBUG("unknown target address !!!");
				nack_send(uniqueSockID, sendmsg_call);
			}

		}

		else {
			PRINT_DEBUG("unknown target address !!!");
			nack_send(uniqueSockID, sendmsg_call);
		}

	}

	PRINT_DEBUG();
	return;

}

void recvmsg_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int datalen;
	int flags;
	int symbol;
	int msgFlags;
	int controlFlag;
	ssize_t msgControl_Length;
	void *msgControl;
	u_char *data;
	u_char *pt;

	struct recvfrom_data *thread_data;
	pthread_t *recvmsg_thread;
	int rc;

	PRINT_DEBUG();

	pt = buf;

	datalen = *(ssize_t *) pt; //check on not in original socket_interceptor: recvmsg
	pt += sizeof(ssize_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	symbol = *(int *) pt;
	pt += sizeof(int);

	msgFlags = *(int *) pt;
	pt += sizeof(int);

	controlFlag = *(int *) pt;
	pt += sizeof(int);

	if (controlFlag) {
		msgControl_Length = *(u_int *) pt;
		pt += sizeof(u_int);

		if (msgControl_Length <= 0) {
			PRINT_DEBUG("READING ERROR! CRASH, msgControl_Length=%d",
					msgControl_Length);
			nack_send(uniqueSockID, recvmsg_call);
			return;
		}
		msgControl = (u_char *) malloc(msgControl_Length);
		if (msgControl) {
			memcpy(msgControl, pt, msgControl_Length); //??? originally had &msgControl
			pt += msgControl_Length;
		} else {
			PRINT_DEBUG("allocation error");
			nack_send(uniqueSockID, recvmsg_call);
			return;
		}
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, recvmsg_call);
		return;
	}

	PRINT_DEBUG("");

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		nack_send(uniqueSockID, recvmsg_call);
		return;
	}
	sem_wait(&jinniSockets_sem);
	jinniSockets[index].threads = threads;
	sem_post(&jinniSockets_sem);

	if (recv_thread_count < MAX_recv_threads) {
		PRINT_DEBUG("recv_thread_count=%d", recv_thread_count);
		recvmsg_thread = (pthread_t *) malloc(sizeof(pthread_t));

		thread_data = (struct recvfrom_data *) malloc(
				sizeof(struct recvfrom_data));
		thread_data->id = recv_thread_index++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->socketCallType = recvmsg_call;
		thread_data->datalen = datalen;
		thread_data->flags = flags;
		thread_data->symbol = symbol;

		if (jinniSockets[index].type == SOCK_DGRAM) {
			/** Whenever we need to implement non_blocking mode using
			 * threads. We will call the function below using thread_create
			 */
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_udp, (void *) thread_data);
			//recvfrom_udp(uniqueSockID, recvmsg_call, datalen, flags, symbol);
		} else if (jinniSockets[index].type == SOCK_STREAM) {
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_tcp, (void *) thread_data);
			//recvfrom_tcp(uniqueSockID, recvmsg_call, datalen, flags, symbol);
		} else if ((jinniSockets[index].type == SOCK_RAW)
				&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {
			rc = pthread_create(recvmsg_thread, NULL,
					(void * (*)(void *)) recvfrom_icmp, (void *) thread_data);
			//recvfrom_icmp(uniqueSockID, recvmsg_call, datalen, flags, symbol);
		} else {
			PRINT_DEBUG("This socket is of unknown type");
			nack_send(uniqueSockID, recvmsg_call);
			rc = 1;
		}

		if (rc) {
			PRINT_DEBUG("Problem starting recvmsg thread: %d, ret=%d",
					thread_data->id, rc);
		} else {
			sem_wait(&recv_thread_sem);
			recv_thread_count++;
			sem_post(&recv_thread_sem);
		}
		free(recvmsg_thread);
	} else {
		PRINT_DEBUG("Hit max allowed recv thread, count=%d", recv_thread_count);
		nack_send(uniqueSockID, recvmsg_call);
	}
}

void getsockopt_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = *(int *) pt;
	pt += sizeof(int);

	if (optlen > 0) {
		optval = (u_char *) malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, getsockopt_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is not found too ");
		nack_send(uniqueSockID, getsockopt_call);
		return;
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].type == SOCK_DGRAM)
		getsockopt_udp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_STREAM)
		getsockopt_tcp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_RAW) {
		getsockopt_icmp(uniqueSockID, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, getsockopt_call);
	}
}

void setsockopt_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int level;
	int optname;
	int optlen;
	u_char *optval;
	u_char *pt;

	PRINT_DEBUG("");

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
		nack_send(uniqueSockID, setsockopt_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		nack_send(uniqueSockID, setsockopt_call);
		return;
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].type == SOCK_DGRAM)
		setsockopt_udp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_STREAM)
		setsockopt_tcp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_RAW) {
		setsockopt_icmp(uniqueSockID, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, setsockopt_call);
	}
}

void listen_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int backlog;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	backlog = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, listen_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is not found too ");
		nack_send(uniqueSockID, listen_call);
		return;
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].type == SOCK_DGRAM)
		listen_udp(uniqueSockID, backlog);
	else if (jinniSockets[index].type == SOCK_STREAM)
		listen_tcp(uniqueSockID, backlog);
	else if (jinniSockets[index].type == SOCK_RAW) {
		listen_icmp(uniqueSockID, backlog);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, listen_call);
	}
}

void accept_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {
	int index;
	unsigned long long uniqueSockID_new;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	uniqueSockID_new = *(unsigned long long *) pt;
	pt += sizeof(unsigned long long);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, listen_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is not found too ");
		nack_send(uniqueSockID, listen_call);
		return;
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].type == SOCK_DGRAM)
		accept_udp(uniqueSockID, uniqueSockID_new);
	else if (jinniSockets[index].type == SOCK_STREAM)
		accept_tcp(uniqueSockID, uniqueSockID_new);
	else if (jinniSockets[index].type == SOCK_RAW) {
		accept_icmp(uniqueSockID, uniqueSockID_new);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		nack_send(uniqueSockID, listen_call);
	}
}

void accept4_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

}

void shutdown_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	int how;
	u_char *pt;

	PRINT_DEBUG();

	pt = buf;

	how = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, shutdown_call);
		return;
	}

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		nack_send(uniqueSockID, shutdown_call);
		return;
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */
		shutdown_udp(uniqueSockID, how);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		shutdown_tcp(uniqueSockID, how);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, shutdown_call);
	}

}

//TODO: dummy function, need to implement this
void release_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {
	u_char *pt;
	pt = buf;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, release_call);
		return;
	}

	if (removejinniSocket(uniqueSockID)) {
		ack_send(uniqueSockID, release_call);
	} else {
		nack_send(uniqueSockID, release_call);
	}
}

//TODO: dummy function, need to implement this
void ioctl_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {
	int index;
	u_int cmd;
	u_long arg;
	u_char *pt;

	PRINT_DEBUG("");

	pt = buf;

	cmd = *(u_int *) pt;
	pt += sizeof(u_int);

	arg = *(u_long *) pt;
	pt += sizeof(u_long);

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, ioctl_call);
		return;
	}

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is not found too ");
		nack_send(uniqueSockID, ioctl_call);
		return;
	}
	PRINT_DEBUG("uniqueSockID=%llu, index=%d, cmd=%d, arg=%lu", uniqueSockID,
			index, cmd, arg);

	/*if (jinniSockets[index].type == SOCK_DGRAM)
	 ioctl_udp(uniqueSockID, cmd, arg);
	 else if (jinniSockets[index].type == SOCK_STREAM)
	 ioctl_tcp(uniqueSockID, cmd, arg);
	 else if (jinniSockets[index].type == SOCK_RAW) {
	 ioctl_icmp(uniqueSockID, cmd, arg);
	 } else {
	 PRINT_DEBUG("unknown socket type has been read !!!");
	 nack_send(uniqueSockID, setsockopt_call);
	 }*/
	ack_send(uniqueSockID, ioctl_call);
}

void close_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	PRINT_DEBUG("socket call handler1");
	PRINT_DEBUG("%llu", uniqueSockID);

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		nack_send(uniqueSockID, close_call);
		return;
	}

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
	if (removejinniSocket(uniqueSockID)) {
		ack_send(uniqueSockID, close_call);
	} else {
		nack_send(uniqueSockID, close_call);
	}

}

void getsockname_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	index = findjinniSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");
		nack_send(uniqueSockID, getsockname_call);
		return;
	}

	PRINT_DEBUG("getsockname_handler called");
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = jinniSockets[index].host_IP;
	addr->sin_port = jinniSockets[index].hostport;
	PRINT_DEBUG("%d , %d", jinniSockets[index].host_IP,
			jinniSockets[index].hostport);

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addrlen;
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = getsockname_call;
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
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg,
				msg_len);
		free(msg);
		nack_send(uniqueSockID, getsockname_call);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);

	PRINT_DEBUG("getsockname DONE");

	return;

}

void connect_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;
	u_char *pt;

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_DEBUG("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(uniqueSockID, connect_call);
		return;
	}

	addr = (struct sockaddr_in *) malloc(addrlen);

	memcpy(addr, pt, addrlen);
	pt += addrlen;

	if (pt - buf != len) {
		PRINT_DEBUG("READING ERROR! CRASH, diff=%d len=%d", pt - buf, len);
		nack_send(uniqueSockID, connect_call);
		return;
	}

	PRINT_DEBUG("%d,%d,%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port),
			addr->sin_family);

	index = findjinniSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");
		nack_send(uniqueSockID, connect_call);
		return;
	}
	if (jinniSockets[index].type == SOCK_DGRAM) {
		connect_udp(uniqueSockID, addr);
	} else if (jinniSockets[index].type == SOCK_STREAM) {
		connect_tcp(uniqueSockID, addr);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		nack_send(uniqueSockID, connect_call);
	}

	return;

}
void getpeername_call_handler(unsigned long long uniqueSockID, int threads,
		unsigned char *buf, ssize_t len) {

	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	index = findjinniSocket(uniqueSockID);
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");
		nack_send(uniqueSockID, getpeername_call);
		return;
	}

	PRINT_DEBUG("getpeername_handler called");
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = ntohl(jinniSockets[index].dst_IP);
	addr->sin_port = jinniSockets[index].dstport;
	PRINT_DEBUG("%d , %d", jinniSockets[index].dst_IP,
			jinniSockets[index].dstport);

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
			+ addrlen;
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = getpeername_call;
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
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg,
				msg_len);
		free(msg);
		nack_send(uniqueSockID, getpeername_call);
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
	sem_wait(&recv_thread_sem);
	recv_thread_count--;
	sem_post(&recv_thread_sem);

	PRINT_DEBUG("Exiting recv thread:%d", thread_data->id);
	free(thread_data);

	pthread_exit(NULL);
}
