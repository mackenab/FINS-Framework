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

extern struct finssocket jinniSockets[MAX_sockets];
extern struct socketIdentifier FinsHistory[MAX_sockets];
/** The queues might be moved later to another Master file */

extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;
extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;

extern int socket_channel_desc;
extern sem_t *meen_channel_semaphore1;
extern sem_t *meen_channel_semaphore2;

/**
 * @brief find a jinni socket among the jinni sockets array
 * @param
 * @return the location index on success , -1 on failure
 */
int findjinniSocket(pid_t target1, int target2) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if ((jinniSockets[i].processid == target1) && (jinniSockets[i].sockfd
				== target2))
			return (i);
	}
	return (-1);
}

int matchjinniSocket(uint16_t dstport, uint32_t dstip, int protocol) {

	int i;

	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].host_IP == INADDR_ANY) {
			if ((jinniSockets[i].hostport == dstport))
				return (i);

		} else {

			if ((jinniSockets[i].hostport == dstport)
					&& (jinniSockets[i].host_IP == dstip))
				return (i);

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
int insertjinniSocket(pid_t processID, int sockfd, int fakeID, int type,
		int protocol) {
	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].processid == -1) {
			jinniSockets[i].processid = processID;
			jinniSockets[i].sockfd = sockfd;
			jinniSockets[i].fakeID = fakeID;
			//	jinniSockets[i].jinniside_pipe_ds = jinnipd;
			/** Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM
			 * it has nothing to do with layer 4 protocols like TCP, UDP , etc
			 */

			jinniSockets[i].type = type;

			jinniSockets[i].protocol = protocol;
			jinniSockets[i].dataQueue = init_queue(NULL, MAX_Queue_size);
			sem_init(&jinniSockets[i].Qs, 0, 1);

			sprintf(jinniSockets[i].name, "socket# %d.%d.%d",
					jinniSockets[i].processid, jinniSockets[i].sockfd,
					jinniSockets[i].jinniside_pipe_ds);
			sprintf(jinniSockets[i].semaphore_name, "socket%d_%d",
					jinniSockets[i].processid, jinniSockets[i].fakeID);
			sprintf(jinniSockets[i].asemaphore_name, "socket%d_%da",
					jinniSockets[i].processid, jinniSockets[i].fakeID);

			/** TODO enable the internal semaphore */

			errno = 0;
			/** the semaphore is initially unlocked */
			jinniSockets[i].s = sem_open(jinniSockets[i].semaphore_name,
					O_CREAT | O_EXCL, 0644, 1);
			jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,
					O_CREAT | O_EXCL, 0644, 0);
			//	jinniSockets[i].s  = sem_open(jinniSockets[i].semaphore_name,O_CREAT,0644,1);
			//	jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,O_CREAT,0644,0);
			PRINT_DEBUG("%s, %s",jinniSockets[i].semaphore_name, jinniSockets[i].asemaphore_name );PRINT_DEBUG("errno is %d", errno);

			if (jinniSockets[i].s == SEM_FAILED || jinniSockets[i].as
					== SEM_FAILED) {
				jinniSockets[i].s = sem_open(jinniSockets[i].semaphore_name, 0);
				jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,
						0);
				PRINT_DEBUG();

			}PRINT_DEBUG("errno is %d", errno);
			if (jinniSockets[i].s == SEM_FAILED || jinniSockets[i].as
					== SEM_FAILED) {
				PRINT_DEBUG("");
				sem_unlink(jinniSockets[i].semaphore_name);
				exit(1);

			}
			return (1);
		}
	}PRINT_DEBUG("reached maximum # of processes to be served, FINS is out of sockets");
	return (-1);
}

/**
 * @brief remove a jinni socket from
 * the jinni sockets array
 * @param
 * @return value of 1 on success , -1 on failure
 */

int removejinniSocket(pid_t target1, int target2) {

	int i = 0;
	for (i = 0; i < MAX_sockets; i++) {
		if ((jinniSockets[i].processid == target1) && (jinniSockets[i].sockfd
				== target2)) {
			jinniSockets[i].processid = -1;
			jinniSockets[i].sockfd = -1;
			term_queue(jinniSockets[i].dataQueue);
			sem_close(jinniSockets[i].s);
			sem_unlink(jinniSockets[i].semaphore_name);
			sem_close(jinniSockets[i].as);
			sem_unlink(jinniSockets[i].asemaphore_name);
			sprintf(jinniSockets[i].semaphore_name, "NULL");
			return (1);

		}
	}
	return (-1);
} // end of removejinniSocket

/**
 * @brief check if this host port is free or not

 * @param
 * @return value of 1 on success (found free) , -1 on failure (found pre-allocated)
 */

int checkjinniports(uint16_t hostport, uint32_t hostip) {

	int i = 0;

	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].host_IP == INADDR_ANY) {
			if (jinniSockets[i].hostport == hostport)
				return (-1);

		} else {
			if ((jinniSockets[i].hostport == hostport)
					&& (jinniSockets[i].host_IP == hostip))
				return (-1);

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
		if ((jinniSockets[i].dstport == dstport) && (jinniSockets[i].dst_IP
				== dstip))
			return (-1);

	}
	return (1);

}

/** ----------------------------------------------------------
 * end of functions that handle finsjinnisockets
 */

int nack_write(int pipe_desc, int processid, int sockfd) {
	int byteswritten;
	int nack = NACK;
	int index;

	/** TODO lock the pipe before writing */

	write(pipe_desc, &processid, sizeof(int));
	write(pipe_desc, &sockfd, sizeof(int));
	write(pipe_desc, &nack, sizeof(int));
	/**TODO unlock the pipe
	 * check for failure of writing
	 * return 1 on success -1 on failure
	 * */

	return (1);

} // end of nack_write


int ack_write(int pipe_desc, int processid, int sockfd) {
	int byteswritten;
	int ack = ACK;
	/** TODO lock the pipe before writing */
	PRINT_DEBUG("processid %d sockfd %d ack %d",processid, sockfd, ack);
	write(pipe_desc, &processid, sizeof(int));
	write(pipe_desc, &sockfd, sizeof(int));
	write(pipe_desc, &ack, sizeof(int));
	/**TODO unlock the pipe
	 * check for failure of writing
	 * return 1 on success -1 on failure
	 * */

	return (1);

}

void socket_call_handler(pid_t senderProcessid) {
	int numOfBytes = -1;
	struct socket_call_msg msg;

	PRINT_DEBUG("socket call handler1");PRINT_DEBUG("%d",senderProcessid);
	//sem_wait(meen_channel_semaphore);

	numOfBytes
			= read(socket_channel_desc, &msg, sizeof(struct socket_call_msg));
	sem_post(meen_channel_semaphore2);

	if ((numOfBytes <= 0) || (numOfBytes != sizeof(struct socket_call_msg))) {

		PRINT_DEBUG("READING ERROR!! Probably Sync Failed!!");
		return;
	}
	/**TODO Unlock the socket main channel previously locked by the main */

	PRINT_DEBUG("socket call handler2");

	PRINT_DEBUG("%d,%d,%d,%d,%d", msg.domain,msg.protocol,msg.type,msg.sockfd,msg.fakeID);
	if (msg.domain != AF_INET) {
		PRINT_DEBUG("Wrong domain, only AF_INET us supported");
		return;
	}
	if (msg.type == SOCK_DGRAM) {
		socket_udp(msg.domain, msg.type, msg.protocol, msg.sockfd, msg.fakeID,
				senderProcessid);
		return;
	} else if (msg.type == SOCK_STREAM) {
		socket_tcp(msg.domain, msg.type, msg.protocol, msg.sockfd,
				senderProcessid);
		return;
	} else {
		PRINT_DEBUG("non supported socket type");
		exit(1);
	}

	return;
}

/** ----------------------------------------------------------
 * End of socket_call_handler
 */

void bind_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(socklen_t));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	addr = (struct sockaddr_in *) malloc(addrlen);

	numOfBytes = read(socket_channel_desc, addr, addrlen);
	sem_post(meen_channel_semaphore2);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	PRINT_DEBUG("%d,%d,%d", addr->sin_addr, ntohs(addr->sin_port),addr->sin_family);
	/** Unlock the main socket channel
	 *
	 */
	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}
	if (jinniSockets[index].type == SOCK_DGRAM)
		bind_udp(senderid, sockfd, addr);
	else if (jinniSockets[index].type == SOCK_STREAM)
		bind_tcp(senderid, sockfd, addr);
	else
		PRINT_DEBUG("unknown socket type has been read !!!");

	return;

} //end of bind_call_handler()
/** ----------------------------------------------------------
 * ------------------End of bind_call_handler-----------------
 */

void send_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("passed data len = %d",datalen);
	if (datalen <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		exit(1);

	}

	data = (u_char *) malloc(datalen);
	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, data, datalen);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}PRINT_DEBUG("");

	if (jinniSockets[index].connection_status <= 0) {

		PRINT_DEBUG("Socket is not connected to any destination !!!");

		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);

	}

	if (jinniSockets[index].type == SOCK_DGRAM)
		send_udp(senderid, sockfd, datalen, data, flags);
	else if (jinniSockets[index].type == SOCK_STREAM)
		send_tcp(senderid, sockfd, datalen, data, flags);
	else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}PRINT_DEBUG();
	return;

} //end of send_call_handler()

/** ----------------------------------------------------------
 * ------------------End of send_call_handler-----------------
 */

void sendto_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("passed data len = %d",datalen);
	if (datalen <= 0) {
		PRINT_DEBUG("DATA Field is empty!!");
		exit(1);

	}

	data = (u_char *) malloc(datalen);
	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, data, datalen);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(socklen_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	addr = (struct sockaddr *) malloc(addrlen);
	numOfBytes = read(socket_channel_desc, addr, addrlen);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}PRINT_DEBUG("");

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG("CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}PRINT_DEBUG("");

	if (jinniSockets[index].type == SOCK_DGRAM)
		sendto_udp(senderid, sockfd, datalen, data, flags, addr, addrlen);
	else if (jinniSockets[index].type == SOCK_STREAM)
		sendto_tcp(senderid, sockfd, datalen, data, flags, addr, addrlen);
	else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}PRINT_DEBUG();
	return;

} //end of sendto_call_handler()

/** ----------------------------------------------------------
 * ------------------End of sendto_call_handler-----------------
 */

void recv_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	int datalen;
	int flags;

	PRINT_DEBUG();
	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	/** Unlock the main socket channel */

	sem_post(meen_channel_semaphore2);

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */

		recv_udp(senderid, sockfd, datalen, flags);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		recv_tcp(senderid, sockfd, datalen, flags);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

} // end of recv_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recv_call_handler-----------------
 */

void recvfrom_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	int datalen;
	int flags;
	int symbol;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG();
	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &symbol, sizeof(int));
	sem_post(meen_channel_semaphore2);

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	/** Unlock the main socket channel
	 *
	 */
	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */
		PRINT_DEBUG("recvfrom Address Symbol = %d",symbol);
		recvfrom_udp(senderid, sockfd, datalen, flags, symbol);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		recvfrom_tcp(senderid, sockfd, datalen, flags);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

} // end of recvfrom_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recvfrom_call_handler-----------------
 */

void sendmsg_call_handler() {

}

void recvmsg_call_handler() {

}

void getsockopt_call_handler() {

}

void setsockopt_call_handler() {

}

void listen_call_handler() {

}
void accept_call_handler() {

}

void accept4_call_handler() {

}

void shutdown_call_handler() {

}

void getsockname_call_handker() {

}

void connect_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(socklen_t));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	addr = (struct sockaddr_in *) malloc(addrlen);

	numOfBytes = read(socket_channel_desc, addr, addrlen);
	/** Unlock the main socket channel */
	sem_post(meen_channel_semaphore2);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	PRINT_DEBUG("%d,%d,%d", addr->sin_addr, ntohs(addr->sin_port),addr->sin_family);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}
	if (jinniSockets[index].type == SOCK_DGRAM) {
		connect_udp(senderid, sockfd, addr);
	} else if (jinniSockets[index].type == SOCK_STREAM) {
		connect_tcp(senderid, sockfd, addr);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	return;

}
void getpeername_call_handler(int senderid) {

	int numOfBytes;
	int sockfd;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	numOfBytes = read(socket_channel_desc, &sockfd, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	sem_post(meen_channel_semaphore2);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}

	PRINT_DEBUG("%d, %d",addrlen,sizeof(struct sockaddr_in));
	if (addrlen < sizeof(struct sockaddr_in)) {
		PRINT_DEBUG("socketjinni failed to accomplish getpeername_udp");PRINT_DEBUG("the length of the passed address buffer is zero or negative");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);

		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);

	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		getpeername_udp(senderid, sockfd, addrlen);
	} else if (jinniSockets[index].type == SOCK_STREAM) {
		getpeername_tcp(senderid, sockfd, addrlen);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}
	return;

}

void socketpair_call_handler()
{

}
