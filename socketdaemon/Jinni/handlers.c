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

	for (i = 0; i < MAX_sockets; i++) {

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
			if (jinniSockets[i].host_IP == INADDR_ANY && (protocol
					!= IPPROTO_ICMP)) {
				if ((jinniSockets[i].hostport == dstport))
					return (i);
			} else if ((jinniSockets[i].hostport == dstport)
					&& (jinniSockets[i].host_IP == dstip) && ((protocol
					!= IPPROTO_ICMP))
			/** && (jinniSockets[i].protocol == protocol)*/) {
				return (i);
			}

			/** Matching for ICMP incoming datagrams
			 * In this case the IP passes is actually the source IP of that incoming message (Or called the host)
			 */
			else if ((jinniSockets[i].protocol == protocol) && (protocol
					== IPPROTO_ICMP) && (jinniSockets[i].dst_IP == dstip)) {
				return (i);

			} else {
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
			//	jinniSockets[i].jinniside_pipe_ds = jinnipd;
			/** Transport protocol SUBTYPE SOCK_DGRAM , SOCK_RAW, SOCK_STREAM
			 * it has nothing to do with layer 4 protocols like TCP, UDP , etc
			 */

			jinniSockets[i].type = type;

			jinniSockets[i].protocol = protocol;
			jinniSockets[i].dataQueue = init_queue(NULL, MAX_Queue_size);
			sem_init(&jinniSockets[i].Qs, 0, 1);

			sprintf(jinniSockets[i].name, "socket# %llu.%d",
					jinniSockets[i].uniqueSockID,
					jinniSockets[i].jinniside_pipe_ds);
			sprintf(jinniSockets[i].semaphore_name, "socket%llu",
					jinniSockets[i].uniqueSockID);
			sprintf(jinniSockets[i].asemaphore_name, "socket%llua",
					jinniSockets[i].uniqueSockID);

			/** TODO enable the internal semaphore */

			errno = 0;
			/** the semaphore is initially unlocked */
			jinniSockets[i].s = sem_open(jinniSockets[i].semaphore_name,
					O_CREAT | O_EXCL, 0644, 1);
			jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,
					O_CREAT | O_EXCL, 0644, 0);
			//	jinniSockets[i].s  = sem_open(jinniSockets[i].semaphore_name,O_CREAT,0644,1);
			//	jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,O_CREAT,0644,0);
			PRINT_DEBUG("%s, %s", jinniSockets[i].semaphore_name,
					jinniSockets[i].asemaphore_name);
			PRINT_DEBUG("errno is %d", errno);

			if (jinniSockets[i].s == SEM_FAILED || jinniSockets[i].as
					== SEM_FAILED) {
				jinniSockets[i].s = sem_open(jinniSockets[i].semaphore_name, 0);
				jinniSockets[i].as = sem_open(jinniSockets[i].asemaphore_name,
						0);
				PRINT_DEBUG("Crash Semaphores Failure");

			}
			PRINT_DEBUG("errno is %d", errno);
			if (jinniSockets[i].s == SEM_FAILED || jinniSockets[i].as
					== SEM_FAILED) {
				PRINT_DEBUG("Crash Semaphores Failure");
				sem_unlink(jinniSockets[i].semaphore_name);
				exit(1);

			}
			return (1);
		}
	}
	PRINT_DEBUG(
			"reached maximum # of processes to be served, FINS is out of sockets");
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
	for (i = 0; i < MAX_sockets; i++) {
		if (jinniSockets[i].uniqueSockID == targetID) {
			jinniSockets[i].uniqueSockID = -1;
			jinniSockets[i].connection_status = 0;
			term_queue(jinniSockets[i].dataQueue);
			//			sem_close(jinniSockets[i].s);
			//			sem_unlink(jinniSockets[i].semaphore_name);
		//			sem_close(jinniSockets[i].as);
		//			sem_unlink(jinniSockets[i].asemaphore_name);
		//			sprintf(jinniSockets[i].semaphore_name, "NULL");
		return (1);

	}
}
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

int nack_write(int pipe_desc, unsigned long long uniqueSockID) {
	int byteswritten;
	int nack = NACK;
	int index;

	/** TODO lock the pipe before writing */

	write(pipe_desc, &uniqueSockID, sizeof(unsigned long long));
	write(pipe_desc, &nack, sizeof(int));
	/**TODO unlock the pipe
	 * check for failure of writing
	 * return 1 on success -1 on failure
	 * */

	return (1);

} // end of nack_write


int ack_write(int pipe_desc, unsigned long long uniqueSockID) {
	int byteswritten;
	int ack = ACK;
	/** TODO lock the pipe before writing */
	PRINT_DEBUG("uniqueSockID %llu ack %d", uniqueSockID, ack);
	write(pipe_desc, &uniqueSockID, sizeof(unsigned long long));
	write(pipe_desc, &ack, sizeof(int));
	/**TODO unlock the pipe
	 * check for failure of writing
	 * return 1 on success -1 on failure
	 * */

	return (1);

}

void socket_call_handler(unsigned long long uniqueSockID) {
	int numOfBytes = -1;
	int domain;
	unsigned int type;
	int protocol;

	PRINT_DEBUG("socket call handler1");
	PRINT_DEBUG("%llu", uniqueSockID);

	numOfBytes = read(socket_channel_desc, &domain, sizeof(int));
		if (numOfBytes <= 0) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
	}

	numOfBytes = read(socket_channel_desc, &type, sizeof(unsigned int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &protocol, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	sem_post(meen_channel_semaphore2);

	/**TODO Unlock the socket main channel previously locked by the main */

	PRINT_DEBUG("socket call handler2");

	PRINT_DEBUG("%d,%d,%d", domain, protocol, type);
	if (domain != AF_INET) {
		PRINT_DEBUG("Wrong domain, only AF_INET us supported");
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
		exit(1);
	}

	return;
}

/** ----------------------------------------------------------
 * End of socket_call_handler
 */

void bind_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

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

	PRINT_DEBUG("%d,%d,%d", addr->sin_addr, ntohs(addr->sin_port),
			addr->sin_family);
	/** Unlock the main socket channel
	 *
	 */
	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}
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

void send_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("passed data len = %d", datalen);
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
	}
	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("");

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}
	PRINT_DEBUG("");

	if (jinniSockets[index].connection_status <= 0) {

		PRINT_DEBUG("Socket is not connected to any destination !!!");

		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);

	}

	if (jinniSockets[index].type == SOCK_DGRAM)
		send_udp(uniqueSockID, datalen, data, flags);
	else if (jinniSockets[index].type == SOCK_STREAM)
		send_tcp(uniqueSockID, datalen, data, flags);
	else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}
	PRINT_DEBUG();
	return;

} //end of send_call_handler()

/** ----------------------------------------------------------
 * ------------------End of send_call_handler-----------------
 */

void sendto_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int datalen;
	int flags;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(size_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("passed data len = %d", datalen);
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
	}
	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(socklen_t));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("");

	addr = (struct sockaddr *) malloc(addrlen);
	numOfBytes = read(socket_channel_desc, addr, addrlen);
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	PRINT_DEBUG("");

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}
	PRINT_DEBUG("");

	/**
	 *
	 * In case a connected socket has been called by mistake using sendto
	 * (IGNORE THE ADDRESSES AND USET THE ADDRESS THE SOCKET IS CONNECTED TO IT)
	 */

	if (jinniSockets[index].connection_status > 0) {

		if (jinniSockets[index].type == SOCK_DGRAM)
			send_udp(uniqueSockID, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_STREAM)
			send_tcp(uniqueSockID, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_RAW) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			sem_wait(jinniSockets[index].s);
			nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
			sem_post(jinniSockets[index].as);
			sem_post(jinniSockets[index].s);
		}

	} else {
		/**
		 * The default case , the socket is not connected socket
		 */

		if (jinniSockets[index].type == SOCK_DGRAM)
			sendto_udp(uniqueSockID, datalen, data, flags, addr, addrlen);
		else if (jinniSockets[index].type == SOCK_STREAM)
			sendto_tcp(uniqueSockID, datalen, data, flags, addr, addrlen);
		else if (jinniSockets[index].type == SOCK_RAW) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			sem_wait(jinniSockets[index].s);
			nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
			sem_post(jinniSockets[index].as);
			sem_post(jinniSockets[index].s);
		}

	}
	PRINT_DEBUG();
	return;

} //end of sendto_call_handler()

/** ----------------------------------------------------------
 * ------------------End of sendto_call_handler-----------------
 */

void recv_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int datalen;
	int flags;

	PRINT_DEBUG();
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
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
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
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

} // end of recv_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recv_call_handler-----------------
 */

void recvfrom_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int datalen;
	int flags;
	int symbol;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG();
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
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */
		PRINT_DEBUG("recvfrom Address Symbol = %d", symbol);
		recvfrom_udp(uniqueSockID, datalen, flags, symbol);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		recvfrom_tcp(uniqueSockID, datalen, flags, symbol);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

} // end of recvfrom_call_handler()

/** ----------------------------------------------------------
 * ------------------End of recvfrom_call_handler-----------------
 */

void sendmsg_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
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
	struct sockaddr *addr;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &flags, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &addrlen, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &symbol, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	if (symbol) {

		addr = (struct sockaddr *) malloc(addrlen);
		numOfBytes = read(socket_channel_desc, addr, addrlen);
		if (numOfBytes <= 0) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}

	}

	numOfBytes = read(socket_channel_desc, &msg_flags, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &controlFlag, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	if (controlFlag) {

		numOfBytes = read(socket_channel_desc, &msg_controlLength, sizeof(int));
		if (numOfBytes <= 0) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}
		numOfBytes = read(socket_channel_desc, msg_control, msg_controlLength);
		if (numOfBytes <= 0) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}

	}

	numOfBytes = read(socket_channel_desc, &datalen, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

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
	}
	PRINT_DEBUG("");

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}
	PRINT_DEBUG("");

	/**
	 * In case of connected sockets
	 */
	if (jinniSockets[index].connection_status > 0) {

		if (jinniSockets[index].type == SOCK_DGRAM)
			send_udp(uniqueSockID, datalen, data, flags);
		else if (jinniSockets[index].type == SOCK_STREAM)
			send_tcp(uniqueSockID, datalen, data, flags);
		else if ((jinniSockets[index].type == SOCK_RAW)
				&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {

		} else {
			PRINT_DEBUG("unknown socket type has been read !!!");
			sem_wait(jinniSockets[index].s);
			nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
			sem_post(jinniSockets[index].as);
			sem_post(jinniSockets[index].s);
		}

	} else {

		/**
		 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
		 * Process. Check if an address has been passed or not is required
		 */
		if (symbol) { // check that the passed address is not NULL
			if (jinniSockets[index].type == SOCK_DGRAM)
				sendto_udp(uniqueSockID, datalen, data, flags, addr,
						addrlen);
			else if (jinniSockets[index].type == SOCK_STREAM)
				sendto_tcp(uniqueSockID, datalen, data, flags, addr,
						addrlen);
			else if ((jinniSockets[index].type == SOCK_RAW)
					&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {

				sendto_icmp(uniqueSockID, datalen, data, flags, addr,
						addrlen);

			} else {

				PRINT_DEBUG("unknown target address !!!");
				sem_wait(jinniSockets[index].s);
				nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
				sem_post(jinniSockets[index].as);
				sem_post(jinniSockets[index].s);
			}

		}

		else {
			PRINT_DEBUG("unknown target address !!!");
			sem_wait(jinniSockets[index].s);
			nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
			sem_post(jinniSockets[index].as);
			sem_post(jinniSockets[index].s);
		}

	}

	PRINT_DEBUG();
	return;

}

void recvmsg_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int datalen;
	int flags;
	int symbol;
	int msgFlags;
	int controlFlag;
	int msgControl_Length;
	void *msgControl;
	u_char *data;
	socklen_t addrlen;
	struct sockaddr *addr;

	PRINT_DEBUG();
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

	numOfBytes = read(socket_channel_desc, &msgFlags, sizeof(int));
	sem_post(meen_channel_semaphore2);

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &controlFlag, sizeof(int));
	sem_post(meen_channel_semaphore2);

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	if (controlFlag) {
		numOfBytes = read(socket_channel_desc, &msgControl_Length, sizeof(int));
		sem_post(meen_channel_semaphore2);

		if (numOfBytes != sizeof(int)) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}
		msgControl = (u_char *) malloc(msgControl_Length);
		numOfBytes = read(socket_channel_desc, &msgControl, msgControl_Length);
		sem_post(meen_channel_semaphore2);

		if (numOfBytes != msgControl_Length) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}

	}

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */
	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (jinniSockets[index].type == SOCK_DGRAM) {
		/** Whenever we need to implement non_blocking mode using
		 * threads. We will call the function below using thread_create
		 */
		PRINT_DEBUG("recvfrom Address Symbol = %d", symbol);
		recvfrom_udp(uniqueSockID, datalen, flags, symbol);

	} else if (jinniSockets[index].type == SOCK_STREAM) {
		recvfrom_tcp(uniqueSockID, datalen, flags, symbol);

	} else if ((jinniSockets[index].type == SOCK_RAW)
			&& (jinniSockets[index].protocol == IPPROTO_ICMP)) {
		recvfrom_icmp(uniqueSockID, datalen, flags, symbol);

	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

}

void getsockopt_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
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
	struct sockaddr *addr;
	int level;
	int optname;
	int optlen;
	void *optval;

	/** Unlock the main socket channel
	 *
	 */

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &level, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &optname, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &optlen, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	sem_post(meen_channel_semaphore2);
	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is not found too ");
		exit(1);
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
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	//		}
	//		else{
	//
	//			/**
	//			 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
	//			 * Process. Check if an address has been passed or not is required
	//			 */
	//			if(symbol){ // check that the passed address is not NULL
	//				if (jinniSockets[index].type == SOCK_DGRAM)
	//					sendto_udp(uniqueSockID, datalen, data, flags, addr, addrlen);
	//				else if (jinniSockets[index].type == SOCK_STREAM)
	//					sendto_tcp(uniqueSockID, datalen, data, flags, addr, addrlen);
	//				else if (jinniSockets[index].type == SOCK_RAW)
	//				{
	//
	//				}
	//				else{
	//
	//					PRINT_DEBUG("unknown target address !!!");
	//					sem_wait(jinniSockets[index].s);
	//					nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	//					sem_post(jinniSockets[index].as);
	//					sem_post(jinniSockets[index].s);
	//				}
	//
	//			}
	//
	//			else {
	//				PRINT_DEBUG("unknown target address !!!");
	//				sem_wait(jinniSockets[index].s);
	//				nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	//				sem_post(jinniSockets[index].as);
	//				sem_post(jinniSockets[index].s);
	//			}
	//
	//
	//
	//
	//		}

	/**
	 * In case of connected sockets
	 */
	//		if (jinniSockets[index].connection_status > 0){
	//


	PRINT_DEBUG();
	return;

}

void setsockopt_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
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
	struct sockaddr *addr;
	int level;
	int optname;
	int optlen;
	void *optval;

	PRINT_DEBUG("");

	numOfBytes = read(socket_channel_desc, &level, sizeof(int));

	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &optname, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	numOfBytes = read(socket_channel_desc, &optlen, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}

	if (optlen > 0) {

		optval = (u_char *) malloc(optlen);
		numOfBytes = read(socket_channel_desc, optval, optlen);
		if (numOfBytes <= 0) {

			PRINT_DEBUG("READING ERROR! CRASH");
			exit(1);
		}

	}

	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	PRINT_DEBUG("");

	if (index == -1) {
		PRINT_DEBUG(
				"CRASH !!! socket descriptor not found into jinni sockets SO pipe descriptor to reply is notfound too ");
		exit(1);
	}
	PRINT_DEBUG("");

	/**
	 * In case of connected sockets
	 */
	//		if (jinniSockets[index].connection_status > 0){
	//


	if (jinniSockets[index].type == SOCK_DGRAM)
		setsockopt_udp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_STREAM)
		setsockopt_tcp(uniqueSockID, level, optname, optlen, optval);
	else if (jinniSockets[index].type == SOCK_RAW) {
		setsockopt_icmp(uniqueSockID, level, optname, optlen, optval);
	} else {
		PRINT_DEBUG("unknown socket type has been read !!!");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	//		}
	//		else{
	//
	//			/**
	//			 * In case of NON-connected sockets, WE USE THE ADDRESS GIVEN BY the APPlication
	//			 * Process. Check if an address has been passed or not is required
	//			 */
	//			if(symbol){ // check that the passed address is not NULL
	//				if (jinniSockets[index].type == SOCK_DGRAM)
	//					sendto_udp(uniqueSockID, datalen, data, flags, addr, addrlen);
	//				else if (jinniSockets[index].type == SOCK_STREAM)
	//					sendto_tcp(uniqueSockID, datalen, data, flags, addr, addrlen);
	//				else if (jinniSockets[index].type == SOCK_RAW)
	//				{
	//
	//				}
	//				else{
	//
	//					PRINT_DEBUG("unknown target address !!!");
	//					sem_wait(jinniSockets[index].s);
	//					nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	//					sem_post(jinniSockets[index].as);
	//					sem_post(jinniSockets[index].s);
	//				}
	//
	//			}
	//
	//			else {
	//				PRINT_DEBUG("unknown target address !!!");
	//				sem_wait(jinniSockets[index].s);
	//				nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	//				sem_post(jinniSockets[index].as);
	//				sem_post(jinniSockets[index].s);
	//			}
	//
	//
	//
	//
	//		}


	PRINT_DEBUG();
	return;

}

void listen_call_handler(unsigned long long uniqueSockID) {

}
void accept_call_handler(unsigned long long uniqueSockID) {

}

void accept4_call_handler(unsigned long long uniqueSockID) {

}

void shutdown_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	int how;

	PRINT_DEBUG();
	numOfBytes = read(socket_channel_desc, &how, sizeof(int));
	if (numOfBytes <= 0) {

		PRINT_DEBUG("READING ERROR! CRASH");
		exit(1);
	}
	/** Unlock the main socket channel
	 *
	 */
	sem_post(meen_channel_semaphore2);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
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
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

}

void close_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes = -1;

	int index;
	PRINT_DEBUG("socket call handler1");
	PRINT_DEBUG("%llu", uniqueSockID);

	sem_post(meen_channel_semaphore2);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !!socket descriptor not found into jinni sockets");
		exit(1);
	}

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
	if (removejinniSocket(uniqueSockID)) {

		sem_wait(jinniSockets[index].s);
		ack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		/** TODO unlock the semaphore */
		sem_post(jinniSockets[index].s);

	}

	else {

		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		/** TODO unlock the semaphore */
		sem_post(jinniSockets[index].s);

	}

}

void getsockname_call_handker(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	/** Unlock the main socket channel */
	sem_post(meen_channel_semaphore2);

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}

	PRINT_DEBUG("getsockname_handler called")
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = jinniSockets[index].host_IP;
	addr->sin_port = jinniSockets[index].hostport;
	PRINT_DEBUG("%d , %d", jinniSockets[index].host_IP,
			jinniSockets[index].hostport);

	sem_wait(jinniSockets[index].s);
	ack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	write(jinniSockets[index].jinniside_pipe_ds, &addrlen, sizeof(int));
	write(jinniSockets[index].jinniside_pipe_ds, addr, addrlen);
	sem_post(jinniSockets[index].as);
	sem_post(jinniSockets[index].s);

	PRINT_DEBUG("getsockname DONE");

	return;

}

void connect_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

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

	PRINT_DEBUG("%d,%d,%d", addr->sin_addr, ntohs(addr->sin_port),
			addr->sin_family);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}
	if (jinniSockets[index].type == SOCK_DGRAM) {
		connect_udp(uniqueSockID, addr);
	} else if (jinniSockets[index].type == SOCK_STREAM) {
		connect_tcp(uniqueSockID, addr);
	} else {
		PRINT_DEBUG("This socket is of unknown type");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	return;

}
void getpeername_call_handler(unsigned long long uniqueSockID) {

	int numOfBytes;
	int index;
	socklen_t addrlen;
	struct sockaddr_in *addr;

	/** Unlock the main socket channel */
	sem_post(meen_channel_semaphore2);

	addrlen = sizeof(struct sockaddr_in);
	addr = (struct sockaddr_in *) malloc(addrlen);

	/** TODO lock access to the jinnisockets */
	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	/** if that requested socket does not exist !!
	 * this means we can not even talk to the requester FINS crash as a response!!
	 */
	if (index == -1) {
		PRINT_DEBUG(
				" CRASH !socket descriptor not found into jinni sockets! Bind failed on Jinni Side ");

		exit(1);
	}

	PRINT_DEBUG("getpeername_handler called")
	//memset( addr, 0,addrlen);
	addr->sin_family = AF_INET;

	addr->sin_addr.s_addr = ntohl(jinniSockets[index].dst_IP);
	addr->sin_port = jinniSockets[index].dstport;
	PRINT_DEBUG("%d , %d", jinniSockets[index].dst_IP,
			jinniSockets[index].dstport);

	sem_wait(jinniSockets[index].s);
	ack_write(jinniSockets[index].jinniside_pipe_ds, uniqueSockID);
	write(jinniSockets[index].jinniside_pipe_ds, &addrlen, sizeof(int));
	write(jinniSockets[index].jinniside_pipe_ds, addr, addrlen);
	sem_post(jinniSockets[index].as);
	sem_post(jinniSockets[index].s);

	PRINT_DEBUG("getpeername DONE");

	return;

}

void socketpair_call_handler() {

}
