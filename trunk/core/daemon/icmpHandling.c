/*
 * icmphandling.c
 *
 *  Created on: Jun 29, 2011
 *      Author: dell
 */

#include "icmpHandling.h"
#include "finstypes.h"

#define	IP4_PT_ICMP		1

extern sem_t daemonSockets_sem;
extern struct finssocket daemonSockets[MAX_sockets];

extern int recv_thread_count;
extern sem_t recv_thread_sem;

extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;
extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

int daemon_ICMP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));

	metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));

	PRINT_DEBUG();

	metadata_create(udpout_meta);

	if (udpout_meta == NULL) {
		PRINT_DEBUG("metadata creation failed");
		free(ff);
		exit(1);

	}

	/** metadata_writeToElement() set the value of an element if it already exist
	 * or it creates the element and set its value in case it is new
	 */
	PRINT_DEBUG("%d, %d, %d, %d", dstport, dst_IP_netformat, hostport, host_IP_netformat);

	uint32_t dstprt = dstport;
	uint32_t hostprt = hostport;
	int protocol = IP4_PT_ICMP;
	metadata_writeToElement(udpout_meta, "dst_port", &dstprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "src_port", &hostprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "dst_ip", &dst_IP_netformat, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "src_ip", &host_IP_netformat, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "protocol", &protocol, META_TYPE_INT);
	ff->dataOrCtrl = DATA;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = IPV4ID;
	ff->destinationID.next = NULL;
	(ff->dataFrame).directionFlag = DOWN;
	(ff->dataFrame).pduLength = len;
	(ff->dataFrame).pdu = dataLocal;
	(ff->dataFrame).metaData = udpout_meta;

	/**TODO insert the frame into daemon_to_switch queue
	 * check if insertion succeeded or not then
	 * return 1 on success, or -1 on failure
	 * */
	PRINT_DEBUG("");
	sem_wait(&Daemon_to_Switch_Qsem);
	if (write_queue(ff, Daemon_to_Switch_Queue)) {

		sem_post(&Daemon_to_Switch_Qsem);
		PRINT_DEBUG("");
		return (1);
	}
	sem_post(&Daemon_to_Switch_Qsem);
	PRINT_DEBUG("");

	return (0);

}
int ICMPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag) {

	/**TODO MUST BE FIXED LATER
	 * force symbol to become zero
	 */
	//symbol = 0;
	struct finsFrame *ff = NULL;
	int index;
	uint16_t srcport;
	uint32_t srcip;
	struct sockaddr_in * addr_in = (struct sockaddr_in *) address;

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("index = %d", index);
	/**
	 * It keeps looping as a bad method to implement the blocking feature
	 * of recvfrom. In case it is not blocking then the while loop should
	 * be replaced with only a single trial !
	 * TODO Replace the dataqueue with a pipeline (file) this will make it easier
	 * to emulate the file characteristics of the socket such as blocking and non-blocking
	 *
	 */

	PRINT_DEBUG();
	if (block_flag == 1) {
		PRINT_DEBUG();

		do {
			sem_wait(&daemonSockets_sem);
			if (daemonSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&daemonSockets_sem);
				return (0);
			}
			sem_wait(&(daemonSockets[index].Qs));
			//		PRINT_DEBUG();

			ff = read_queue(daemonSockets[index].dataQueue);
			//	ff = get_fake_frame();
			//					PRINT_DEBUG();

			sem_post(&(daemonSockets[index].Qs));
			sem_post(&daemonSockets_sem);
		} while (ff == NULL);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG();
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&daemonSockets_sem);
			return (0);
		}
		sem_wait(&(daemonSockets[index].Qs));
		//ff= read_queue(daemonSockets[index].dataQueue);
		/**	ff = get_fake_frame();
		 print_finsFrame(ff); */
		ff = read_queue(daemonSockets[index].dataQueue);

		sem_post(&(daemonSockets[index].Qs));
		sem_post(&daemonSockets_sem);
	}

	if (ff == NULL) {
		//free(ff);
		return (0);
	}
	PRINT_DEBUG("PDU length %d", ff->dataFrame.pduLength);

	if (metadata_readFromElement(ff->dataFrame.metaData, "src_port", (uint16_t *) &srcport) == 0) {
		addr_in->sin_port = 0;

	}
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_ip", (uint32_t *) &srcip) == 0) {
		addr_in->sin_addr.s_addr = 0;

	}

	/**
	 * making sure that the datagram coming from the destination we are connected to it
	 * in case of connection previously done
	 */
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&daemonSockets_sem);
		return (0);
	}
	if (daemonSockets[index].connection_status > 0) {

		if ((srcport != daemonSockets[index].dstport) || (srcip != daemonSockets[index].dst_IP)) {
			PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
			sem_post(&daemonSockets_sem);
			return (0);

		}

	}
	sem_post(&daemonSockets_sem);

	//*buf = (u_char *)malloc(sizeof(ff->dataFrame.pduLength));
	//memcpy(*buf,ff->dataFrame.pdu,ff->dataFrame.pduLength);
	memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	*buflen = ff->dataFrame.pduLength;

	PRINT_DEBUG();

	if (symbol == 0) {
		//		address = NULL;
		PRINT_DEBUG();
		//	freeFinsFrame(ff);

		return (1);
	}
	PRINT_DEBUG();

	addr_in->sin_family = AF_INET;
	addr_in->sin_port = srcport;
	addr_in->sin_addr.s_addr = srcip;

	/**TODO Free the finsFrame
	 * This is the final consumer
	 * call finsFrame_free(Struct finsFrame** ff)
	 */
	PRINT_DEBUG();

	//freeFinsFrame(ff);

	/** Finally succeeded
	 *
	 */
	return (1);

}

void socket_icmp(int domain, int type, int protocol, unsigned long long uniqueSockID) {

	char clientName[200];
	int index;
	int pipe_desc;
	int tester;

	sem_wait(&daemonSockets_sem);
	index = insert_daemonSocket(uniqueSockID, type, protocol);
	sem_post(&daemonSockets_sem);

	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		nack_send(uniqueSockID, socket_call, 0);
		return;
	}
	PRINT_DEBUG("0000");

	ack_send(uniqueSockID, socket_call, 0);
	PRINT_DEBUG("0003");

	return;

}

void write_icmp(unsigned long long uniqueSockID, int datalen, u_char *data) {

}

void recv_icmp(unsigned long long uniqueSockID, int datalen, int flags) {

}

void sendto_icmp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *addr, socklen_t addrlen) {
	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;

	int len = datalen;

	PRINT_DEBUG();

	/** TODO handle flags cases */
	switch (flags) {
	case MSG_CONFIRM:
	case MSG_DONTROUTE:
	case MSG_DONTWAIT:
	case MSG_EOR:
	case MSG_MORE:
	case MSG_NOSIGNAL:
	case MSG_OOB: /** case of recieving a (write call)*/
	default:
		break;

	}
	PRINT_DEBUG("");

	struct sockaddr_in *address;
	address = (struct sockaddr_in *) addr;

	if (address->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, sendmsg_call, 0);
		PRINT_DEBUG("");
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = ntohs(address->sin_port); /** reverse it since it is in network order after application used htons */

	dst_IP = ntohl(address->sin_addr.s_addr);/** it is in network format since application used htonl */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_wait(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = daemonSockets[index].hostport;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = daemonSockets[index].host_IP;
	sem_post(&daemonSockets_sem);
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	int blocking_flag = 1; //TODO get from flags

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (daemon_ICMP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		PRINT_DEBUG("");
		ack_send(uniqueSockID, sendmsg_call, 0);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish sendto");
		nack_send(uniqueSockID, sendmsg_call, 0);
	}

	return;

}

void recvfrom_icmp(void *threadData) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	//	u_char *buf=NULL;
	//	buf = (u_char *)malloc(MAX_DATA_PER_UDP);
	u_char buf[MAX_DATA_PER_UDP];

	u_char *bufptr;
	bufptr = buf;
	struct sockaddr_in *address;
	int buflen = 0;
	int index;
	int i;
	int blocking_flag;
	int addressLen = sizeof(struct sockaddr_in);

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	struct recvfrom_data *thread_data;
	thread_data = (struct recvfrom_data *) threadData;

	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int socketCallType = thread_data->socketCallType;
	int datalen = thread_data->datalen;
	int flags = thread_data->flags;
	int symbol = thread_data->symbol;

	PRINT_DEBUG("Entered recv thread:%d", thread_data->id);

	sem_wait(&daemonSockets_sem);
	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);
		recvthread_exit(thread_data);
	}

	PRINT_DEBUG("index = %d", index);

	if (daemonSockets[index].protocol == IPPROTO_ICMP)
		symbol = 1;

	PRINT_DEBUG();
	blocking_flag = daemonSockets[index].blockingFlag;
	sem_post(&daemonSockets_sem);

	if (symbol == 1)
		address = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	address = NULL;
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */

	if (ICMPreadFrom_fins(uniqueSockID, bufptr, &buflen, symbol, address, blocking_flag) == 1) {

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("%d", buflen);
		PRINT_DEBUG("%s", buf);

		msg_len = 4 * sizeof(int) + sizeof(unsigned long long) + buflen + (symbol ? sizeof(int) + addressLen : 0);
		msg = malloc(msg_len);
		pt = msg;

		*(int *) pt = socketCallType;
		pt += sizeof(int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *) pt = ACK;
		pt += sizeof(int);

		*(int *) pt = 0;
		pt += sizeof(int);

		if (symbol) {
			*(int *) pt = addressLen;
			pt += sizeof(int);

			memcpy(pt, address, addressLen);
			pt += addressLen;
		}

		*(int *) pt = buflen;
		pt += sizeof(int);

		memcpy(pt, buf, buflen);
		pt += buflen;

		if (pt - (u_char *) msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
			free(msg);
			recvthread_exit(thread_data);
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);

		//free(buf);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish recvfrom");
		sem_wait(&daemonSockets_sem);
		index = find_daemonSocket(uniqueSockID);
		sem_post(&daemonSockets_sem);

		if (index == -1) {
			PRINT_DEBUG("socket descriptor not found into daemon sockets");
			recvthread_exit(thread_data);
		} else {
			nack_send(uniqueSockID, socketCallType, 0);
		}
	}
	PRINT_DEBUG();

	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(address);
	//free(buf);
	recvthread_exit(thread_data);
}
void sendmsg_icmp() {

}
void recvmsg_icmp() {

}
void getsockopt_icmp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval) {

	//TODO: convert

	int optvalue = -1;
	index = find_daemonSocket(uniqueSockID);

	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG();

	//ack_write(daemonSockets[index].daemonside_pipe_ds, uniqueSockID);
	//write(daemonSockets[index].daemonside_pipe_ds, &optlen, sizeof(socklen_t));

	switch (level) {
	case SOL_SOCKET:
		switch (optname) {
		case SO_RCVBUF:
			/** This is just a dummy value taken from strace but this will change to actual
			 * value once the socket options get fully implemented
			 */

			optvalue = 131072;
			//write(daemonSockets[index].daemonside_pipe_ds, &optvalue, optlen);

		}
	default:
		break;

	}

	return;

}
void setsockopt_icmp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval) {

	index = find_daemonSocket(uniqueSockID);

	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG();

	ack_send(uniqueSockID, setsockopt_call, 0);

	return;

}

void shutdown_icmp(unsigned long long uniqueSockID, int how) {

}

void release_icmp(int index, unsigned long long uniqueSockID) {
	int ret;

	PRINT_DEBUG("release_icmp: index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_icmp.");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, recvmsg_call, 0);
		return;
	}

	ret = remove_daemonSocket(uniqueSockID);

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (ret) {
		ack_send(uniqueSockID, release_call, 0);
	} else {
		nack_send(uniqueSockID, release_call, 0);
	}
}

void listen_icmp(int index, unsigned long long uniqueSockID, int backlog) {
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, listen_call, 0);
		return;
	}

	daemonSockets[index].listening = 1;
	daemonSockets[index].backlog = backlog;
	sem_post(&daemonSockets_sem);

	ack_send(uniqueSockID, listen_call, 0);
}

void accept_icmp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags) {
	//TODO: finish this
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, accept_call, 0);
		return;
	}
	sem_post(&daemonSockets_sem);

	ack_send(uniqueSockID, accept_call, 0);
}

void getname_icmp(int index, unsigned long long uniqueSockID, int peer) {
	int status;
	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	PRINT_DEBUG("getname_tcp CALL");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	if (peer == 1) { //TODO find right number
		host_ip = daemonSockets[index].host_IP;
		host_port = daemonSockets[index].hostport;
	} else if (peer == 2) {
		status = daemonSockets[index].connection_status;
		if (status) {
			rem_ip = daemonSockets[index].dst_IP;
			rem_port = daemonSockets[index].dstport;
		}
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	struct sockaddr_in *addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if (addr == NULL) {
		PRINT_DEBUG("getname_tcp: addr creation failed");
		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	if (peer == 1) { //TODO find right number
		//getsockname
	} else if (peer == 2) {
		addr->sin_addr.s_addr = host_ip;
		//addr->sin_addr.s_addr = htonl(host_ip);
		addr->sin_port = htons(host_port);
	} else {
		//TODO ??
	}

	int msg_len = 5 * sizeof(int) + sizeof(unsigned long long) + sizeof(struct sockaddr_in);
	u_char *msg = (u_char *) malloc(msg_len);
	if (msg == NULL) {
		PRINT_DEBUG("getname_tcp: Exiting, msg creation fail: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
		free(addr);
		return;
	}
	u_char *pt = msg;

	*(int *) pt = getname_call;
	pt += sizeof(int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = 0;
	pt += sizeof(int);

	*(int *) pt = peer;
	pt += sizeof(int);

	*(int *) pt = sizeof(addr);
	pt += sizeof(int);

	memcpy(pt, &addr, sizeof(addr));
	pt += sizeof(struct sockaddr);

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		PRINT_DEBUG("getname_tcp: Exiting, No fdf: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("getname_tcp: Exiting, fail send_wedge: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
	} else {
		PRINT_DEBUG("getname_tcp: Exiting, normal: index=%d, uniqueSockID=%llu", index, uniqueSockID);
	}

	free(msg);
}

void ioctl_icmp(int index, unsigned long long uniqueSockID, u_int cmd, u_char *buf, ssize_t buf_len) {
	u_int len;
	int msg_len;
	u_char *msg = NULL;
	u_char *pt;

	PRINT_DEBUG("ioctl_icmp CALL");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, ioctl_call, 0);
		return;
	}

	len = daemonSockets[index].buf_data;

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	switch (cmd) {
	case FIONREAD:
		PRINT_DEBUG("FIONREAD cmd=%d", cmd);
		//figure out buffered data

		//send msg to wedge
		msg_len = 4 * sizeof(u_int) + sizeof(unsigned long long);
		msg = (u_char *) malloc(msg_len);
		pt = msg;

		*(u_int *) pt = ioctl_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = ACK;
		pt += sizeof(u_int);

		*(u_int *) pt = 0;
		pt += sizeof(u_int);

		*(u_int *) pt = len;
		pt += sizeof(u_int);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, ioctl_call, 0);
			return;
		}
		break;
	default:
		PRINT_DEBUG("default cmd=%d", cmd);
		return;
	}

	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("ioctl_icmp: Exiting, fail send_wedge: uniqueSockID=%llu", uniqueSockID);
			nack_send(uniqueSockID, ioctl_call, 0);
		}
		free(msg);
	} else {
		nack_send(uniqueSockID, ioctl_call, 0);
	}
}
