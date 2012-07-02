/**
 * @file udpHandling.c
 *
 *  @date Nov 28, 2010
 *   @author Abdallah Abdallah
 */

#include "udpHandling.h"
#include "finstypes.h"

#define	IP4_PT_UDP		17

extern sem_t daemonSockets_sem;
extern struct finssocket daemonSockets[MAX_sockets];

extern int thread_count;
extern sem_t thread_sem;

extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;
extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

struct finsFrame *get_fake_frame() {

	struct finsFrame *f = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	PRINT_DEBUG("2.1");

	int linkvalue = 80211;
	char linkname[] = "linklayer";
	unsigned char *fakeData = (unsigned char *) malloc(10);
	strncpy(fakeData, "loloa7aa7a", 10);
	//fakeData = "loloa7aa7a";

	metadata *metaptr = (metadata *) malloc(sizeof(metadata));

	PRINT_DEBUG("2.2");
	//	metadata_create(metaptr);
	PRINT_DEBUG("2.3");
	//	metadata_addElement(metaptr,linkname,META_TYPE_INT);
	PRINT_DEBUG("2.4");
	//	metadata_writeToElement(metaptr,linkname,&linkvalue,META_TYPE_INT);
	PRINT_DEBUG("2.5");
	f->dataOrCtrl = DATA;
	f->destinationID.id = (unsigned char) SOCKETSTUBID;
	f->destinationID.next = NULL;

	(f->dataFrame).directionFlag = UP;
	//	(f->dataFrame).metaData		= metaptr;
	(f->dataFrame).metaData = NULL;
	(f->dataFrame).pdu = fakeData;
	(f->dataFrame).pduLength = 10;

	return (f);

}

/**
 *  Functions interfacing socketdaemon_UDP with FINS core
 *
 */

int UDPreadFrom_fins(int index, unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag,
		int multi_flag) {

	/**TODO MUST BE FIXED LATER
	 * force symbol to become zero
	 */
	//symbol = 0;
	struct finsFrame *ff = NULL;
	struct finsFrame *ff_copy = NULL;
	uint16_t srcport;
	uint32_t srcip;
	struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
	int i;

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

		int value;
		sem_getvalue(&(daemonSockets[index].Qs), &value);
		PRINT_DEBUG("uniqID=%llu sem: ind=%d, val=%d", uniqueSockID, index, value);
		PRINT_DEBUG("block=%d, multi=%d, threads=%d", block_flag, multi_flag, daemonSockets[index].threads);

		do {
			PRINT_DEBUG("");
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

			if (ff && multi_flag) {
				PRINT_DEBUG("index=%d threads=%d replies=%d", index, daemonSockets[index].threads, daemonSockets[index].replies);
				if (daemonSockets[index].replies) {
					daemonSockets[index].replies--;
				} else {
					daemonSockets[index].replies = daemonSockets[index].threads - 1;
					for (i = 0; i < daemonSockets[index].replies; i++) {
						PRINT_DEBUG("adding frame copy, threads=%d", daemonSockets[index].threads);
						ff_copy = (struct finsFrame *) malloc(sizeof(struct finsFrame));
						cpy_fins_to_fins(ff_copy, ff); //copies pointers, freeFinsFrame doesn't free pointers
						if (!write_queue_front(ff_copy, daemonSockets[index].dataQueue)) {
							; //error
						}
					}
				}
			}

			sem_post(&(daemonSockets[index].Qs));
			PRINT_DEBUG("");
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

		if (ff && multi_flag) {
			PRINT_DEBUG("index=%d threads=%d replies=%d", index, daemonSockets[index].threads, daemonSockets[index].replies);
			if (daemonSockets[index].replies) {
				daemonSockets[index].replies--;
			} else {
				daemonSockets[index].replies = daemonSockets[index].threads - 1;
				for (i = 0; i < daemonSockets[index].replies; i++) {
					PRINT_DEBUG("adding frame copy, threads=%d", daemonSockets[index].threads);
					ff_copy = (struct finsFrame *) malloc(sizeof(struct finsFrame));
					cpy_fins_to_fins(ff_copy, ff); //copies pointers, freeFinsFrame doesn't free pointers
					if (!write_queue_front(ff_copy, daemonSockets[index].dataQueue)) {
						; //error
					}
				}
			}
		}

		sem_post(&(daemonSockets[index].Qs));
		PRINT_DEBUG("");
		sem_post(&daemonSockets_sem);
	}

	if (ff == NULL) {
		//free(ff);
		return (0);
	}
	PRINT_DEBUG("recv'd uniqID=%llu ind=%d", uniqueSockID, index);
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
	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&daemonSockets_sem);
		return (0);
	}
	PRINT_DEBUG("Rest of read for index=%d.", index);

	if (daemonSockets[index].connection_status > 0) {
		if ((srcport != daemonSockets[index].dstport) || (srcip != daemonSockets[index].dst_IP)) {
			PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
			sem_post(&daemonSockets_sem);
			return (0);
		}
	}
	PRINT_DEBUG("");
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

} //end of readFrom_fins

int daemon_UDP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));

	metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));

	PRINT_DEBUG();

	if (udpout_meta == NULL) {
		PRINT_DEBUG("metadata creation failed");
		free(ff);
		return 0;
	}

	metadata_create(udpout_meta);

	/** metadata_writeToElement() set the value of an element if it already exist
	 * or it creates the element and set its value in case it is new
	 */
	PRINT_DEBUG("%d, %d, %d, %d", dstport, dst_IP_netformat, hostport, host_IP_netformat);

	uint32_t dstprt = dstport;
	uint32_t hostprt = hostport;
	int protocol = IP4_PT_UDP;
	metadata_writeToElement(udpout_meta, "dst_port", &dstprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "src_port", &hostprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "dst_ip", &dst_IP_netformat, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "src_ip", &host_IP_netformat, META_TYPE_INT);

	metadata_writeToElement(udpout_meta, "protocol", &protocol, META_TYPE_INT);
	ff->dataOrCtrl = DATA;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = UDPID;
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

	metadata_destroy(udpout_meta);

	return (0);
}

/**
 * End of interfacing socketdaemon with FINS core
 * */
void socket_udp(int domain, int type, int protocol, unsigned long long uniqueSockID) {
	int index;

	PRINT_DEBUG("socket_UDP CALL");

	sem_wait(&daemonSockets_sem);
	index = insert_daemonSocket(uniqueSockID, type, protocol);
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		nack_send(uniqueSockID, socket_call, 0);
		return;
	}

	ack_send(uniqueSockID, socket_call, 0);
}

void bind_udp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP_netformat;
	uint32_t dst_IP_netformat;

	PRINT_DEBUG("bind_UDP CALL");

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family=%d", addr->sin_family);
		nack_send(uniqueSockID, bind_call, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	hostport = ntohs(addr->sin_port);
	host_IP_netformat = addr->sin_addr.s_addr;

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);
	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the daemonSockets database
	 */
	PRINT_DEBUG("bind address: host=%s/%d host_IP_netformat=%d", inet_ntoa(addr->sin_addr), hostport, host_IP_netformat);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, bind_call, 0);
		return;
	}

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!check_daemon_ports(hostport, host_IP_netformat) && !daemonSockets[index].sockopts.FSO_REUSEADDR) {
		PRINT_DEBUG("this port is not free");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, bind_call, 0);
		free(addr);
		return;
	}

	/**
	 * Binding
	 */
	daemonSockets[index].hostport = hostport;
	daemonSockets[index].host_IP = host_IP_netformat;

	PRINT_DEBUG("bind: index:%d, host:%d/%d, dst:%d/%d",
			index, daemonSockets[index].host_IP, daemonSockets[index].hostport, daemonSockets[index].dst_IP, daemonSockets[index].dstport);
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[index].host_IP.s_addr = ntohl(daemonSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send(uniqueSockID, bind_call, 0);

	free(addr);
} // end of bind_udp

void listen_udp(int index, unsigned long long uniqueSockID, int backlog) {
	PRINT_DEBUG("listen_UDP CALL");

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, listen_call, 0);
		return;
	}

	daemonSockets[index].listening = 1;
	daemonSockets[index].backlog = backlog;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	ack_send(uniqueSockID, listen_call, 0);
}

void connect_udp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr) {

	uint16_t dstport;
	uint32_t dst_IP;

	PRINT_DEBUG("connect_UDP CALL");

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, connect_call, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	dstport = ntohs(addr->sin_port);
	dst_IP = ntohl((addr->sin_addr).s_addr);

	PRINT_DEBUG("%d,%d,%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family);

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * according to the RFC document and man pages: Application can call connect more than
	 * once over the same UDP socket changing the address from one to another. SO the assigning
	 * will take place even if the check functions returns (-1) !!!
	 * */

	/** TODO connect for UDP means that this address will be the default address to send
	 * to. BUT IT WILL BE ALSO THE ONLY ADDRESS TO RECEIVER FROM
	 *	NOTICE THAT the relation
	 * */

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, connect_call, 0);
		return;
	}

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (daemonSockets[index].connection_status > 0) {
		PRINT_DEBUG("old destined address %d, %d", daemonSockets[index].dst_IP, daemonSockets[index].dstport);
		PRINT_DEBUG("new destined address %d, %d", dst_IP, dstport);

	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);
	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the daemonSockets database
	 */
	daemonSockets[index].dst_IP = dst_IP;
	daemonSockets[index].dstport = dstport;
	daemonSockets[index].connection_status++;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[index].host_IP.s_addr = ntohl(daemonSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send(uniqueSockID, connect_call, 0);

	free(addr);
	return;

}

void accept_udp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags) {

	PRINT_DEBUG("accept_UDP CALL");

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

void getname_udp(int index, unsigned long long uniqueSockID, int peer) {
	int status;
	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	PRINT_DEBUG("getname_udp CALL");
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
		PRINT_DEBUG("getname_udp: addr creation failed");
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

	int msg_len = 3 * sizeof(u_int) + sizeof(unsigned long long) +  sizeof(int) + sizeof(struct sockaddr_in);
	u_char *msg = (u_char *) malloc(msg_len);
	if (msg == NULL) {
		PRINT_DEBUG("getname_udp: Exiting, msg creation fail: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
		free(addr);
		return;
	}
	u_char *pt = msg;

	*(u_int *) pt = getname_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = ACK;
	pt += sizeof(u_int);

	*(u_int *) pt = 0;
	pt += sizeof(u_int);

	*(int *) pt = peer;
	pt += sizeof(int);

	memcpy(pt, &addr, sizeof(addr));
	pt += sizeof(struct sockaddr);

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		PRINT_DEBUG("getname_udp: Exiting, No fdf: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("getname_udp: Exiting, fail send_wedge: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send(uniqueSockID, getname_call, 0);
	} else {
		PRINT_DEBUG("getname_udp: Exiting, normal: index=%d, uniqueSockID=%llu", index, uniqueSockID);
	}

	free(msg);
}

void write_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;

	PRINT_DEBUG("");

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (daemonSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketdaemon failed to accomplish send");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = daemonSockets[index].dstport;

	dst_IP = daemonSockets[index].dst_IP;

	//hostport = daemonSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	//hostport = daemonSockets[index].hostport;
	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firsly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = daemonSockets[index].hostport;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = daemonSockets[index].host_IP;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (daemon_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1) {
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, sendmsg_call, 0);
		PRINT_DEBUG("");
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		nack_send(uniqueSockID, sendmsg_call, 0);
	}
} // end of write_udp

void send_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;

	if (flags == -1000) {
		return write_udp(index, uniqueSockID, data, datalen);
	}
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
	} // end of the switch clause

	PRINT_DEBUG("");

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (daemonSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = daemonSockets[index].dstport;

	dst_IP = daemonSockets[index].dst_IP;

	//hostport = daemonSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = daemonSockets[index].host_IP;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = daemonSockets[index].hostport;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("addr %d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	int blocking_flag = 1; //TODO get from flags

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (daemon_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, sendmsg_call, 0);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		nack_send(uniqueSockID, sendmsg_call, 0);
	}
} // end of send_udp

void sendto_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *addr, socklen_t addrlen) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;

	int len = datalen;
	int i;

	struct in_addr *temp;

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

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");

	dst_IP = ntohl(addr->sin_addr.s_addr);/** it is in network format since application used htonl */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = ntohs(addr->sin_port); /** reverse it since it is in network order after application used htons */

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, sendmsg_call, 0);
		return;
	}

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = daemonSockets[index].host_IP;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = daemonSockets[index].hostport;
	if (hostport == 0) {
		while (1) {
			hostport = randoming(MIN_port, MAX_port);
			if (check_daemon_ports(hostport, host_IP)) {
				break;
			}
		}
		daemonSockets[index].hostport = hostport;
	}
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("index=%d, dst=%u/%d, host=%u/%d", index, dst_IP, dstport, host_IP, hostport);

	temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = host_IP;
	PRINT_DEBUG("index=%d, dst=%s/%d, host=%s/%d", index, inet_ntoa(addr->sin_addr), dstport, inet_ntoa(*temp), hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	int blocking_flag = 1; //TODO get from flags

	/** the meta-data parameters are all passes by copy starting from this point
	 *
	 */
	if (daemon_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, sendmsg_call, 0);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish sendto");
		nack_send(uniqueSockID, sendmsg_call, 0);
	}

	return;

} //end of sendto_udp

void *recvfrom_udp_thread(void *local) {
	struct daemon_udp_thread_data *thread_data = (struct daemon_udp_thread_data *) local;
	int id = thread_data->id;
	int index = thread_data->index;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int data_len = thread_data->data_len;
	int flags = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("recvfrom_udp_thread: Entered: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);

	int blocking_flag = 1; //TODO get from flags

	PRINT_DEBUG();
	struct finsFrame *ff = get_fdf(index, uniqueSockID, blocking_flag);
	PRINT_DEBUG("after get_fdf uniqID=%llu ind=%d", uniqueSockID, index);

	if (ff == NULL) {
		PRINT_DEBUG("recvfrom_udp_thread: Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call, 0); //TODO check return of nonblocking send
		pthread_exit(NULL);
	}

	struct sockaddr_in addr;
	uint32_t src_port;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_port", &src_port) == 0) {
		addr.sin_port = 0;
	} else {
		addr.sin_port = (uint16_t) src_port;
	}

	uint32_t src_ip;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_ip", &src_ip) == 0) {
		addr.sin_addr.s_addr = 0;
	} else {
		addr.sin_addr.s_addr = (uint32_t) htonl(src_ip);
	}

	//#######
	PRINT_DEBUG("address: %d/%d", addr.sin_addr.s_addr, ntohs(addr.sin_port));
	PRINT_DEBUG("address: addr=%s/%d", inet_ntoa(addr.sin_addr), addr.sin_port);
	//#######

	int msg_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + sizeof(struct sockaddr_in) + ff->dataFrame.pduLength;
	u_char *msg = (u_char *) malloc(msg_len);
	u_char *pt = msg;

	*(u_int *) pt = recvmsg_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = ACK;
	pt += sizeof(u_int);

	*(u_int *) pt = 0;
	pt += sizeof(u_int);

	memcpy(pt, &addr, sizeof(struct sockaddr_in));
	pt += sizeof(struct sockaddr_in);

	*(int *) pt = ff->dataFrame.pduLength;
	pt += sizeof(int);

	memcpy(pt, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	pt += ff->dataFrame.pduLength;

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		PRINT_DEBUG("recvfrom_udp_thread: Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call, 0);
		pthread_exit(NULL);
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("recvfrom_udp_thread: Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call, 0);
	} else {
		PRINT_DEBUG("recvfrom_udp_thread: Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
	}

	free(msg);
	pthread_exit(NULL);
}

/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvfrom_udp(int index, unsigned long long uniqueSockID, int data_len, int flags, int msg_flags) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	int multi_flag;
	int thread_flags;

	PRINT_DEBUG("recvfrom_udp: Entered: index=%d uniqueSockID=%llu data_len=%d flags=%d", index, uniqueSockID, data_len, flags);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, recvmsg_call, 0);
		return;
	}

	multi_flag = 0; //for udp, if SOL_SOCKET/SO_REUSEADDR
	//change flags?

	/** TODO handle flags cases, convert flags/msg_flags to */
	thread_flags = 0; // |= FLAGS_BLOCK | MULTI_FLAG;

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (1) { //TODO thread count check
		pthread_t thread;
		struct daemon_udp_thread_data *thread_data = (struct daemon_udp_thread_data *) malloc(sizeof(struct daemon_udp_thread_data));
		thread_data->id = thread_count++;
		thread_data->index = index;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->data_len = data_len;
		thread_data->flags = thread_flags;

		//spin off thread to handle
		if (pthread_create(&thread, NULL, recvfrom_udp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create recvfrom_udp_thread thread.");
			nack_send(uniqueSockID, recvmsg_call, 0);

			free(thread_data);
		}
	}
}

void release_udp(int index, unsigned long long uniqueSockID) {
	int ret;

	PRINT_DEBUG("release_udp: index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_udp.");
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

/** .......................................................................*/
/**
 * @brief recv_udp
 *
 */

void recv_udp(unsigned long long uniqueSockID, int datalen, int flags) {

	//u_char *buf= NULL;
	u_char buf[MAX_DATA_PER_UDP];
	int buflen = 0;
	int index;
	int i;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	int blocking_flag;
	int multi_flag;

	blocking_flag = 1;
	multi_flag = 0; //for udp, if SOL_SOCKET/SO_REUSEADDR
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG();

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */
	/** passing 0 as value for symbol, and NULL as an address
	 * this the difference between the call from here, and the call in case of
	 * the function recvfrom_udp
	 * */
	if (UDPreadFrom_fins(index, uniqueSockID, buf, &buflen, 0, NULL, blocking_flag, multi_flag) == 1) {

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("%d", buflen);
		PRINT_DEBUG("%s", buf);

		msg_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + buflen;
		msg = malloc(msg_len);
		pt = msg;

		*(u_int *) pt = recv_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(u_int *) pt = ACK;
		pt += sizeof(u_int);

		*(u_int *) pt = 0;
		pt += sizeof(u_int);

		*(int *) pt = buflen;
		pt += sizeof(int);

		memcpy(pt, buf, buflen);
		pt += buflen;

		if (pt - (u_char *) msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
			free(msg);
			nack_send(uniqueSockID, recv_call, 0);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);
		if (ret_val) {
			nack_send(uniqueSockID, recv_call, 0);
		}

		PRINT_DEBUG();

		//	free(buf);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish recv_udp");
		nack_send(uniqueSockID, recv_call, 0);
	}

	PRINT_DEBUG();
	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(address);
	//free(buf);
} // end of recv_udp

/** .......................................................................*/

void shutdown_udp(unsigned long long uniqueSockID, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	int index;

	index = find_daemonSocket(uniqueSockID);
	/** TODO unlock access to the daemonsockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);

	ack_send(uniqueSockID, shutdown_call, 0);
}

void setsockopt_udp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, u_char *optval) {

	PRINT_DEBUG("setsockopt_udp: index=%d, uniqueSockID=%llu, level=%d, optname=%d, optlen=%d", index, uniqueSockID, level, optname, optlen);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling getsockopt_udp.");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, setsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	/*
	 * 7 levels+:
	 * IPPPROTO_IP
	 * IPPPROTO_IPv6
	 * IPPPROTO_ICMP
	 * IPPPROTO_RAW
	 * IPPPROTO_TCP
	 * IPPPROTO_UDP
	 * SOL_SOCKET
	 */

	switch (optname) {
	case SO_DEBUG:
		daemonSockets[index].sockopts.FSO_DEBUG = *(int *) optval;
		PRINT_DEBUG("FSO_DEBUG=%d", daemonSockets[index].sockopts.FSO_DEBUG);
		break;
	case SO_REUSEADDR:
		daemonSockets[index].sockopts.FSO_REUSEADDR = *(int *) optval;
		PRINT_DEBUG("FSO_REUSEADDR=%d", daemonSockets[index].sockopts.FSO_REUSEADDR);
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
	case SO_OOBINLINE:
	case SO_NO_CHECK:
	case SO_PRIORITY:
	case SO_LINGER:
	case SO_BSDCOMPAT:
	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
	case SO_TIMESTAMPING:
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_PASSCRED:
	case SO_PEERCRED:
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_ATTACH_FILTER:
	case SO_DETACH_FILTER:
	default:
		PRINT_DEBUG("default=%d", optname);
		break;
	}

	ack_send(uniqueSockID, setsockopt_call, 0);

	/*
	 metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));
	 metadata_create(udpout_meta);
	 metadata_writeToElement(udpout_meta, "dstport", &dstprt, META_TYPE_INT);
	 */

	/** check the opt_name to find which bit to access in the options variable then use
	 * the following code to handle the bits individually
	 * setting a bit   number |= 1 << x;  That will set bit x.
	 * Clearing a bit number &= ~(1 << x); That will clear bit x.
	 * The XOR operator (^) can be used to toggle a bit. number ^= 1 << x; That will toggle bit x.
	 * Checking a bit      value = number & (1 << x);
	 */
	//uint32_t socketoptions;
}

void getsockopt_udp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, u_char *optval) {
	int len;
	char *val;
	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	PRINT_DEBUG("getsockopt_udp: index=%d, uniqueSockID=%llu, level=%d, optname=%d, optlen=%d", index, uniqueSockID, level, optname, optlen);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling getsockopt_udp.");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	/*
	 metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));
	 metadata_create(udpout_meta);
	 metadata_writeToElement(udpout_meta, "dstport", &dstprt, META_TYPE_INT);
	 */

	switch (optname) {
	case SO_DEBUG:
		//daemonSockets[index].sockopts.FSO_DEBUG = *(int *)optval;
		break;
	case SO_REUSEADDR:
		len = sizeof(int);
		val = (char *) &(daemonSockets[index].sockopts.FSO_REUSEADDR);
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
	case SO_OOBINLINE:
	case SO_NO_CHECK:
	case SO_PRIORITY:
	case SO_LINGER:
	case SO_BSDCOMPAT:
	case SO_TIMESTAMP:
	case SO_TIMESTAMPNS:
	case SO_TIMESTAMPING:
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
	case SO_PASSCRED:
	case SO_PEERCRED:
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_ATTACH_FILTER:
	case SO_DETACH_FILTER:
	default:
		//nack?
		break;
	}

	msg_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + len;
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = getsockopt_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = ACK;
	pt += sizeof(u_int);

	*(u_int *) pt = 0;
	pt += sizeof(u_int);

	*(int *) pt = len;
	pt += sizeof(int);

	memcpy(pt, val, len);
	pt += len;

	if (pt - (u_char *) msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
		free(msg);
		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		nack_send(uniqueSockID, getsockopt_call, 0);
	}
}

//############################## Deprecated, not used & only temp keeping

/**
 * @brief getpeername_udp
 *
 */

void getpeername_udp(unsigned long long uniqueSockID, int addrlen) {
	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	int index;
	struct sockaddr_in address;
	int address_length = sizeof(struct sockaddr_in);
	index = find_daemonSocket(uniqueSockID);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = daemonSockets[index].dst_IP;
	address.sin_port = daemonSockets[index].dstport;
	memset(address.sin_zero, 0, 8);

	PRINT_DEBUG("*****%d*********%d , %d*************", sizeof(struct sockaddr_in), address.sin_addr.s_addr, address.sin_port)

	msg_len = 3 * sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + sizeof(struct sockaddr_in);
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = 0; //getpeername_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = ACK;
	pt += sizeof(u_int);

	*(u_int *) pt = 0;
	pt += sizeof(u_int);

	*(int *) pt = sizeof(struct sockaddr_in);
	pt += sizeof(int);

	memcpy(pt, &address, address_length);
	pt += sizeof(struct sockaddr_in);

	if (pt - (u_char *) msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
		free(msg);
		//nack_send(uniqueSockID, getpeername_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		//nack_send(uniqueSockID, getpeername_call, 0);
	}
}

