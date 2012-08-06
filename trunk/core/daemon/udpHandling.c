/**
 * @file udpHandling.c
 *
 *  @date Nov 28, 2010
 *   @author Abdallah Abdallah
 */

#include "udpHandling.h"
#include <finstypes.h>

#define	IP4_PT_UDP		17

extern sem_t daemonSockets_sem;
extern struct fins_daemon_socket daemonSockets[MAX_SOCKETS];

extern int thread_count;
extern sem_t thread_sem;

extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;
extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

//#include <unistd.h> //TODO remove

struct finsFrame *get_fake_frame() {

	struct finsFrame *f = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	PRINT_DEBUG("2.1");

	//int linkvalue = 80211;
	//char linkname[] = "linklayer";
	unsigned char *fakeData = (unsigned char *) malloc(10);
	strncpy((char *) fakeData, "loloa7aa7a", 10);
	//fakeData = "loloa7aa7a";

	//metadata *metaptr = (metadata *) malloc(sizeof(metadata));

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

	if (daemonSockets[index].state > SS_UNCONNECTED) {
		if ((srcport != daemonSockets[index].dst_port) || (srcip != daemonSockets[index].dst_ip)) {
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
		PRINT_DEBUG("metadata creation failed, freeing: ff=%x", (int) ff);
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
void socket_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol) {
	int ret;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d domain=%d type=%d proto=%d",
			uniqueSockID, index, call_id, call_index, domain, type, protocol);

	sem_wait(&daemonSockets_sem);
	ret = insert_daemonSocket_new(uniqueSockID, index, type, protocol);
	PRINT_DEBUG("index=%d ret=%d", index, ret);
	sem_post(&daemonSockets_sem);

	if (ret) {
		nack_send_new(uniqueSockID, index, call_id, call_index, socket_call, 0);
	} else {
		ack_send_new(uniqueSockID, index, call_id, call_index, socket_call, 0);
	}
}

void bind_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr) {

	uint16_t host_port;
	uint32_t host_ip;

	PRINT_DEBUG("socket_udp: Entered: uniqueSockID=%llu index=%d id=%u index=%d", uniqueSockID, index, call_id, call_index);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family=%d", addr->sin_family);
		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	host_port = ntohs(addr->sin_port);
	host_ip = ntohl(addr->sin_addr.s_addr);

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);
	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the daemonSockets database
	 */
	PRINT_DEBUG("bind address: host=%s/%d host_IP_netformat=%d", inet_ntoa(addr->sin_addr), host_port, addr->sin_addr.s_addr);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!check_daemon_ports(host_port, host_ip) && !daemonSockets[index].sockopts.FSO_REUSEADDR) {
		PRINT_DEBUG("this port is not free");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		free(addr);
		return;
	}

	/**
	 * Binding
	 */
	daemonSockets[index].host_port = host_port;

	if (host_ip == any_ip_addr) { //TODO change this when have multiple interfaces
		daemonSockets[index].host_ip = my_host_ip_addr;
	} else {
		daemonSockets[index].host_ip = host_ip;
	}

	PRINT_DEBUG("bind: index:%d, host:%d/%d, dst:%d/%d",
			index, daemonSockets[index].host_ip, daemonSockets[index].host_port, daemonSockets[index].dst_ip, daemonSockets[index].dst_port);
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[index].host_IP.s_addr = ntohl(daemonSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);

	free(addr);
} // end of bind_udp

void listen_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog) {
	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d backlog=%d", uniqueSockID, index, call_id, call_index, backlog);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
		return;
	}

	daemonSockets[index].listening = 1;
	daemonSockets[index].backlog = backlog;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	ack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
}

void connect_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags) {

	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d flags=%d", uniqueSockID, index, call_id, call_index, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	dst_ip = ntohl((addr->sin_addr).s_addr);
	dst_port = ntohs(addr->sin_port);

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

		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		return;
	}

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (daemonSockets[index].state > SS_UNCONNECTED) {
		PRINT_DEBUG("old destined address %d, %d", daemonSockets[index].dst_ip, daemonSockets[index].dst_port);
		PRINT_DEBUG("new destined address %d, %d", dst_ip, dst_port);

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
	daemonSockets[index].dst_ip = dst_ip;
	daemonSockets[index].dst_port = dst_port;
	daemonSockets[index].state = SS_CONNECTING;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[index].host_IP.s_addr = ntohl(daemonSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);

	free(addr);
	return;

}

void accept_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags) {

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d uniqueSockID_new=%llu index=%d flags=%d",
			uniqueSockID, index, call_id, call_index, uniqueSockID_new, index_new, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	//TODO: finish this
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}
	sem_post(&daemonSockets_sem);

	ack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
}

void getname_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer) {
	int state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;
	struct nl_daemon_to_wedge *hdr;
	u_char *pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d peer=%d", uniqueSockID, index, call_id, call_index, peer);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	if (peer == 0) { //getsockname
		host_ip = daemonSockets[index].host_ip;
		host_port = daemonSockets[index].host_port;
	} else if (peer == 1) { //getpeername
		state = daemonSockets[index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemonSockets[index].dst_ip;
			rem_port = daemonSockets[index].dst_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
		state = daemonSockets[index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemonSockets[index].dst_ip;
			rem_port = daemonSockets[index].dst_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else {
		//TODO error
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	struct sockaddr_in *addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if (addr == NULL) {
		PRINT_DEBUG("addr creation failed");
		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	if (peer == 0) { //getsockname
		addr->sin_addr.s_addr = htonl(host_ip);
		addr->sin_port = htons(host_port);
	} else if (peer == 1) { //getpeername
		addr->sin_addr.s_addr = htonl(rem_ip);
		addr->sin_port = htons(rem_port);
	} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
		addr->sin_addr.s_addr = htonl(rem_ip);
		addr->sin_port = htons(rem_port);
	} else {
		//TODO error
	}

	int len = sizeof(struct sockaddr_in);

	//send msg to wedge
	int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + len;
	u_char *msg = (u_char *) malloc(msg_len);
	if (msg == NULL) {
		PRINT_ERROR("ERROR: buf alloc fail");
		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	hdr = (struct nl_daemon_to_wedge *) msg;
	hdr->call_type = getname_call;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->uniqueSockID = uniqueSockID;
	hdr->index = index;
	hdr->ret = ACK;
	hdr->msg = 0;
	pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = len;
	pt += sizeof(int);

	memcpy(pt, addr, len);
	pt += len;

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("Exiting, fail send_wedge: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
	} else {
		PRINT_DEBUG("Exiting, normal: index=%d, uniqueSockID=%llu", index, uniqueSockID);
	}

	free(msg);
}

void ioctl_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len) {
	u_int len;
	int msg_len;
	u_char *msg = NULL;
	struct nl_daemon_to_wedge *hdr;
	u_char *pt;

	PRINT_DEBUG("Entered: index=%d uniqueSockID=%llu cmd=%d len=%d", index, uniqueSockID, cmd, buf_len);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
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
		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(u_int);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}

		hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = ioctl_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->uniqueSockID = uniqueSockID;
		hdr->index = index;
		hdr->ret = ACK;
		hdr->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(u_int *) pt = len;
		pt += sizeof(u_int);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
			return;
		}
		break;
	default:
		PRINT_DEBUG("default cmd=%d", cmd);
		return;
	}

	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("ioctl_call_handler: Exiting, fail send_wedge: uniqueSockID=%llu", uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
		}
		free(msg);
	} else {
		nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
	}
}

void send_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int datalen, u_int flags) {

	uint32_t host_ip;
	uint16_t host_port;
	uint32_t dst_ip;
	uint16_t dst_port;
	int len = datalen;

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

		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		free(data);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (daemonSockets[index].state < SS_CONNECTING) {
		/** socket is not connected to an address. Send call will fail */
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		free(data);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken */
	dst_port = daemonSockets[index].dst_port;
	dst_ip = daemonSockets[index].dst_ip;

	//hostport = daemonSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */

	if (daemonSockets[index].host_ip == any_ip_addr) { //TODO change this when have multiple interfaces
		daemonSockets[index].host_ip = my_host_ip_addr;
	}
	host_ip = daemonSockets[index].host_ip;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	host_port = daemonSockets[index].host_port;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("addr %d,%d,%d,%d", dst_ip, dst_port, host_ip, host_port);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	//int blocking_flag = 1; //TODO get from flags

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (daemon_UDP_to_fins(data, len, dst_port, dst_ip, host_port, host_ip) == 1) {
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		ack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	}
} // end of send_udp

void sendto_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags, struct sockaddr_in *addr,
		socklen_t addrlen) {

	uint32_t host_ip;
	uint16_t host_port;
	uint32_t dst_ip;
	uint16_t dst_port;

	int len = data_len;

	struct in_addr *temp;

	PRINT_DEBUG("sendto_udp: Entered: index=%d, uniqueSockID=%llu, data_len=%d, flags=%d", index, uniqueSockID, data_len, flags);
	PRINT_DEBUG("MSG_CONFIRM=%d (%d) MSG_DONTROUTE=%d (%d) MSG_DONTWAIT=%d (%d) MSG_EOR=%d (%d) MSG_MORE=%d (%d) MSG_NOSIGNAL=%d (%d) MSG_OOB=%d (%d)",
			MSG_CONFIRM & flags, MSG_CONFIRM, MSG_DONTROUTE & flags, MSG_DONTROUTE, MSG_DONTWAIT & flags, MSG_DONTWAIT, MSG_EOR & flags, MSG_EOR, MSG_MORE & flags, MSG_MORE, MSG_NOSIGNAL & flags, MSG_NOSIGNAL, MSG_OOB & flags, MSG_OOB);

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
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);

		free(data);
		free(addr);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");

	dst_ip = ntohl(addr->sin_addr.s_addr);/** it is in network format since application used htonl */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/** Keep all ports and addresses in host order until later  action taken */
	dst_port = ntohs(addr->sin_port); /** reverse it since it is in network order after application used htons */

	PRINT_DEBUG("");
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);

		free(data);
		free(addr);
		return;
	}

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	if (daemonSockets[index].host_ip == any_ip_addr) { //TODO change this when have multiple interfaces
		daemonSockets[index].host_ip = my_host_ip_addr;
	}

	host_ip = daemonSockets[index].host_ip;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	host_port = daemonSockets[index].host_port;
	if (host_port == 0) {
		while (1) {
			host_port = randoming(MIN_port, MAX_port);
			if (check_daemon_ports(host_port, host_ip)) {
				break;
			}
		}
		daemonSockets[index].host_port = host_port;
	}
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("index=%d, dst=%u/%d, host=%u/%d", index, dst_ip, dst_port, host_ip, host_port);

	temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = host_ip;
	PRINT_DEBUG("index=%d, dst=%s/%d (%u)", index, inet_ntoa(addr->sin_addr), dst_port, addr->sin_addr.s_addr);
	PRINT_DEBUG("index=%d, host=%s/%d (%u)", index, inet_ntoa(*temp), host_port, (*temp).s_addr);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	//int blocking_flag = 1; //TODO get from flags

	/** the meta-data parameters are all passes by copy starting from this point
	 *
	 */
	if (daemon_UDP_to_fins(data, len, dst_port, dst_ip, host_port, host_ip) == 1) {
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		ack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish sendto");
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	}
	free(addr);
} //end of sendto_udp

void *recvfrom_udp_thread(void *local) {
	struct daemon_udp_thread_data *thread_data = (struct daemon_udp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int data_len = thread_data->data_len;
	int flags = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);

	int non_blocking_flag = flags & (SOCK_NONBLOCK | O_NONBLOCK | MSG_DONTWAIT); //TODO get from flags
	int ret;

	PRINT_DEBUG();
	struct finsFrame *ff = NULL;
	ret = get_fdf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fdf uniqID=%llu ind=%d ff=%x", uniqueSockID, index, (int)ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, EBADF); //TODO socket closed/invalid

		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			//sleep(1);
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		}
		pthread_exit(NULL);
	}

	struct sockaddr_in addr;
	uint32_t src_port;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_port", &src_port) == 0) {
		addr.sin_port = 0;
	} else {
		addr.sin_port = htons((uint16_t) src_port);
	}

	uint32_t src_ip;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_ip", &src_ip) == 0) {
		addr.sin_addr.s_addr = 0;
	} else {
		addr.sin_addr.s_addr = (uint32_t) htonl(src_ip);
	}

	if (data_len < ff->dataFrame.pduLength) {
		//TODO finish, slice off piece of pdu
	}

	//#######
	PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
	u_char *temp = (u_char *) malloc(ff->dataFrame.pduLength + 1);
	memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	temp[ff->dataFrame.pduLength] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength, temp);
	free(temp);
	//#######

	int addr_len = sizeof(struct sockaddr_in);

	int msg_len = sizeof(struct nl_daemon_to_wedge) + 2 * sizeof(int) + addr_len + ff->dataFrame.pduLength;
	u_char *msg = (u_char *) malloc(msg_len);
	if (msg == NULL) {
		PRINT_ERROR("ERROR: buf alloc fail");
		exit(0);
	}

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
	hdr->call_type = recvmsg_call;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->uniqueSockID = uniqueSockID;
	hdr->index = index;
	hdr->ret = ACK;
	hdr->msg = 0;
	u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, &addr, addr_len);
	pt += sizeof(struct sockaddr_in);

	*(int *) pt = ff->dataFrame.pduLength;
	pt += sizeof(int);

	memcpy(pt, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	pt += ff->dataFrame.pduLength;

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		PRINT_DEBUG("Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
	} else {
		PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
	}

	free(msg);
	freeFinsFrame(ff);
	pthread_exit(NULL);
}

/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvfrom_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	int multi_flag;
	int thread_flags;

	PRINT_DEBUG("Entered: index=%d uniqueSockID=%llu data_len=%d flags=%d msg_flags=%d", index, uniqueSockID, data_len, flags, msg_flags);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, (SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);
	PRINT_DEBUG( "MSG_CMSG_CLOEXEC=%d, MSG_DONTWAIT=%d, MSG_ERRQUEUE=%d, MSG_OOB=%d, MSG_PEEK=%d, MSG_TRUNC=%d, MSG_WAITALL=%d",
			(MSG_CMSG_CLOEXEC & flags)>0, (MSG_DONTWAIT & flags)>0, (MSG_ERRQUEUE & flags)>0, (MSG_OOB & flags)>0, (MSG_PEEK & flags)>0, (MSG_TRUNC & flags)>0, (MSG_WAITALL & flags)>0);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & msg_flags)>0, (SOCK_CLOEXEC & msg_flags)>0, (O_NONBLOCK & msg_flags)>0, (O_ASYNC & msg_flags)>0);
	PRINT_DEBUG( "MSG_EOR=%d, MSG_TRUNC=%d, MSG_CTRUNC=%d, MSG_OOB=%d, MSG_ERRQUEUE=%d",
			(MSG_EOR & msg_flags)>0, (MSG_TRUNC & msg_flags)>0, (MSG_CTRUNC & msg_flags)>0, (MSG_OOB & msg_flags)>0, (MSG_ERRQUEUE & msg_flags)>0);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
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
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->data_len = data_len;
		thread_data->flags = flags;

		//spin off thread to handle
		if (pthread_create(&thread, NULL, recvfrom_udp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create recvfrom_udp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);

			free(thread_data);
		} else {
			pthread_detach(thread);
		}
	}
}

void release_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index) {
	int ret;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d", uniqueSockID, index, call_id, call_index);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_udp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		return;
	}

	ret = remove_daemonSocket_new(uniqueSockID, index);

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (ret) {
		ack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
	} else {
		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
	}
}

void poll_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index) {
	socket_state state;
	uint32_t mask = 0;

	PRINT_DEBUG("poll_udp: index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling poll_udp.");
		sem_post(&daemonSockets_sem);

		nack_send(uniqueSockID, poll_call, 0);
		return;
	}

	state = daemonSockets[index].state;

	sem_wait(&daemonSockets[index].Qs);
	if (daemonSockets[index].buf_data) {
		mask |= POLLIN;
	}
	sem_post(&daemonSockets[index].Qs);

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	//TODO finish creating mask

	int msg_len;
	u_char *msg;
	u_char *pt;
	int ret_val;

	msg_len = 4 * sizeof(u_int) + sizeof(unsigned long long);
	msg = (u_char *) malloc(msg_len);
	pt = msg;

	*(u_int *) pt = poll_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(u_int *) pt = ACK;
	pt += sizeof(u_int);

	*(u_int *) pt = 0;
	pt += sizeof(u_int);

	*(u_int *) pt = mask;
	pt += sizeof(u_int);

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		nack_send(uniqueSockID, poll_call, 0);
	}
}

/** .......................................................................*/

void shutdown_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	//index = find_daemonSocket(uniqueSockID);
	/** TODO unlock access to the daemonsockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);

	ack_send(uniqueSockID, shutdown_call, 0);
}

void setsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval) {

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

void getsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval) {
	int len;
	char *val;
	u_char *msg;
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
	msg = (u_char *) malloc(msg_len);
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

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		nack_send(uniqueSockID, getsockopt_call, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		nack_send(uniqueSockID, getsockopt_call, 0);
	}
}

//############################## Deprecated, not used & only temp keeping

