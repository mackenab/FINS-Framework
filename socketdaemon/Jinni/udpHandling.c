/**
 * @file udpHandling.c
 *
 *  @date Nov 28, 2010
 *   @author Abdallah Abdallah
 */

#include "udpHandling.h"
#include "finstypes.h"

#define	IP4_PT_UDP		17

extern sem_t jinniSockets_sem;
extern struct finssocket jinniSockets[MAX_sockets];

extern int recv_thread_count;
extern sem_t recv_thread_sem;

extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;
extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;

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
 *  Functions interfacing socketjinni_UDP with FINS core
 *
 */

int UDPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag, int multi_flag) {

	/**TODO MUST BE FIXED LATER
	 * force symbol to become zero
	 */
	//symbol = 0;
	struct finsFrame *ff = NULL;
	struct finsFrame *ff_copy = NULL;
	int index;
	uint16_t srcport;
	uint32_t srcip;
	struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
	int i;

	sem_wait(&jinniSockets_sem);
	index = findjinniSocket(uniqueSockID);
	sem_post(&jinniSockets_sem);
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

		int value;
		sem_getvalue(&(jinniSockets[index].Qs), &value);
		PRINT_DEBUG("uniqID=%llu sem: ind=%d, val=%d", uniqueSockID, index,
				value);
		PRINT_DEBUG("block=%d, multi=%d, threads=%d", block_flag, multi_flag,
				jinniSockets[index].threads);

		do {
			sem_wait(&jinniSockets_sem);
			if (jinniSockets[index].uniqueSockID != uniqueSockID) {
				PRINT_DEBUG("Socket closed, canceling read block.");
				sem_post(&jinniSockets_sem);
				return (0);
			}
			sem_wait(&(jinniSockets[index].Qs));
			//		PRINT_DEBUG();
			ff = read_queue(jinniSockets[index].dataQueue);
			//	ff = get_fake_frame();
			//					PRINT_DEBUG();

			if (ff && multi_flag) {
				PRINT_DEBUG("index=%d threads=%d replies=%d", index,
						jinniSockets[index].threads,
						jinniSockets[index].replies);
				if (jinniSockets[index].replies) {
					jinniSockets[index].replies--;
				} else {
					jinniSockets[index].replies = jinniSockets[index].threads
							- 1;
					for (i = 0; i < jinniSockets[index].replies; i++) {
						PRINT_DEBUG("adding frame copy, threads=%d",
								jinniSockets[index].threads);
						ff_copy = (struct finsFrame *) malloc(
								sizeof(struct finsFrame));
						cpy_fins_to_fins(ff_copy, ff); //copies pointers, freeFinsFrame doesn't free pointers
						if (!write_queue_front(ff_copy,
								jinniSockets[index].dataQueue)) {
							; //error
						}
					}
				}
			}

			sem_post(&(jinniSockets[index].Qs));
			sem_post(&jinniSockets_sem);
		} while (ff == NULL);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG();

		sem_wait(&jinniSockets_sem);
		if (jinniSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Socket closed, canceling read block.");
			sem_post(&jinniSockets_sem);
			return (0);
		}

		sem_wait(&(jinniSockets[index].Qs));
		//ff= read_queue(jinniSockets[index].dataQueue);
		/**	ff = get_fake_frame();
		 print_finsFrame(ff); */
		ff = read_queue(jinniSockets[index].dataQueue);

		if (ff && multi_flag) {
			PRINT_DEBUG("index=%d threads=%d replies=%d", index,
					jinniSockets[index].threads, jinniSockets[index].replies);
			if (jinniSockets[index].replies) {
				jinniSockets[index].replies--;
			} else {
				jinniSockets[index].replies = jinniSockets[index].threads - 1;
				for (i = 0; i < jinniSockets[index].replies; i++) {
					PRINT_DEBUG("adding frame copy, threads=%d",
							jinniSockets[index].threads);
					ff_copy = (struct finsFrame *) malloc(
							sizeof(struct finsFrame));
					cpy_fins_to_fins(ff_copy, ff); //copies pointers, freeFinsFrame doesn't free pointers
					if (!write_queue_front(ff_copy,
							jinniSockets[index].dataQueue)) {
						; //error
					}
				}
			}
		}

		sem_post(&(jinniSockets[index].Qs));
		sem_post(&jinniSockets_sem);
	}

	if (ff == NULL) {
		//free(ff);
		return (0);
	}
	PRINT_DEBUG("recv'd uniqID=%llu ind=%d", uniqueSockID, index);
	PRINT_DEBUG("PDU length %d", ff->dataFrame.pduLength);

	if (metadata_readFromElement(ff->dataFrame.metaData, "portsrc",
			(uint16_t *) &srcport) == 0) {
		addr_in->sin_port = 0;

	}
	if (metadata_readFromElement(ff->dataFrame.metaData, "ipsrc",
			(uint32_t *) &srcip) == 0) {
		addr_in->sin_addr.s_addr = 0;

	}

	/**
	 * making sure that the datagram coming from the destination we are connected to it
	 * in case of connection previously done
	 */
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&jinniSockets_sem);
		return (0);
	}
	PRINT_DEBUG("Rest of read for index=%d.", index);

	if (jinniSockets[index].connection_status > 0) {
		if ((srcport != jinniSockets[index].dstport)
				|| (srcip != jinniSockets[index].dst_IP)) {
			PRINT_DEBUG(
					"Wrong address, the socket is already connected to another destination");
			sem_post(&jinniSockets_sem);
			return (0);
		}
	}
	sem_post(&jinniSockets_sem);

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

int jinni_UDP_to_fins(u_char *dataLocal, int len, uint16_t dstport,
		uint32_t dst_IP_netformat, uint16_t hostport,
		uint32_t host_IP_netformat) {

	struct finsFrame *ff = (struct finsFrame *) malloc(
			sizeof(struct finsFrame));

	metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));

	PRINT_DEBUG();

	metadata_create(udpout_meta);

	if (udpout_meta == NULL) {
		PRINT_DEBUG("metadata creation failed");
		free(ff);
		return 0;
	}

	/** metadata_writeToElement() set the value of an element if it already exist
	 * or it creates the element and set its value in case it is new
	 */
	PRINT_DEBUG("%d, %d, %d, %d", dstport, dst_IP_netformat, hostport,
			host_IP_netformat);

	uint32_t dstprt = dstport;
	uint32_t hostprt = hostport;
	int protocol = IP4_PT_UDP;
	metadata_writeToElement(udpout_meta, "dstport", &dstprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "srcport", &hostprt, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "dstip", &dst_IP_netformat,
			META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "srcip", &host_IP_netformat,
			META_TYPE_INT);

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

	/**TODO insert the frame into jinni_to_switch queue
	 * check if insertion succeeded or not then
	 * return 1 on success, or -1 on failure
	 * */
	PRINT_DEBUG("");
	sem_wait(&Jinni_to_Switch_Qsem);
	if (write_queue(ff, Jinni_to_Switch_Queue)) {

		sem_post(&Jinni_to_Switch_Qsem);
		PRINT_DEBUG("");
		return (1);
	}
	sem_post(&Jinni_to_Switch_Qsem);
	PRINT_DEBUG("");

	return (0);
}

/**
 * End of interfacing socketjinni with FINS core
 * */
void socket_udp(int domain, int type, int protocol,
		unsigned long long uniqueSockID) {
	PRINT_DEBUG("socket_UDP CALL");

	char clientName[200];
	int index;
	int pipe_desc;
	int tester;
	/** TODO lock the pipe semaphore then open the pipe*/

	insertjinniSocket(uniqueSockID, type, protocol);

	PRINT_DEBUG();

	index = findjinniSocket(uniqueSockID);
	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		return;
	}

	ack_send(uniqueSockID, socket_call);
}

void bind_udp(unsigned long long uniqueSockID, struct sockaddr_in *addr) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP_netformat;
	uint32_t dst_IP_netformat;
	int index;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, bind_call);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	hostport = ntohs(addr->sin_port);
	host_IP_netformat = (addr->sin_addr).s_addr;
	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!checkjinniports(hostport, host_IP_netformat)
			&& !jinniSockets[index].sockopts.FSO_REUSEADDR) {
		PRINT_DEBUG("this port is not free");
		nack_send(uniqueSockID, bind_call);

		free(addr);
		return;
	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);

	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */
	PRINT_DEBUG("bind address: %d,%d,%d", (addr->sin_addr).s_addr,
			ntohs(addr->sin_port), addr->sin_family);
	PRINT_DEBUG("bind address: %d, %s/%d", addr->sin_family,
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	/**
	 * Binding
	 */
	sem_wait(&jinniSockets_sem);
	jinniSockets[index].hostport = ntohs(addr->sin_port);
	jinniSockets[index].host_IP = (addr->sin_addr).s_addr;
	sem_post(&jinniSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_IP.s_addr = ntohl(jinniSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	PRINT_DEBUG("bind: index:%d, host:%d/%d, dst:%d/%d", index,
			jinniSockets[index].host_IP, jinniSockets[index].hostport,
			jinniSockets[index].dst_IP, jinniSockets[index].dstport);
	ack_send(uniqueSockID, bind_call);

	free(addr);
	return;

} // end of bind_udp

void connect_udp(unsigned long long uniqueSockID, struct sockaddr_in *addr) {

	uint16_t dstport;
	uint32_t dst_IP;
	int index;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, connect_call);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	dstport = ntohs(addr->sin_port);
	dst_IP = ntohl((addr->sin_addr).s_addr);
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

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (jinniSockets[index].connection_status > 0) {
		PRINT_DEBUG("old destined address %d, %d", jinniSockets[index].dst_IP,
				jinniSockets[index].dstport);
		PRINT_DEBUG("new destined address %d, %d", dst_IP, dstport);

	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);

	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */
	PRINT_DEBUG("%d,%d,%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port),
			addr->sin_family);

	sem_wait(&jinniSockets_sem);
	jinniSockets[index].dstport = ntohs(addr->sin_port);
	jinniSockets[index].dst_IP = ntohl((addr->sin_addr).s_addr);
	jinniSockets[index].connection_status++;
	sem_post(&jinniSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_IP.s_addr = ntohl(jinniSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send(uniqueSockID, connect_call);

	free(addr);
	return;

}

void write_udp(unsigned long long uniqueSockID, int socketCallType, int datalen,
		u_char *data) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;
	int index;

	PRINT_DEBUG("");

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, socketCallType);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = jinniSockets[index].dstport;

	dst_IP = jinniSockets[index].dst_IP;

	//hostport = jinniSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	//hostport = jinniSockets[index].hostport;
	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firsly inserted into the jinnisockets
	 * check insertjinniSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = jinniSockets[index].hostport;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = jinniSockets[index].host_IP;
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (jinni_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, socketCallType);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, socketCallType);
	}

} // end of write_udp

void send_udp(unsigned long long uniqueSockID, int socketCallType, int datalen,
		u_char *data, int flags) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;
	int index;

	if (flags == -1000) {

		return (write_udp(uniqueSockID, socketCallType, datalen, data));

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

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, socketCallType);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = jinniSockets[index].dstport;

	dst_IP = jinniSockets[index].dst_IP;

	//hostport = jinniSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = jinniSockets[index].host_IP;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the jinnisockets
	 * check insertjinniSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = jinniSockets[index].hostport;
	if (hostport == (uint16_t)(-1)) {
		while (1) {
			hostport = randoming(MIN_port, MAX_port);
			if (checkjinniports(hostport, host_IP)) {
				break;
			}
		}
		jinniSockets[index].hostport = hostport;
	}

	PRINT_DEBUG("");

	PRINT_DEBUG("addr %d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (jinni_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, socketCallType);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, socketCallType);
	}
} // end of send_udp

void sendto_udp(unsigned long long uniqueSockID, int socketCallType,
		int datalen, u_char *data, int flags, struct sockaddr_in *addr,
		socklen_t addrlen) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;

	int len = datalen;
	int index;
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

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		return;
	}

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, socketCallType);
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

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = jinniSockets[index].host_IP;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the jinnisockets
	 * check insertjinniSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = jinniSockets[index].hostport;
	if (hostport == (uint16_t)(-1)) {
		while (1) {
			hostport = randoming(MIN_port, MAX_port);
			if (checkjinniports(hostport, host_IP)) {
				break;
			}
		}
		jinniSockets[index].hostport = hostport;
	}

	PRINT_DEBUG("");

	PRINT_DEBUG("index=%d, dst=%d/%d, host=%d/%d", index, dst_IP, dstport,
			host_IP, hostport);

	temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = host_IP;
	PRINT_DEBUG("index=%d, dst=%s/%d, host=%s/%d", index,
			inet_ntoa(addr->sin_addr), dstport, inet_ntoa(*temp), hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	/** the meta-data parameters are all passes by copy starting from this point
	 *
	 */
	if (jinni_UDP_to_fins(data, len, dstport, dst_IP, hostport, host_IP) == 1)

	{
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		PRINT_DEBUG("");

		ack_send(uniqueSockID, socketCallType);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish sendto");
		nack_send(uniqueSockID, socketCallType);
	}

	return;

} //end of sendto_udp

/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvfrom_udp(void *threadData) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	u_char *buf = NULL;
	//u_char buf[MAX_DATA_PER_UDP];

	u_char *bufptr;
	struct sockaddr_in *addr;
	int buflen = 0;
	int index;
	int i;
	int blocking_flag;
	int multi_flag;

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

	PRINT_DEBUG("Entered recv thread=%d", thread_data->id);

	sem_wait(&jinniSockets_sem);
	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);
		recvthread_exit(thread_data);
	}

	PRINT_DEBUG("index = %d", index);
	blocking_flag = jinniSockets[index].blockingFlag;
	multi_flag = 0; //for udp, if SOL_SOCKET/SO_REUSEADDR
	sem_post(&jinniSockets_sem);

	if (symbol == 1)
		addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	else
		addr = NULL;
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */

	buf = (u_char *) malloc(MAX_DATA_PER_UDP + 1);
	bufptr = buf;

	if (UDPreadFrom_fins(uniqueSockID, bufptr, &buflen, symbol, addr,
			blocking_flag, multi_flag) == 1) {
		PRINT_DEBUG("after UDPreadFrom_fins uniqID=%llu ind=%d", uniqueSockID,
				index);

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("buflen=%d", buflen);

		for (i = 0; i < buflen; i++) {
			PRINT_DEBUG("%d", buf[i]);
		}
		PRINT_DEBUG("buf=%s", buf);

		msg_len = 4 * sizeof(int) + sizeof(unsigned long long) + buflen
				+ (symbol ? sizeof(struct sockaddr_in) : 0);
		msg = malloc(msg_len);
		pt = msg;

		*(int *) pt = socketCallType;
		pt += sizeof(int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *) pt = ACK;
		pt += sizeof(int);

		if (symbol) {
			*(int *) pt = sizeof(struct sockaddr_in);
			pt += sizeof(int);

			memcpy(pt, addr, sizeof(struct sockaddr_in));
			pt += sizeof(struct sockaddr_in);

			//#######
			PRINT_DEBUG("address: %d/%d", (addr->sin_addr).s_addr,
					ntohs(addr->sin_port));
			//#######
		}

		*(int *) pt = buflen;
		pt += sizeof(int);

		memcpy(pt, buf, buflen);
		pt += buflen;

		if (pt - (u_char *) msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg,
					msg_len);
			free(msg);
			free(buf);
			if (addr)
				free(addr);
			nack_send(uniqueSockID, socketCallType);
			recvthread_exit(thread_data);
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);
		if (ret_val) {
			nack_send(uniqueSockID, socketCallType);
		}

		PRINT_DEBUG();
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish recvfrom");
		nack_send(uniqueSockID, socketCallType);
	}
	PRINT_DEBUG();

	if (addr)
		free(addr);
	free(buf);

	recvthread_exit(thread_data);
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

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
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
	if (UDPreadFrom_fins(uniqueSockID, buf, &buflen, 0, NULL, blocking_flag,
			multi_flag) == 1) {

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("%d", buflen);
		PRINT_DEBUG("%s", buf);

		msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int)
				+ buflen;
		msg = malloc(msg_len);
		pt = msg;

		*(u_int *) pt = recv_call;
		pt += sizeof(u_int);

		*(unsigned long long *) pt = uniqueSockID;
		pt += sizeof(unsigned long long);

		*(int *) pt = ACK;
		pt += sizeof(int);

		*(int *) pt = buflen;
		pt += sizeof(int);

		memcpy(pt, buf, buflen);
		pt += buflen;

		if (pt - (u_char *) msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg,
					msg_len);
			free(msg);
			nack_send(uniqueSockID, recv_call);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);
		if (ret_val) {
			nack_send(uniqueSockID, recv_call);
		}

		PRINT_DEBUG();

		//	free(buf);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish recv_udp");
		nack_send(uniqueSockID, recv_call);
	}

	PRINT_DEBUG();
	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(address);
	//free(buf);
} // end of recv_udp

/** .......................................................................*/
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
	index = findjinniSocket(uniqueSockID);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = jinniSockets[index].dst_IP;
	address.sin_port = jinniSockets[index].dstport;
	memset(address.sin_zero, 0, 8);

	PRINT_DEBUG("*****%d*********%d , %d*************", address_length,
			address.sin_addr.s_addr, address.sin_port)

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int)
			+ address_length;
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = getpeername_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = address_length;
	pt += sizeof(int);

	memcpy(pt, &address, address_length);
	pt += address_length;

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
	if (ret_val) {
		nack_send(uniqueSockID, getpeername_call);
	}
}

void shutdown_udp(unsigned long long uniqueSockID, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	int index;

	index = findjinniSocket(uniqueSockID);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);

	ack_send(uniqueSockID, shutdown_call);
}

void setsockopt_udp(unsigned long long uniqueSockID, int level, int optname,
		int optlen, u_char *optval) {
	int index;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG("level=%d, optname=%d, optlen=%d", level, optname, optlen);

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
		jinniSockets[index].sockopts.FSO_DEBUG = *(int *) optval;
		PRINT_DEBUG("FSO_DEBUG=%d", jinniSockets[index].sockopts.FSO_DEBUG);
		break;
	case SO_REUSEADDR:
		jinniSockets[index].sockopts.FSO_REUSEADDR = *(int *) optval;
		PRINT_DEBUG("FSO_REUSEADDR=%d",
				jinniSockets[index].sockopts.FSO_REUSEADDR);
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

	ack_send(uniqueSockID, setsockopt_call);

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

void getsockopt_udp(unsigned long long uniqueSockID, int level, int optname,
		int optlen, u_char *optval) {
	int index;
	int len;
	char *val;
	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG("level=%d, optname=%d, optlen=%d", level, optname, optlen);

	/*
	 metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));
	 metadata_create(udpout_meta);
	 metadata_writeToElement(udpout_meta, "dstport", &dstprt, META_TYPE_INT);
	 */

	switch (optname) {
	case SO_DEBUG:
		//jinniSockets[index].sockopts.FSO_DEBUG = *(int *)optval;
		break;
	case SO_REUSEADDR:
		len = sizeof(int);
		val = (char *) &(jinniSockets[index].sockopts.FSO_REUSEADDR);
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

	msg_len = sizeof(u_int) + sizeof(unsigned long long) + 2 * sizeof(int)
			+ len;
	msg = malloc(msg_len);
	pt = msg;

	*(u_int *) pt = getsockopt_call;
	pt += sizeof(u_int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = len;
	pt += sizeof(int);

	memcpy(pt, val, len);
	pt += len;

	if (pt - (u_char *) msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg,
				msg_len);
		free(msg);
		nack_send(uniqueSockID, getsockopt_call);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		nack_send(uniqueSockID, getsockopt_call);
	}
}

void listen_udp(unsigned long long uniqueSockID, int backlog) {

	int index;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}
	PRINT_DEBUG("index = %d", index);

	ack_send(uniqueSockID, listen_call);
}

void accept_udp(unsigned long long uniqueSockID,
		unsigned long long uniqueSockID_new) {
	int index;

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		return;
	}
	PRINT_DEBUG("index = %d", index);

	ack_send(uniqueSockID, accept_call);
}
