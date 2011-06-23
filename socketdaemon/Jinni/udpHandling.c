/**
 * @file udpHandling.c
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#include "udpHandling.h"
#include "finstypes.h"

extern struct finssocket jinniSockets[MAX_sockets];
extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;
extern sem_t *meen_channel_semaphore1;
extern sem_t *meen_channel_semaphore2;
extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;
//extern struct socketIdentifier FinsHistory[MAX_sockets];

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

int readFrom_fins(int senderid, int sockfd, u_char **buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag) {

	/**TODO MUST BE FIXED LATER
	 * force symbol to become zero
	 */
	//symbol = 0;
	struct finsFrame *ff = NULL;
	int index;
	uint16_t srcport;
	uint32_t srcip;
	struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
	index = findjinniSocket(senderid, sockfd);
	PRINT_DEBUG("index = %d",index);
	/**
	 * It keeps looping as a bad method to implement the blocking feature
	 * of recvfrom. In case it is not blocking then the while loop should
	 * be replaced with only a single trial !
	 *
	 */

	PRINT_DEBUG();
	if (block_flag == 1) {
		PRINT_DEBUG();

		do {

			sem_wait(&(jinniSockets[index].Qs));
			//		PRINT_DEBUG();


			ff = read_queue(jinniSockets[index].dataQueue);
			//	ff = get_fake_frame();
			//					PRINT_DEBUG();

			sem_post(&(jinniSockets[index].Qs));
		} while (ff == NULL);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG();

		sem_wait(&(jinniSockets[index].Qs));
		//ff= read_queue(jinniSockets[index].dataQueue);
		/**	ff = get_fake_frame();
		 print_finsFrame(ff); */
		ff = read_queue(jinniSockets[index].dataQueue);

		sem_post(&(jinniSockets[index].Qs));

	}

	if (ff == NULL) {
		//free(ff);
		return (0);
	} PRINT_DEBUG("PDU lenght %d",ff->dataFrame.pduLength);

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
	} PRINT_DEBUG();

	if (metadata_readFromElement(ff->dataFrame.metaData, "portsrc", &srcport)
			== 0) {
		address->sin_port = 0;
		return (1);
	}
	if (metadata_readFromElement(ff->dataFrame.metaData, "ipsrc", &srcip) == 0) {
		address->sin_addr.s_addr = 0;
		return (1);
	}

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

	struct finsFrame *ff =
			(struct finsFrame *) malloc(sizeof(struct finsFrame));

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
	PRINT_DEBUG("%d, %d, %d, %d", dstport,dst_IP_netformat,hostport,
			host_IP_netformat);

	uint32_t dstprt = dstport;
	uint32_t hostprt = hostport;

	metadata_writeToElement(udpout_meta, "dstport", &dstport, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "srcport", &hostport, META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "dstip", &dst_IP_netformat,
			META_TYPE_INT);
	metadata_writeToElement(udpout_meta, "srcip", &host_IP_netformat,
			META_TYPE_INT);

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
void socket_udp(int domain, int type, int protocol, int sockfd, int fakeID,
		pid_t processid) {
	PRINT_DEBUG("socket_UDP CALL");

	char clientName[200];
	int index;
	int pipe_desc;
	int tester;
	/** TODO lock the pipe semaphore then open the pipe*/

	insertjinniSocket(processid, sockfd, fakeID, type, protocol);

	PRINT_DEBUG();
	sprintf(clientName, CLIENT_CHANNEL_RX, processid, fakeID);
	mkfifo(clientName, 0777);
	pipe_desc = open(clientName, O_WRONLY);
	index = findjinniSocket(processid, sockfd);

	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		exit(1);

	} PRINT_DEBUG("0000");

	jinniSockets[index].jinniside_pipe_ds = pipe_desc;
	/** Now the client can proceed to next step after openning the pipe */
	PRINT_DEBUG("0002");
	sem_getvalue(jinniSockets[index].s, &tester);
	PRINT_DEBUG("tester = %d", tester);

	PRINT_DEBUG("0001");

	sem_wait(jinniSockets[index].s);
	ack_write(pipe_desc, processid, sockfd);
	sem_post(jinniSockets[index].as);
	/** TODO unlock the semaphore */
	sem_post(jinniSockets[index].s);
	PRINT_DEBUG("0003");

	return;

}

void bind_udp(int sender, int sockfd, struct sockaddr *addr) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP_netformat;
	uint32_t dst_IP_netformat;
	int index;

	struct sockaddr_in *address;
	address = (struct sockaddr_in *) addr;
	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(sender, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (address->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, sender, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	/**TODO lock the jinni sockets */

	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}
	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	hostport = ntohs(address->sin_port);
	host_IP_netformat = (address->sin_addr).s_addr;
	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (checkjinniports(hostport, host_IP_netformat) == -1) {
		PRINT_DEBUG("this port is not free");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, sender, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);

		free(addr);
		return;
	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(address->sin_port);


	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */
	PRINT_DEBUG("%d,%d,%d",(address->sin_addr).s_addr, ntohs(address->sin_port),
			address->sin_family);

	jinniSockets[index].hostport = ntohs(address->sin_port);
	jinniSockets[index].host_IP = (address->sin_addr).s_addr;

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_IP.s_addr = ntohl(jinniSockets[index].host_IP.s_addr);

	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	sem_wait(jinniSockets[index].s);
	ack_write(jinniSockets[index].jinniside_pipe_ds, sender, sockfd);
	sem_post(jinniSockets[index].as);
	sem_post(jinniSockets[index].s);

	free(addr);
	return;

} // end of bind_udp


void connect_udp(int sender, int sockfd, struct sockaddr_in *addr) {

	uint16_t dstport;
	uint32_t dst_IP;
	int index;

	struct sockaddr_in *address;
	address = (struct sockaddr_in *) addr;
	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(sender, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (address->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, sender, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	dstport = ntohs(address->sin_port);
	dst_IP = ntohl((address->sin_addr).s_addr);
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
		PRINT_DEBUG("old destined address %d, %d", jinniSockets[index].dst_IP, jinniSockets[index].dstport ); PRINT_DEBUG("new destined address %d, %d", dst_IP, dstport );

	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */
	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(address->sin_port);


	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */
	PRINT_DEBUG("%d,%d,%d",(address->sin_addr).s_addr, ntohs(address->sin_port),
			address->sin_family);

	jinniSockets[index].dstport = ntohs(address->sin_port);
	jinniSockets[index].dst_IP = ntohl((address->sin_addr).s_addr);
	jinniSockets[index].connection_status++;

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_IP.s_addr = ntohl(jinniSockets[index].host_IP.s_addr);

	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	sem_wait(jinniSockets[index].s);
	ack_write(jinniSockets[index].jinniside_pipe_ds, sender, sockfd);
	sem_post(jinniSockets[index].as);
	sem_post(jinniSockets[index].s);

	free(addr);
	return;

}

void write_udp(int senderid, int sockfd, int datalen, u_char *data) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	u_char *dataLocal = (u_char *) malloc(datalen);
	int len = datalen;
	int index;

	PRINT_DEBUG("");

	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(senderid, sockfd);
	PRINT_DEBUG("");

	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		exit(1);
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);

	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = jinniSockets[index].dstport;

	dst_IP = jinniSockets[index].dst_IP;

	//hostport = jinniSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	hostport = jinniSockets[index].hostport;
	host_IP = jinniSockets[index].host_IP;
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP,hostport);
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
		sem_wait(jinniSockets[index].s);
		PRINT_DEBUG("");

		ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);

	}

	return;

} // end of write_udp


void send_udp(int senderid, int sockfd, int datalen, u_char *data, int flags) {
	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	u_char *dataLocal = (u_char *) malloc(datalen);
	int len = datalen;
	int index;

	if (flags == -1000) {

		return (write_udp(senderid, sockfd, datalen, data));

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

	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(senderid, sockfd);
	PRINT_DEBUG("");

	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		exit(1);
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);

	}

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = jinniSockets[index].dstport;

	dst_IP = jinniSockets[index].dst_IP;

	//hostport = jinniSockets[index].hostport;
	//hostport = 3000;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	//hostport = jinniSockets[index].hostport;
	hostport = 58088;
	host_IP = jinniSockets[index].host_IP;
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP,hostport);
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
		sem_wait(jinniSockets[index].s);
		PRINT_DEBUG("");

		ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);

	}

	return;

}// end of send_udp


void sendto_udp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *addr, socklen_t addrlen) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;

	int len = datalen;
	int index;

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

	} PRINT_DEBUG("");

	struct sockaddr_in *address;
	address = (struct sockaddr_in *) addr;
	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(senderid, sockfd);
	PRINT_DEBUG("");

	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		exit(1);
	}

	if (address->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family"); PRINT_DEBUG("");

		sem_wait(jinniSockets[index].s);
		PRINT_DEBUG("");

		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
		PRINT_DEBUG("");

	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");

	/** Keep all ports and addresses in host order until later  action taken */
	dstport = ntohs(address->sin_port); /** reverse it since it is in network order after application used htons */

	dst_IP = ntohl(address-> sin_addr.s_addr);/** it is in network format since application used htonl */

	//hostport = jinniSockets[index].hostport;
	hostport = 58088;
	//host_IP = jinniSockets[index].host_IP;
	host_IP = IP4_ADR_P2N(172,31,54,87);

	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP,hostport);
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
		sem_wait(jinniSockets[index].s);
		PRINT_DEBUG("");

		ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish sendto");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);

	}

	return;

} //end of sendto_udp


/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *
 */

void recvfrom_udp(int senderid, int sockfd, int datalen, int flags, int symbol) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	//	u_char *buf=NULL;
	//	buf = (u_char *)malloc(MAX_DATA_PER_UDP);
	u_char buf[MAX_DATA_PER_UDP];

	u_char *bufptr;
	bufptr = buf;

	int buflen = 0;
	int index;
	int i;
	struct sockaddr_in *address = (struct sockaddr_in *) malloc(
			sizeof(struct sockaddr_in));

	int blocking_flag;
	blocking_flag = 1;
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d",index); PRINT_DEBUG();

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */

	if (readFrom_fins(senderid, sockfd, bufptr, &buflen, symbol, address,
			blocking_flag) == 1) {

		if (symbol == 0) {
			sem_wait(jinniSockets[index].s);

			ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
			buf[buflen] = '\0';
			PRINT_DEBUG("%d",buflen ); PRINT_DEBUG("%s",buf);
			write(jinniSockets[index].jinniside_pipe_ds, &buflen, sizeof(int));
			write(jinniSockets[index].jinniside_pipe_ds, buf, buflen);
			sem_post(jinniSockets[index].as);
			sem_post(jinniSockets[index].s);
			PRINT_DEBUG();

			//	free(buf);
			PRINT_DEBUG();

		} else if (symbol == 1) {

			sem_wait(jinniSockets[index].s);

			ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
			PRINT_DEBUG();
			write(jinniSockets[index].jinniside_pipe_ds, address,
					sizeof(struct sockaddr_in));
			write(jinniSockets[index].jinniside_pipe_ds, &buflen, sizeof(int));
			write(jinniSockets[index].jinniside_pipe_ds, buf, buflen);

			sem_post(jinniSockets[index].as);

			sem_post(jinniSockets[index].s);
		} else {

		}

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish recvfrom");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);

		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
	} PRINT_DEBUG();

	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(address);
	//free(buf);

	return;
}

/** .......................................................................*/
/**
 * @brief recv_udp
 *
 */

void recv_udp(int senderid, int sockfd, int datalen, int flags) {

	//u_char *buf= NULL;
	u_char buf[MAX_DATA_PER_UDP];
	int buflen = 0;
	int index;
	int i;

	int blocking_flag;
	blocking_flag = 1;
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	/** TODO lock access to the jinnisockets */

	index = findjinniSocket(senderid, sockfd);
	/** TODO unlock access to the jinnisockets */
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d",index); PRINT_DEBUG();

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */
	/** passing 0 as value for symbol, and NULL as an address
	 * this the difference between the call from here, and the call in case of
	 * the function recvfrom_udp
	 * */
	if (readFrom_fins(senderid, sockfd, &buf, &buflen, 0, NULL, blocking_flag)
			== 1) {

		sem_wait(jinniSockets[index].s);

		ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
		buf[buflen] = '\0';
		PRINT_DEBUG("%d",buflen ); PRINT_DEBUG("%s",buf);
		write(jinniSockets[index].jinniside_pipe_ds, &buflen, sizeof(int));
		write(jinniSockets[index].jinniside_pipe_ds, buf, buflen);
		sem_post(jinniSockets[index].as);
		sem_post(jinniSockets[index].s);
		PRINT_DEBUG();

		//	free(buf);
		PRINT_DEBUG();

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish recv_udp");
		sem_wait(jinniSockets[index].s);
		nack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);

		sem_post(jinniSockets[index].as);

		sem_post(jinniSockets[index].s);
	}

	PRINT_DEBUG();
	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(address);
	//free(buf);

	return;

} // end of recv_udp


/** .......................................................................*/
/**
 * @brief getpeername_udp
 *
 */

void getpeername_udp(int senderid, int sockfd, int addrlen) {

	int index;
	struct sockaddr_in address;
	int address_length = sizeof(struct sockaddr_in);
	index = findjinniSocket(senderid, sockfd);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = jinniSockets[index].dst_IP;
	address.sin_port = jinniSockets[index].dstport;
	memset(address.sin_zero, 0, 8);

	PRINT_DEBUG("*****%d*********%d , %d*************",address_length,address.sin_addr.s_addr,address.sin_port )
	sem_wait(jinniSockets[index].s);

	ack_write(jinniSockets[index].jinniside_pipe_ds, senderid, sockfd);
	PRINT_DEBUG();
	write(jinniSockets[index].jinniside_pipe_ds, &address_length, sizeof(int));
	write(jinniSockets[index].jinniside_pipe_ds, &address, address_length);
	sem_post(jinniSockets[index].as);

	sem_post(jinniSockets[index].s);

}
