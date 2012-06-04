/**
 * @file tcpHandling.c
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#include "tcpHandling.h"
#include "finstypes.h"

extern sem_t jinniSockets_sem;
extern struct finssocket jinniSockets[MAX_sockets];

extern int thread_count;
extern sem_t thread_sem;

extern finsQueue Jinni_to_Switch_Queue;
extern finsQueue Switch_to_Jinni_Queue;
extern sem_t Jinni_to_Switch_Qsem;
extern sem_t Switch_to_Jinni_Qsem;

int serial_num = 0;

static struct finsFrame *get_fake_frame() {

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
 *  Functions interfacing socketjinni_TCP with FINS core
 *
 */

int TCPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag) {

	/**TODO MUST BE FIXED LATER
	 * force symbol to become zero
	 */
	//symbol = 0;
	struct finsFrame *ff = NULL;
	int index;
	uint16_t srcport;
	uint32_t srcip;
	struct sockaddr_in * addr_in = (struct sockaddr_in *) address;

	PRINT_DEBUG("");
	sem_wait(&jinniSockets_sem);
	index = findjinniSocket(uniqueSockID);

	PRINT_DEBUG("index = %d", index);
	sem_post(&jinniSockets_sem);

	/**
	 * It keeps looping as a bad method to implement the blocking feature
	 * of recvfrom. In case it is not blocking then the while loop should
	 * be replaced with only a single trial !
	 *
	 */

	PRINT_DEBUG();
	if (block_flag == 1) {
		PRINT_DEBUG();
		/**
		 * WE Must FINS another way to emulate the blocking.
		 * The best suggestion is to use a pipeline to push the data in
		 * instead of the data queue
		 */
		do {
			PRINT_DEBUG("");
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

			sem_post(&(jinniSockets[index].Qs));
			PRINT_DEBUG("");
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

		sem_post(&(jinniSockets[index].Qs));
		sem_post(&jinniSockets_sem);
	}

	if (ff == NULL) {
		//free(ff);
		return (0);
	}

	PRINT_DEBUG("PDU length %d", ff->dataFrame.pduLength);

	if (metadata_readFromElement(ff->dataFrame.metaData, "portsrc", (uint16_t *) &srcport) == 0) {
		addr_in->sin_port = 0;

	}
	if (metadata_readFromElement(ff->dataFrame.metaData, "ipsrc", (uint32_t *) &srcip) == 0) {
		addr_in->sin_addr.s_addr = 0;

	}

	PRINT_DEBUG("");
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&jinniSockets_sem);
		return (0);
	}
	if (jinniSockets[index].connection_status > 0) {

		if ((srcport != jinniSockets[index].dstport) || (srcip != jinniSockets[index].dst_IP)) {

			PRINT_DEBUG("Wrong address, the socket is already connected to another destination");
			sem_post(&jinniSockets_sem);
			return (0);

		}
	}
	PRINT_DEBUG("");
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

int jinni_TCP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat, int block_flag) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));

	metadata *tcpout_meta = (metadata *) malloc(sizeof(metadata));

	PRINT_DEBUG();

	metadata_create(tcpout_meta);

	if (tcpout_meta == NULL) {
		PRINT_DEBUG("metadata creation failed");
		free(ff);
		return 0;
	}

	/** metadata_writeToElement() set the value of an element if it already exist
	 * or it creates the element and set its value in case it is new
	 */
	PRINT_DEBUG("%d, %d, %d, %d", dstport, dst_IP_netformat, hostport, host_IP_netformat);

	uint32_t dstprt = dstport;
	uint32_t hostprt = hostport;

	metadata_writeToElement(tcpout_meta, "dstport", &dstprt, META_TYPE_INT);
	metadata_writeToElement(tcpout_meta, "srcport", &hostprt, META_TYPE_INT);
	metadata_writeToElement(tcpout_meta, "dstip", &dst_IP_netformat, META_TYPE_INT);
	metadata_writeToElement(tcpout_meta, "srcip", &host_IP_netformat, META_TYPE_INT);
	metadata_writeToElement(tcpout_meta, "blockflag", &block_flag, META_TYPE_INT);

	ff->dataOrCtrl = DATA;
	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->destinationID.id = TCPID;
	ff->destinationID.next = NULL;
	(ff->dataFrame).directionFlag = DOWN;
	(ff->dataFrame).pduLength = len;
	(ff->dataFrame).pdu = dataLocal;
	(ff->dataFrame).metaData = tcpout_meta;

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

int jinni_TCP_to_fins_cntrl_exec(metadata *params) {
	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	ff->dataOrCtrl = CONTROL;
	ff->destinationID.id = TCPID; //TODO get the address from local copy of switch table
	ff->destinationID.next = NULL;
	ff->ctrlFrame.senderID = JINNIID;
	ff->ctrlFrame.opcode = CTRL_EXEC;
	ff->ctrlFrame.serialNum = serial_num++;
	ff->ctrlFrame.metaData = params;

	//ff->ctrlFrame.paramterID = command;
	//ff->ctrlFrame.paramterValue = data;
	//ff->ctrlFrame.paramterLen = len;

	PRINT_DEBUG("");
	sem_wait(&Jinni_to_Switch_Qsem);
	if (write_queue(ff, Jinni_to_Switch_Queue)) {
		sem_post(&Jinni_to_Switch_Qsem);
		PRINT_DEBUG("");

		return (1);
	} else {
		sem_post(&Jinni_to_Switch_Qsem);
		PRINT_DEBUG("");

		return (0);
	}
}

void socket_tcp(int domain, int type, int protocol, unsigned long long uniqueSockID) {
	int index;

	PRINT_DEBUG("socket_tcp CALL");
	sem_wait(&jinniSockets_sem);
	index = insertjinniSocket(uniqueSockID, type, protocol);
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	if (index < 0) {
		PRINT_DEBUG("incorrect index !! Crash");
		nack_send(uniqueSockID, socket_call);
		return;
	}
	PRINT_DEBUG("0000");

	ack_send(uniqueSockID, socket_call);
	PRINT_DEBUG("0003");
}

void bind_tcp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr) {

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP_netformat;
	uint32_t dst_IP_netformat;

	PRINT_DEBUG("bind_TCP CALL");

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, bind_call);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	hostport = ntohs(addr->sin_port);
	host_IP_netformat = (addr->sin_addr).s_addr;

	PRINT_DEBUG("%d,%d,%d", host_IP_netformat, hostport, addr->sin_family);

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, bind_call);
		return;
	}

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!checkjinniports(hostport, host_IP_netformat) && !jinniSockets[index].sockopts.FSO_REUSEADDR) {
		PRINT_DEBUG("this port is not free");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, bind_call);
		free(addr);
		return;
	}

	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */

	jinniSockets[index].hostport = hostport;
	jinniSockets[index].host_IP = host_IP_netformat;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_IP.s_addr = ntohl(jinniSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send(uniqueSockID, bind_call);

	free(addr);
	return;

}

void listen_tcp(int index, unsigned long long uniqueSockID, int backlog) {
	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("listen_TCP CALL");

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, listen_call);
		return;
	}

	jinniSockets[index].listening = 1;
	jinniSockets[index].backlog = backlog;

	host_ip = jinniSockets[index].host_IP;
	host_port = jinniSockets[index].hostport;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */
	metadata *params = (metadata *) malloc(sizeof(metadata));
	metadata_create(params);
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");
		nack_send(uniqueSockID, listen_call);
		return;
	}

	uint32_t exec_call = EXEC_TCP_LISTEN;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "backlog", &backlog, META_TYPE_INT);

	if (jinni_TCP_to_fins_cntrl_exec(params)) {
		ack_send(uniqueSockID, listen_call);
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish listen");
		nack_send(uniqueSockID, listen_call);
	}
}

void *connect_tcp_thread(void *local) {
	struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) local;
	int index = thread_data->index;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	free(thread_data);

	int block_flag;
	uint32_t exec_call;
	uint32_t ret_val;

	PRINT_DEBUG("connect_TCP CALL");
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		sem_post(&jinniSockets_sem);
		pthread_exit(NULL);
	}

	block_flag = jinniSockets[index].blockingFlag;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	PRINT_DEBUG();
	struct finsFrame *ff = get_fcf(index, uniqueSockID, block_flag);
	if (ff == NULL) {
		nack_send(uniqueSockID, connect_call);
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		nack_send(uniqueSockID, connect_call);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	int ret;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == 0;

	if (ret || (exec_call != EXEC_TCP_CONNECT && exec_call != EXEC_TCP_ACCEPT) || ret_val == 0) {
		nack_send(uniqueSockID, connect_call);
	} else {
		ack_send(uniqueSockID, connect_call);
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void connect_tcp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr) {
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, connect_call);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	rem_ip = ntohl((addr->sin_addr).s_addr);
	rem_port = (uint32_t) ntohs(addr->sin_port);
	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * according to the RFC document and man pages: Application can call connect more than
	 * once over the same UDP socket changing the address from one to another. SO the assigning
	 * will take place even if the check functions returns (-1) !!!
	 * */

	/** TODO connect for UDP means that this address will be the default address to send
	 * to. BUT IT WILL BE ALSO THE ONLY ADDRESS TO RECEIVER FROM
	 * */

	/** Reverse again because it was reversed by the application itself */
	//hostport = ntohs(addr->sin_port);
	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the jinniSockets database
	 */
	PRINT_DEBUG("%d,%d,%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family);

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket removed/changed");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, connect_call);
		return;
	}

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (jinniSockets[index].connection_status > 0) {
		PRINT_DEBUG("old destined address %d, %d", jinniSockets[index].dst_IP, jinniSockets[index].dstport);
		PRINT_DEBUG("new destined address %d, %d", rem_ip, rem_port);

	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */

	jinniSockets[index].dst_IP = rem_ip;
	jinniSockets[index].dstport = rem_port;
	jinniSockets[index].connection_status++;

	host_ip = jinniSockets[index].host_IP;
	host_port = (uint32_t) jinniSockets[index].hostport;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//jinniSockets[index].host_ip.s_addr = ntohl(jinniSockets[index].host_ip.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	metadata *params = (metadata *) malloc(sizeof(metadata));
	metadata_create(params);
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");
		nack_send(uniqueSockID, connect_call);
		return;
	}

	uint32_t exec_call = EXEC_TCP_CONNECT;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
	metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);

	if (jinni_TCP_to_fins_cntrl_exec(params)) {
		pthread_t thread;
		struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) malloc(sizeof(struct jinni_tcp_thread_data));
		thread_data->index = index;
		thread_data->uniqueSockID = uniqueSockID;

		//spin off thread to handle
		if (pthread_create(&thread, NULL, connect_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create connect_tcp_thread thread.");
			nack_send(uniqueSockID, connect_call);
		}
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish connect");
		nack_send(uniqueSockID, connect_call);
	}

	free(addr);
}

void *accept_tcp_thread(void *local) {
	struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) local;
	int index = thread_data->index;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int flags = thread_data->flags;
	unsigned long long uniqueSockID_new = thread_data->uniqueSockID_new;
	free(thread_data);

	int block_flag = 1; //TODO get from flags

	uint32_t exec_call;
	uint32_t ret_val;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG();
	struct finsFrame *ff = get_fcf(index, uniqueSockID, block_flag);
	if (ff == NULL || ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		nack_send(uniqueSockID, accept_call);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	int ret;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "rem_ip", &rem_ip) == 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "rem_port", &rem_port) == 0;

	if (ret || exec_call != EXEC_TCP_ACCEPT || ret_val == 0) {
		nack_send(uniqueSockID, accept_call);
	} else {
		PRINT_DEBUG("");
		sem_wait(&jinniSockets_sem);
		if (jinniSockets[index].uniqueSockID != uniqueSockID) {
			sem_post(&jinniSockets_sem);

			nack_send(uniqueSockID, accept_call);
		} else {
			int index_new = insertjinniSocket(uniqueSockID_new, jinniSockets[index].type, jinniSockets[index].protocol);
			if (index_new < 0) {
				PRINT_DEBUG("incorrect index !! Crash");
				sem_post(&jinniSockets_sem);

				nack_send(uniqueSockID, accept_call);
			} else {
				jinniSockets[index_new].host_IP = jinniSockets[index].host_IP;
				jinniSockets[index_new].hostport = jinniSockets[index].hostport;
				jinniSockets[index_new].dst_IP = rem_ip;
				jinniSockets[index_new].dstport = rem_port;

				jinniSockets[index].connection_status = 1; //TODO check?
				/*
				 if (jinniSockets[index].connection_status > 0) {

				 if ((srcport != jinniSockets[index].dstport)
				 || (srcip != jinniSockets[index].dst_IP)) {

				 PRINT_DEBUG(
				 "Wrong address, the socket is already connected to another destination");
				 sem_post(&jinniSockets_sem);
				 pthread_exit(NULL);

				 }
				 }*/
				PRINT_DEBUG("");
				sem_post(&jinniSockets_sem);

				ack_send(uniqueSockID, accept_call);
			}
		}
	}

	//*buf = (u_char *)malloc(sizeof(ff->dataFrame.pduLength));
	//memcpy(*buf,ff->dataFrame.pdu,ff->dataFrame.pduLength);
	//memcpy(buf, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	//*buflen = ff->dataFrame.pduLength;
	//addr->sin_addr.s_addr = src_IP;
	//addr->sin_port = srcport;

	PRINT_DEBUG();

	/**TODO Free the finsFrame
	 * This is the final consumer
	 * call finsFrame_free(Struct finsFrame** ff)
	 */
	PRINT_DEBUG();

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void accept_tcp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags) {
	uint32_t host_ip;
	uint32_t host_port;
	int blocking_flag;

	PRINT_DEBUG("Accept_tcp call");
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket removed/changed");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, accept_call);
		return;
	}

	host_ip = jinniSockets[index].host_IP;
	host_port = (uint32_t) jinniSockets[index].hostport;
	blocking_flag = jinniSockets[index].blockingFlag;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	//TODO process flags?

	metadata *params = (metadata *) malloc(sizeof(metadata));
	metadata_create(params);
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send(uniqueSockID, accept_call);
		return;
	}

	uint32_t exec_call = EXEC_TCP_ACCEPT;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	if (jinni_TCP_to_fins_cntrl_exec(params)) {
		pthread_t thread;
		struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) malloc(sizeof(struct jinni_tcp_thread_data));
		thread_data->index = index;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->flags = 0; //TODO implement?
		thread_data->uniqueSockID_new = uniqueSockID_new;

		//spin off thread to handle
		if (pthread_create(&thread, NULL, accept_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create accept_tcp_thread thread.");
			nack_send(uniqueSockID, accept_call);
		}
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish accept");
		nack_send(uniqueSockID, accept_call);
	}
}

void write_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen) {
	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;

	PRINT_DEBUG("");

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, sendmsg_call);
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
	int block_flag = jinniSockets[index].blockingFlag;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	/**
	 * The meta-data paraters are all passes by copy starting from this point
	 */
	if (jinni_TCP_to_fins(data, len, dstport, dst_IP, hostport, host_IP, block_flag)) {
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		ack_send(uniqueSockID, sendmsg_call);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, sendmsg_call);
	}

	return;

}

void *sendmsg_tcp_thread(void *local) {
	struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) local;
	int index = thread_data->index;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	//int block_flag = thread_data->blocking_flag;
	free(thread_data);

	uint32_t exec_call;
	uint32_t ret_val;

	PRINT_DEBUG();
	struct finsFrame *ff = get_fcf(index, uniqueSockID, 1);
	if (ff == NULL || ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		nack_send(uniqueSockID, sendmsg_call); //TODO check return of nonblocking send
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	int ret;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == 0;

	if (ret || exec_call != EXEC_TCP_SEND || ret_val == 0) {
		nack_send(uniqueSockID, sendmsg_call);
	} else {
		ack_send(uniqueSockID, sendmsg_call);
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void send_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags) {

	//	sendto_tcp(senderid, sockfd, datalen, data, flags, NULL, 0);

	//	return;

	uint16_t hostport;
	uint16_t dstport;
	uint32_t host_IP;
	uint32_t dst_IP;
	int len = datalen;

	if (flags == -1000) {
		return (write_tcp(index, uniqueSockID, data, datalen)); //TODO remove?
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

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (jinniSockets[index].connection_status == 0) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketjinni failed to accomplish send, socket found unconnected !!!");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	dstport = jinniSockets[index].dstport;

	dst_IP = jinniSockets[index].dst_IP;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the jinnisockets
	 * check insertjinniSocket(processid, sockfd, fakeID, type, protocol);
	 */
	hostport = jinniSockets[index].hostport;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_IP = jinniSockets[index].host_IP;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);
	PRINT_DEBUG("");

	PRINT_DEBUG("%d,%d,%d,%d", dst_IP, dstport, host_IP, hostport);
	//free(data);
	//free(addr);
	PRINT_DEBUG("");

	int blocking_flag = 1; //TODO get from flags

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (jinni_TCP_to_fins(data, len, dstport, dst_IP, hostport, host_IP, blocking_flag)) {
		if (blocking_flag) {
			pthread_t thread;
			struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) malloc(sizeof(struct jinni_tcp_thread_data));
			thread_data->index = index;
			thread_data->uniqueSockID = uniqueSockID;
			//thread_data->blocking_flag = blocking_flag;

			//spin off thread to handle
			if (pthread_create(&thread, NULL, sendmsg_tcp_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create accept_tcp_thread thread.");
				nack_send(uniqueSockID, sendmsg_call);
			}
		} else {
			ack_send(uniqueSockID, sendmsg_call);
		}
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish send");
		nack_send(uniqueSockID, sendmsg_call);
	}
}

void sendto_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *addr, socklen_t addrlen) {
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

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(uniqueSockID, sendmsg_call);
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
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, sendmsg_call);
		return;
	}

	/*//TODO confirm this
	 if (jinniSockets[index].connection_status == 0 || dst_IP != jinniSockets[index].dst_IP || dstport != jinniSockets[index].dstport) {
	 sem_wait(&jinniSockets_sem);

	 nack_send(uniqueSockID, sendmsg_call);
	 return;
	 }
	 */

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
	if (hostport == 0) {
		while (1) {
			hostport = randoming(MIN_port, MAX_port);
			if (checkjinniports(hostport, host_IP)) {
				break;
			}
		}
		jinniSockets[index].hostport = hostport;
	}
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	int blocking_flag = 1; //TODO get from flags

	/** the meta-data paraters are all passes by copy starting from this point
	 *
	 */
	if (jinni_TCP_to_fins(data, len, dstport, dst_IP, hostport, host_IP, blocking_flag)) {
		PRINT_DEBUG("");
		/** TODO prevent the socket interceptor from holding this semaphore before we reach this point */
		ack_send(uniqueSockID, sendmsg_call);
		PRINT_DEBUG("");

	} else {
		PRINT_DEBUG("socketjinni failed to accomplish sendto");
		nack_send(uniqueSockID, sendmsg_call);
	}
}

void *recvfrom_tcp_thread(void *local) {
	struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) local;
	int id = thread_data->id;
	int index = thread_data->index;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int data_len = thread_data->data_len;
	int flags = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("recvfrom_tcp_thread: Entered: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);

	int blocking_flag = 1; //TODO get from flags

	PRINT_DEBUG();
	struct finsFrame *ff = get_fdf(index, uniqueSockID, blocking_flag);
	PRINT_DEBUG("after get_fdf uniqID=%llu ind=%d", uniqueSockID, index);

	if (ff == NULL) { //TODO add check if nonblocking send
		PRINT_DEBUG("recvfrom_tcp_thread: Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call);
		pthread_exit(NULL);
	}

	struct sockaddr_in addr;
	uint32_t src_port;
	if (metadata_readFromElement(ff->dataFrame.metaData, "portsrc", &src_port) == 0) {
		addr.sin_port = 0;
	} else {
		addr.sin_port = (uint16_t) src_port;
	}

	uint32_t src_ip;
	if (metadata_readFromElement(ff->dataFrame.metaData, "ipsrc", &src_ip) == 0) {
		addr.sin_addr.s_addr = 0;
	} else {
		addr.sin_addr.s_addr = (uint32_t) src_ip;
	}

	//#######
	PRINT_DEBUG("address: %d/%d", addr.sin_addr.s_addr, ntohs(addr.sin_port));
	//#######

	int msg_len = 4 * sizeof(int) + sizeof(unsigned long long) + sizeof(struct sockaddr_in) + ff->dataFrame.pduLength;
	u_char *msg = (u_char *) malloc(msg_len);
	u_char *pt = msg;

	*(int *) pt = recvmsg_call;
	pt += sizeof(int);

	*(unsigned long long *) pt = uniqueSockID;
	pt += sizeof(unsigned long long);

	*(int *) pt = ACK;
	pt += sizeof(int);

	*(int *) pt = sizeof(addr);
	pt += sizeof(int);

	memcpy(pt, &addr, sizeof(struct sockaddr_in));
	pt += sizeof(struct sockaddr_in);

	*(int *) pt = ff->dataFrame.pduLength;
	pt += sizeof(int);

	memcpy(pt, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	pt += ff->dataFrame.pduLength;

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		PRINT_DEBUG("recvfrom_tcp_thread: Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call);
		pthread_exit(NULL);
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("recvfrom_tcp_thread: Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send(uniqueSockID, recvmsg_call);
	} else {
		PRINT_DEBUG("recvfrom_tcp_thread: Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
	}

	//TODO send size back to TCP handlers

	free(msg);
	pthread_exit(NULL);
}

/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvfrom_tcp(int index, unsigned long long uniqueSockID, int data_len, int flags, int msg_flags) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	int multi_flag;
	int thread_flags;

	PRINT_DEBUG("recvfrom_tcp: Entered: index=%d uniqueSockID=%llu data_len=%d flags=%d", index, uniqueSockID, data_len, flags);

	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, recvmsg_call);
		return;
	}

	multi_flag = 0; //for udp, if SOL_SOCKET/SO_REUSEADDR
	//change flags?

	/** TODO handle flags cases, convert flags/msg_flags to */
	thread_flags = 0; // |= FLAGS_BLOCK | MULTI_FLAG;

	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	if (1) { //TODO thread count check
		pthread_t thread;
		struct jinni_tcp_thread_data *thread_data = (struct jinni_tcp_thread_data *) malloc(sizeof(struct jinni_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->index = index;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->data_len = data_len;
		thread_data->flags = thread_flags;

		//spin off thread to handle
		if (pthread_create(&thread, NULL, recvfrom_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create recvfrom_udp_thread thread.");
			nack_send(uniqueSockID, recvmsg_call);

			free(thread_data);
		}
	}
}

void release_tcp(int index, unsigned long long uniqueSockID) {
	int ret;

	PRINT_DEBUG("release_udp: index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_tcp.");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, recvmsg_call);
		return;
	}

	ret = removejinniSocket(uniqueSockID);

	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	if (ret) {
		ack_send(uniqueSockID, release_call);
	} else {
		nack_send(uniqueSockID, release_call);
	}
}

//void recvfrom_tcp(void *threadData) {
void recvfrom_tcp_old(int index, unsigned long long uniqueSockID, int datalen, int flags, int symbol) {

	/** symbol parameter is the one to tell if an address has been passed from the
	 * application to get the sender address or not
	 */

	u_char buf[MAX_DATA_PER_TCP];

	u_char *bufptr;
	bufptr = buf;
	struct sockaddr_in *addr;
	int buflen = 0;
	int i;
	int blocking_flag;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;
	/*
	 struct recvfrom_data *thread_data;
	 thread_data = (struct recvfrom_data *) threadData;

	 unsigned long long uniqueSockID = thread_data->uniqueSockID;
	 int datalen = thread_data->datalen;
	 int flags = thread_data->flags;
	 int symbol = thread_data->symbol;
	 */
	if (symbol == 1)
		addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	addr = NULL;
	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	//PRINT_DEBUG("Entered recv thread:%d", thread_data->id);

	PRINT_DEBUG("");
	sem_wait(&jinniSockets_sem);
	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		sem_post(&jinniSockets_sem);
		//recvthread_exit(thread_data);
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG();
	blocking_flag = jinniSockets[index].blockingFlag;
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */

	if (TCPreadFrom_fins(uniqueSockID, bufptr, &buflen, symbol, addr, blocking_flag) == 1) {

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("%d", buflen);
		PRINT_DEBUG("%s", buf);

		msg_len = 4 * sizeof(int) + sizeof(unsigned long long) + buflen + (symbol ? sizeof(struct sockaddr_in) : 0);
		msg = malloc(msg_len);
		pt = msg;

		*(int *) pt = recvmsg_call;
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
		}

		*(int *) pt = buflen;
		pt += sizeof(int);

		memcpy(pt, buf, buflen);
		pt += buflen;

		if (pt - (u_char *) msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
			free(msg);
			//recvthread_exit(thread_data);
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);

		//free(buf);
		PRINT_DEBUG();
	} else {
		PRINT_DEBUG("socketjinni failed to accomplish recvfrom");
		sem_wait(&jinniSockets_sem);
		index = findjinniSocket(uniqueSockID);
		PRINT_DEBUG("");
		sem_post(&jinniSockets_sem);

		if (index == -1) {
			PRINT_DEBUG("socket descriptor not found into jinni sockets");
			//recvthread_exit(thread_data);
		} else {
			nack_send(uniqueSockID, recvmsg_call);
		}
	}
	PRINT_DEBUG();

	/** TODO find a way to release these buffers later
	 * using free here causing a segmentation fault
	 */
	//free(addr);
	//free(buf);
	//recvthread_exit(thread_data);
}

void recv_tcp_old(int index, unsigned long long uniqueSockID, int data_len, int flags, int msg_flags) {
	//u_char *buf= NULL;
	u_char buf[MAX_DATA_PER_TCP];
	int buflen = 0;

	int blocking_flag;
	blocking_flag = 1;

	void *msg;
	u_char *pt;
	int msg_len;
	int ret_val;

	/** TODO handle flags cases */
	switch (flags) {

	default:
		break;

	}

	PRINT_DEBUG("");
	sem_wait(&jinniSockets_sem);
	if (jinniSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		sem_post(&jinniSockets_sem);

		nack_send(uniqueSockID, recvmsg_call);
		return;
	}
	//TODO something?
	PRINT_DEBUG("");
	sem_post(&jinniSockets_sem);

	/** the meta-data parameters are all passed by copy starting from this point
	 *
	 */
	/** passing 0 as value for symbol, and NULL as an address
	 * this the difference between the call from here, and the call in case of
	 * the function recvfrom_udp
	 * */
	if (TCPreadFrom_fins(uniqueSockID, buf, &buflen, 0, NULL, blocking_flag) == 1) {

		buf[buflen] = '\0'; //may be specific to symbol==0

		PRINT_DEBUG("%d", buflen);
		PRINT_DEBUG("%s", buf);

		msg_len = sizeof(u_int) + sizeof(unsigned long long) + sizeof(int) + buflen;
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
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - (u_char *) msg, msg_len);
			free(msg);
			exit(1);
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, (char *) msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);

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
	//free(addr);
	//free(buf);
}

void getpeername_tcp(int index, unsigned long long uniqueSockID, int addrlen) {

	return;

}

void shutdown_tcp(int index, unsigned long long uniqueSockID, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	index = findjinniSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into jinni sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG();

	ack_send(uniqueSockID, shutdown_call);
}

void setsockopt_tcp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval) {

}

void getsockopt_tcp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval) {

}
