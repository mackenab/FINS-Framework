/**
 * @file tcpHandling.c
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#include "tcpHandling.h"
#include <finstypes.h>

//#include <ipv4.h>
#define	IP4_PT_TCP		6		/* protocol type for TCP packets	*/

extern sem_t daemonSockets_sem;
extern struct fins_daemon_socket daemonSockets[MAX_SOCKETS];

extern int thread_count;
extern sem_t thread_sem;

extern finsQueue Daemon_to_Switch_Queue;
extern finsQueue Switch_to_Daemon_Queue;
extern sem_t Daemon_to_Switch_Qsem;
extern sem_t Switch_to_Daemon_Qsem;

int serial_num = 0;

int daemon_fdf_to_tcp(u_char *data, u_int data_len, metadata *params) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = TCPID;
	ff->destinationID.next = NULL;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;
	ff->dataFrame.metaData = params;

	sem_wait(&Daemon_to_Switch_Qsem);
	if (write_queue(ff, Daemon_to_Switch_Queue)) {
		sem_post(&Daemon_to_Switch_Qsem);
		PRINT_DEBUG("");

		return 1;
	} else {
		sem_post(&Daemon_to_Switch_Qsem);
		PRINT_DEBUG("freeing: ff=%p", ff);
		free(ff);

		return 0;
	}
}

int daemon_fcf_to_tcp(uint16_t opcode, metadata *params) {
	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	//TODO get the address from local copy of switch table
	ff->dataOrCtrl = CONTROL;
	ff->destinationID.id = TCPID;
	ff->destinationID.next = NULL;

	ff->ctrlFrame.senderID = DAEMONID;
	ff->ctrlFrame.serialNum = serial_num++;
	ff->ctrlFrame.opcode = opcode;
	ff->ctrlFrame.metaData = params;

	PRINT_DEBUG("daemon_TCP_to_fins_cntrl: ff=%p, meta=%p", ff, params);
	sem_wait(&Daemon_to_Switch_Qsem);
	if (write_queue(ff, Daemon_to_Switch_Queue)) {
		sem_post(&Daemon_to_Switch_Qsem);
		PRINT_DEBUG("");

		return (1);
	} else {
		sem_post(&Daemon_to_Switch_Qsem);
		PRINT_DEBUG("freeing: ff=%p", ff);
		free(ff);

		return (0);
	}
}

void socket_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol) {
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

void bind_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr) {

	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d", uniqueSockID, index, call_id, call_index);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family=%d", addr->sin_family);
		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	host_ip = ntohl(addr->sin_addr.s_addr);
	host_port = ntohs(addr->sin_port);

	PRINT_DEBUG("bind address: host=%u (%s):%d host_IP_netformat=%u", host_ip, inet_ntoa(addr->sin_addr), host_port, htonl(host_ip));

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		return;
	}

	//TODO check if already bound, return already bound error

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!check_daemon_ports(host_port, host_ip) && !daemonSockets[index].sockopts.FSO_REUSEADDR) { //TODO change, need to check if in TIME_WAIT state
		PRINT_DEBUG("this port is not free");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);
		free(addr);
		return;
	}

	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the daemonSockets database
	 */

	if (host_ip == any_ip_addr) {
		daemonSockets[index].host_ip = my_host_ip_addr;
	} else {
		daemonSockets[index].host_ip = host_ip;
	}

	daemonSockets[index].host_port = host_port;
	PRINT_DEBUG("bind address: host=%u:%u (%u)", daemonSockets[index].host_ip, host_port, htonl(daemonSockets[index].host_ip));
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[index].host_IP.s_addr = ntohl(daemonSockets[index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send_new(uniqueSockID, index, call_id, call_index, bind_call, 0);

	free(addr);
	return;

}

void listen_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog) {
	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d backlog=%d", uniqueSockID, index, call_id, call_index, backlog);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
		return;
	}

	socket_state state = daemonSockets[index].state;
	daemonSockets[index].listening = 1;
	daemonSockets[index].backlog = backlog;

	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("listen address: host=%u/%d", host_ip, host_port);

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */
	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");
		nack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
		return;
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_LISTEN;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "backlog", &backlog, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);

	if (daemon_fcf_to_tcp(CTRL_EXEC, params)) {
		ack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish listen");
		nack_send_new(uniqueSockID, index, call_id, call_index, listen_call, 0);
		metadata_destroy(params);
	}
}

void *connect_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & (SOCK_NONBLOCK | O_NONBLOCK);
	int ret;
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);

	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, EINPROGRESS); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: id=%d, index=%d, uniqueSockID=%llu opcode=%d, metaData=%d",
				id, index, uniqueSockID, ff->ctrlFrame.opcode, ff->ctrlFrame.metaData==NULL);
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_CONNECT && exec_call != EXEC_TCP_ACCEPT)) {
		PRINT_DEBUG("Exiting, meta errors: id=%d, index=%d, uniqueSockID=%llu, ret=%d, exec_call=%d, ret_val=%d",
				id, index, uniqueSockID, ret, exec_call, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
	} else {
		PRINT_DEBUG("Exiting, ACK: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("Exiting, socket closed: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			sem_post(&daemonSockets_sem);
			freeFinsFrame(ff);
			pthread_exit(NULL);
		}

		if (ret_val) {
			daemonSockets[index].state = SS_CONNECTED;

			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			ack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		} else {
			daemonSockets[index].state = SS_UNCONNECTED;

			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, ECONNREFUSED); //TODO change based off of timeout, refused etc
		}
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void connect_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags) {
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d flags=%d", uniqueSockID, index, call_id, call_index, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, ( SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, EAFNOSUPPORT);
		free(addr);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	rem_ip = ntohl((addr->sin_addr).s_addr);
	rem_port = ntohs(addr->sin_port);

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
	 * any modifications to the contents of the daemonSockets database
	 */
	PRINT_DEBUG("address: rem=%u (%s):%d rem_IP_netformat=%u", rem_ip, inet_ntoa(addr->sin_addr), rem_port, htonl(rem_ip));

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket removed/changed");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, ENOTSOCK); //TODO check?
		free(addr);
		return;
	}

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	socket_state state = daemonSockets[index].state;
	if (state == SS_CONNECTING) {
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			sem_post(&daemonSockets_sem);

			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, EALREADY);
			free(addr);
			return;
		} else {
			sem_post(&daemonSockets_sem);

			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0); //TODO EADDRINUSE, check?
			free(addr);
			return;
		}
	} else if (state > SS_CONNECTING) {
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, EISCONN);
		free(addr);
		return;
	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */

//if statements make sure socket is in SS_UNCONNECTED
	daemonSockets[index].listening = 0;
	daemonSockets[index].dst_ip = rem_ip;
	daemonSockets[index].dst_port = rem_port;
	daemonSockets[index].state = SS_CONNECTING;

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
		PRINT_DEBUG("");
		while (1) {
			host_port = (uint16_t) randoming(MIN_port, MAX_port);
			if (check_daemon_ports(host_port, host_ip)) {
				break;
			}
		}
		PRINT_DEBUG("");
		daemonSockets[index].host_port = host_port;
	}
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
//daemonSockets[index].host_ip.s_addr = ntohl(daemonSockets[index].host_ip.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		free(addr);
		return;
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_CONNECT;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
	metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);

	if (daemon_fcf_to_tcp(CTRL_EXEC, params)) {
		struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->flags = flags;

		//spin off thread to handle
		pthread_t thread;
		if (pthread_create(&thread, NULL, connect_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create connect_tcp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
			free(thread_data);
			metadata_destroy(params);
		} else {
			pthread_detach(thread);
		}
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish connect");
		nack_send_new(uniqueSockID, index, call_id, call_index, connect_call, 0);
		metadata_destroy(params);
	}

	free(addr);
}

void *accept_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	unsigned long long uniqueSockID_new = thread_data->uniqueSockID_new;
	int index_new = thread_data->index_new;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & SOCK_NONBLOCK; //TODO get from flags
	int ret;

	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, No fdf/opcode/metadata: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "rem_ip", &rem_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "rem_port", &rem_port) == CONFIG_FALSE;

	if (ret || exec_call != EXEC_TCP_ACCEPT || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: id=%d, index=%d, uniqueSockID=%llu, ret=%d, exec_call=%d, ret_val=%d", id, index, uniqueSockID, ret, exec_call, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
	} else {
		PRINT_DEBUG("");
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			PRINT_DEBUG("Exiting, socket closed: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		} else {
			//int index_new = insert_daemonSocket(uniqueSockID_new, daemonSockets[index].type, daemonSockets[index].protocol);
			ret = insert_daemonSocket_new(uniqueSockID_new, index_new, daemonSockets[index].type, daemonSockets[index].protocol);
			if (ret) {
				PRINT_DEBUG("incorrect index !! Crash");
				sem_post(&daemonSockets_sem);

				PRINT_DEBUG("Exiting, insert faile: id=%d, index=%d, uniqueSockID=%llu, uniqueSockID_new=%llu", id, index, uniqueSockID, uniqueSockID_new);
				nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
			} else {
				daemonSockets[index_new].host_ip = daemonSockets[index].host_ip;
				daemonSockets[index_new].host_port = daemonSockets[index].host_port;
				daemonSockets[index_new].dst_ip = rem_ip;
				daemonSockets[index_new].dst_port = rem_port;

				daemonSockets[index_new].state = SS_CONNECTED;
				daemonSockets[index].state = SS_UNCONNECTED;

				PRINT_DEBUG("");
				sem_post(&daemonSockets_sem);

				PRINT_DEBUG("Exiting, ACK: id=%d, index=%d, uniqueSockID=%llu, uniqueSockID_new=%llu", id, index, uniqueSockID, uniqueSockID_new);
				ack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
			}
		}
	}

	/**TODO Free the finsFrame
	 * This is the final consumer
	 * call finsFrame_free(Struct finsFrame** ff)
	 */
	PRINT_DEBUG("");

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void accept_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags) {
	uint32_t host_ip;
	uint32_t host_port;
	int blocking_flag;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d uniqueSockID_new=%llu index=%d flags=%d",
			uniqueSockID, index, call_id, call_index, uniqueSockID_new, index_new, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("socket removed/changed");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}

	if (!daemonSockets[index].listening) {
		PRINT_DEBUG("socket not listening");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}

	host_ip = daemonSockets[index].host_ip;
	host_port = (uint32_t) daemonSockets[index].host_port;
	blocking_flag = daemonSockets[index].blockingFlag;

	socket_state state = daemonSockets[index].state;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("accept address: host=%u/%d", host_ip, host_port);

	//TODO process flags?

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		return;
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_ACCEPT;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);

	if (daemon_fcf_to_tcp(CTRL_EXEC, params)) {
		struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->uniqueSockID_new = uniqueSockID_new;
		thread_data->index_new = index_new;
		thread_data->flags = 0; //TODO implement?

		//spin off thread to handle
		pthread_t thread;
		if (pthread_create(&thread, NULL, accept_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create accept_tcp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
			free(thread_data);
			metadata_destroy(params);
		} else {
			pthread_detach(thread);
		}
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish accept");
		nack_send_new(uniqueSockID, index, call_id, call_index, accept_call, 0);
		metadata_destroy(params);
	}
}

void getname_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer) {
	int state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;
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

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
	hdr->call_type = getname_call;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
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

void ioctl_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len) {
	u_int len;
	int msg_len;
	u_char *msg = NULL;
	struct nl_daemon_to_wedge *hdr;
	u_char *pt;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d cmd=%d len=%d", uniqueSockID, index, call_id, call_index, cmd, buf_len);

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
			PRINT_DEBUG("Exiting, fail send_wedge: uniqueSockID=%llu", uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
		}
		free(msg);
	} else {
		nack_send_new(uniqueSockID, index, call_id, call_index, ioctl_call, 0);
	}
}

void *sendmsg_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	//int data_len = thread_data->data_len;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & 0;
	int ret;

	uint32_t exec_call = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0); //TODO check return of nonblocking send
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || exec_call != EXEC_TCP_SEND || ret_val == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	} else {
		ack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void sendmsg_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags, struct sockaddr_in *addr,
		int addr_len) {
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: index=%d, uniqueSockID=%llu, data_len=%d, flags=%d", index, uniqueSockID, data_len, flags);
	PRINT_DEBUG("MSG_CONFIRM=%d (%d) MSG_DONTROUTE=%d (%d) MSG_DONTWAIT=%d (%d) MSG_EOR=%d (%d) MSG_MORE=%d (%d) MSG_NOSIGNAL=%d (%d) MSG_OOB=%d (%d)",
			MSG_CONFIRM & flags, MSG_CONFIRM, MSG_DONTROUTE & flags, MSG_DONTROUTE, MSG_DONTWAIT & flags, MSG_DONTWAIT, MSG_EOR & flags, MSG_EOR, MSG_MORE & flags, MSG_MORE, MSG_NOSIGNAL & flags, MSG_NOSIGNAL, MSG_OOB & flags, MSG_OOB);

	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		if (data_len) {
			free(data);
		}
		if (addr_len > 0) {
			free(addr);
		}
		return;
	}

	/** copying the data passed to be able to free the old memory location
	 * the new created location is the one to be included into the newly created finsFrame*/
	PRINT_DEBUG("");
	/** check if this socket already connected to a destined address or not */

	if (daemonSockets[index].state < SS_CONNECTING) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketdaemon failed to accomplish send, socket found unconnected !!!");
		sem_post(&daemonSockets_sem);

		//TODO buffer data & send ACK

		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		if (data_len) {
			free(data);
		}
		if (addr_len > 0) {
			free(addr);
		}
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	dst_port = daemonSockets[index].dst_port;

	dst_ip = daemonSockets[index].dst_ip;

	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	host_port = daemonSockets[index].host_port;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_ip = daemonSockets[index].host_ip;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("host=%u/%d, dst=%u/%d", host_ip, host_port, dst_ip, dst_port);

	PRINT_DEBUG("");

	//int blocking_flag = 1; //TODO get from flags

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		return;
	}
	metadata_create(params);

	//int protocol = IP4_PT_TCP;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	//metadata_writeToElement(params, "protocol", &protocol, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "src_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "src_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);
	metadata_writeToElement(params, "dst_port", &dst_port, META_TYPE_INT);

	if (daemon_fdf_to_tcp(data, data_len, params)) {
		if (!(flags & MSG_DONTWAIT)) {
			struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
			thread_data->id = thread_count++;
			thread_data->uniqueSockID = uniqueSockID;
			thread_data->index = index;
			thread_data->call_id = call_id;
			thread_data->call_index = call_index;
			thread_data->data_len = data_len;
			thread_data->flags = flags;

			//spin off thread to handle
			pthread_t thread;
			if (pthread_create(&thread, NULL, sendmsg_tcp_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create accept_tcp_thread thread.");
				nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
			} else {
				pthread_detach(thread);
			}
		} else {
			ack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		}
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish send");
		nack_send_new(uniqueSockID, index, call_id, call_index, sendmsg_call, 0);
		metadata_destroy(params);
		if (data_len) {
			free(data);
		}
	}

	if (addr_len > 0) {
		free(addr);
	}
}

void *recvmsg_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int data_len = thread_data->data_len;
	int flags = thread_data->flags;
	free(thread_data);

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);

	int ret;
	int non_blocking_flag = flags & MSG_DONTWAIT; //TODO get from flags
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_tcp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		pthread_exit(NULL);
	}

	state = daemonSockets[index].state;
	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemonSockets[index].dst_ip;
		rem_port = daemonSockets[index].dst_port;
	}

	/** TODO handle flags cases, convert flags/msg_flags to */
//thread_flags = 0; // |= FLAGS_BLOCK | MULTI_FLAG;
	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	PRINT_DEBUG("");
	struct finsFrame *ff = NULL;
	ret = get_fdf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fdf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);

	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, EAGAIN);
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
		}
		pthread_exit(NULL);
	}

	struct sockaddr_in addr;
	uint32_t src_port;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_port", &src_port) == CONFIG_FALSE) {
		addr.sin_port = 0;
	} else {
		addr.sin_port = (uint16_t) src_port;
	}

	uint32_t src_ip;
	if (metadata_readFromElement(ff->dataFrame.metaData, "src_ip", &src_ip) == CONFIG_FALSE) {
		addr.sin_addr.s_addr = 0;
	} else {
		addr.sin_addr.s_addr = (uint32_t) src_ip;
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
		nack_send_new(uniqueSockID, index, call_id, call_index, getname_call, 0);
		pthread_exit(NULL);
	}

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
	hdr->call_type = recvmsg_call;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
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
		//TODO send size back to TCP handlers
		if (state > SS_UNCONNECTED) {
			PRINT_DEBUG("recvfrom address: host=%u/%d rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
		} else {
			PRINT_DEBUG("recvfrom address: host=%u/%d", host_ip, host_port);
		}

		metadata *params = (metadata *) malloc(sizeof(metadata));
		if (params == NULL) {
			PRINT_ERROR("metadata creation failed");

			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);
			freeFinsFrame(ff);
			pthread_exit(NULL);
		}
		metadata_create(params);

		uint32_t param_id = CTRL_SET_PARAM;
		metadata_writeToElement(params, "param_id", &param_id, META_TYPE_INT);

		metadata_writeToElement(params, "state", &state, META_TYPE_INT);
		metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
		metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
		if (state > SS_UNCONNECTED) {
			metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
			metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
		}

		if (daemon_fcf_to_tcp(CTRL_SET_PARAM, params)) {
			PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		} else {
			PRINT_DEBUG("Exiting, fail sending flow msgs: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			metadata_destroy(params);
		}

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
void recvmsg_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags) {

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
		struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->data_len = data_len;
		thread_data->flags = flags;

		//spin off thread to handle
		pthread_t thread;
		if (pthread_create(&thread, NULL, recvmsg_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create recvfrom_udp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, recvmsg_call, 0);

			free(thread_data);
		} else {
			pthread_detach(thread);
		}
	}
}

void *release_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & 0; //TODO get from flags
	int ret;

	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	//uint32_t rem_ip = 0;
	//uint16_t rem_port = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);

	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, release_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, No fdf/opcode/metadata: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_CLOSE && exec_call != EXEC_TCP_CLOSE_STUB) || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: id=%d, index=%d, uniqueSockID=%llu, ret=%d, exec_call=%d, ret_val=%d", id, index, uniqueSockID, ret, exec_call, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
	} else {
		PRINT_DEBUG("");
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			PRINT_DEBUG("Exiting, socket closed: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		} else {
			if (remove_daemonSocket(uniqueSockID)) {
				PRINT_DEBUG("Exiting, ACK: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
				sem_post(&daemonSockets_sem);

				ack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
			} else {
				PRINT_DEBUG("Exiting, remove fail: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
				sem_post(&daemonSockets_sem);

				nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
			}

		}
	}

	PRINT_DEBUG("");

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void release_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index) { //TODO finish
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("index=%d uniqueSockID=%llu", index, uniqueSockID);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling release_tcp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		return;
	}

	state = daemonSockets[index].state;
	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemonSockets[index].dst_ip;
		rem_port = daemonSockets[index].dst_port;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	//TODO process flags?

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("release address: host=%u/%d rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
	} else {
		PRINT_DEBUG("release address: host=%u/%d", host_ip, host_port);
	}

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		return;
	}
	metadata_create(params);

	uint32_t exec_call = (state > SS_UNCONNECTED) ? EXEC_TCP_CLOSE : EXEC_TCP_CLOSE_STUB;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	//metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (state > SS_UNCONNECTED) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	if (daemon_fcf_to_tcp(CTRL_EXEC, params)) {
		struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->flags = 0; //TODO implement?

		//spin off thread to handle
		pthread_t thread;
		if (pthread_create(&thread, NULL, release_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create release_tcp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
			free(thread_data);
			metadata_destroy(params);
		} else {
			pthread_detach(thread);
		}
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish release");
		nack_send_new(uniqueSockID, index, call_id, call_index, release_call, 0);
		metadata_destroy(params);
	}
}

void *poll_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int flags = thread_data->flags; //has events
	free(thread_data);

	int non_blocking_flag = flags & 0; //TODO get from flags
	int ret;

	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	uint32_t ret_msg = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_EXEC_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, No fcf/opcode/metadata: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_msg", &ret_msg) == CONFIG_FALSE;
	//ret += metadata_readFromElement(ff->ctrlFrame.metaData, "mask", &mask) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_POLL) || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: id=%d, index=%d, uniqueSockID=%llu, ret=%d, exec_call=%d, ret_val=%d", id, index, uniqueSockID, ret, exec_call, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
	} else {
		PRINT_DEBUG("");
		sem_wait(&daemonSockets_sem);
		if (daemonSockets[index].uniqueSockID != uniqueSockID) {
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			PRINT_DEBUG("Exiting, socket closed: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		} else {
			PRINT_DEBUG("");
			sem_post(&daemonSockets_sem);

			//send msg to wedge
			int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(u_int);
			u_char *msg = (u_char *) malloc(msg_len);
			if (msg == NULL) {
				PRINT_ERROR("ERROR: buf alloc fail");
				nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
				pthread_exit(NULL);
			}

			struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
			hdr->call_type = poll_call;
			hdr->call_id = call_id;
			hdr->call_index = call_index;
			hdr->ret = ACK;
			hdr->msg = 0;
			u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

			*(u_int *) pt = ret_msg;
			pt += sizeof(u_int);

			if (pt - msg != msg_len) {
				PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
				free(msg);
				nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
				pthread_exit(NULL);
			}

			PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_DEBUG("Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
				nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
			} else {
				PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			}
			free(msg);
		}
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void poll_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int events) {
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d events=%x", uniqueSockID, index, call_id, call_index, events);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling poll_tcp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		return;
	}

	state = daemonSockets[index].state;
	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemonSockets[index].dst_ip;
		rem_port = daemonSockets[index].dst_port;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("poll address: host=%u/%u rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
	} else {
		PRINT_DEBUG("poll address: host=%u/%u", host_ip, host_port);
	}

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		return;
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_POLL;
	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &events, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (state > SS_UNCONNECTED) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	if (daemon_fcf_to_tcp(CTRL_EXEC, params)) {
		struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
		thread_data->id = thread_count++;
		thread_data->uniqueSockID = uniqueSockID;
		thread_data->index = index;
		thread_data->call_id = call_id;
		thread_data->call_index = call_index;
		thread_data->flags = events; //TODO implement

		//spin off thread to handle
		pthread_t thread;
		if (pthread_create(&thread, NULL, poll_tcp_thread, (void *) thread_data)) {
			PRINT_ERROR("ERROR: unable to create poll_tcp_thread thread.");
			nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
			free(thread_data);
			metadata_destroy(params);
		} else {
			pthread_detach(thread);
		}
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish poll_tcp");
		nack_send_new(uniqueSockID, index, call_id, call_index, poll_call, 0);
		metadata_destroy(params);
	}
}

void shutdown_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	//index = find_daemonSocket(uniqueSockID);
	if (index == -1) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		exit(1);
	}

	PRINT_DEBUG("index = %d", index);
	PRINT_DEBUG("");

	ack_send(uniqueSockID, shutdown_call, 0);
}

void *getsockopt_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & 0; //TODO get from flags
	int ret;

	uint32_t param_id = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_READ_PARAM_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: id=%d, index=%d, uniqueSockID=%llu opcode=%d, metaData=%d",
				id, index, uniqueSockID, ff->ctrlFrame.opcode, ff->ctrlFrame.metaData==NULL);
		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "param_id", &param_id) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || /*(exec_call != EXEC_TCP_CONNECT && exec_call != EXEC_TCP_ACCEPT) ||*/ret_val == 0) {
		PRINT_DEBUG("Exiting, meta errors: id=%d, index=%d, uniqueSockID=%llu, ret=%d, exec_call=%d, ret_val=%d",
				id, index, uniqueSockID, ret, param_id, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
	} else {
		//TODO switch by param_id, convert into val/len
		int len = 0;
		uint8_t *val = NULL;
		//################

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			pthread_exit(NULL);
		}

		struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = getsockopt_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = len;
		pt += sizeof(int);

		if (len > 0) {
			memcpy(pt, val, len);
			pt += len;
		}

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			PRINT_DEBUG("Exiting, No fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			freeFinsFrame(ff);
			pthread_exit(NULL);
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		} else {
			PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		}
		free(msg);
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void getsockopt_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval) {
	uint32_t host_ip;
	uint16_t host_port;
	socket_state state;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d level=%d, optname=%d, optlen=%d",
			uniqueSockID, index, call_id, call_index, level, optname, optlen);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling getsockopt_tcp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		return;
	}

	state = daemonSockets[index].state;
	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemonSockets[index].dst_ip;
		rem_port = daemonSockets[index].dst_port;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		return;
	}
	metadata_create(params);

	int send_dst = -1;
	//uint32_t param_id = 0;
	int len = 0;
	uint8_t *val = NULL;

	metadata_writeToElement(params, "call_id", &call_id, META_TYPE_INT);
	metadata_writeToElement(params, "call_index", &call_index, META_TYPE_INT);
	metadata_writeToElement(params, "param", &optname, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (state > SS_UNCONNECTED) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	switch (optname) {
	case SO_DEBUG:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_DEBUG; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_REUSEADDR:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_REUSEADDR; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_SNDBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_RCVBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_KEEPALIVE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_OOBINLINE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_OOBINLINE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_NO_CHECK:
	case SO_PRIORITY:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_PRIORITY; //TODO move into sem's
			send_dst = 0;
		}
		break;
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
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemonSockets[index].sockopts.FSO_PASSCRED; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_PEERCRED:
		//TODO trickier
		break;
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_ATTACH_FILTER:
	case SO_DETACH_FILTER:
		break;
	default:
		//nack?
		PRINT_DEBUG("default=%d", optname);
		break;
	}

	if (send_dst == -1) {
		PRINT_DEBUG("freeing meta=%p", params);
		metadata_destroy(params);
		nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
	} else if (send_dst == 0) {
		PRINT_DEBUG("freeing meta=%p", params);
		metadata_destroy(params);

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			return;
		}

		struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) msg;
		hdr->call_type = getsockopt_call;
		hdr->call_id = call_id;
		hdr->call_index = call_index;
		hdr->ret = ACK;
		hdr->msg = 0;
		u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = len;
		pt += sizeof(int);

		if (len > 0) {
			memcpy(pt, val, len);
			pt += len;
		}

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			PRINT_DEBUG("Exiting, No fdf: index=%d, uniqueSockID=%llu", index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exiting, fail send_wedge: index=%d, uniqueSockID=%llu", index, uniqueSockID);
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
		} else {
			PRINT_DEBUG("Exiting, normal: index=%d, uniqueSockID=%llu", index, uniqueSockID);
		}
		free(msg);
	} else {
		if (daemon_fcf_to_tcp(CTRL_READ_PARAM, params)) {
			struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
			thread_data->id = thread_count++;
			thread_data->uniqueSockID = uniqueSockID;
			thread_data->index = index;
			thread_data->call_id = call_id;
			thread_data->call_index = call_index;
			thread_data->flags = 0; //TODO implement

			pthread_t thread;
			if (pthread_create(&thread, NULL, getsockopt_tcp_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create getsockopt_tcp_thread thread.");
				nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
				free(thread_data);
				metadata_destroy(params);
			} else {
				pthread_detach(thread);
			}
		} else {
			PRINT_DEBUG("socketdaemon failed to accomplish accept");
			nack_send_new(uniqueSockID, index, call_id, call_index, getsockopt_call, 0);
			metadata_destroy(params);
		}
	}
}

void *setsockopt_tcp_thread(void *local) {
	struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) local;
	int id = thread_data->id;
	unsigned long long uniqueSockID = thread_data->uniqueSockID;
	int index = thread_data->index;
	u_int call_id = thread_data->call_id;
	int call_index = thread_data->call_index;
	int flags = thread_data->flags;
	free(thread_data);

	int non_blocking_flag = flags & 0; //TODO get from flags
	int ret;

	uint32_t param_id = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: uniqueSockID=%llu index=%d id=%u index=%d id=%d", uniqueSockID, index, call_id, call_index, id);
	struct finsFrame *ff = NULL;
	ret = get_fcf(index, uniqueSockID, &ff, non_blocking_flag);
	PRINT_DEBUG("after get_fcf: id=%d index=%d uniqueSockID=%llu ff=%p", id, index, uniqueSockID, ff);
	if (ret == 0) {
		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, EBADF); //TODO socket closed/invalid
		pthread_exit(NULL);
	}

	if (ff == NULL) {
		PRINT_DEBUG("Exiting, NULL fdf: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		if (non_blocking_flag) {
			nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, EAGAIN); //TODO or EWOULDBLOCK?
		} else {
			//TODO error case
			PRINT_DEBUG("todo error");
			nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		}
		pthread_exit(NULL);
	}

	if (ff->ctrlFrame.opcode != CTRL_READ_PARAM_REPLY || ff->ctrlFrame.metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: id=%d, index=%d, uniqueSockID=%llu opcode=%d, metaData=%d",
				id, index, uniqueSockID, ff->ctrlFrame.opcode, ff->ctrlFrame.metaData==NULL);
		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		freeFinsFrame(ff);
		pthread_exit(NULL);
	}

	ret = 0;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "param_id", &param_id) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->ctrlFrame.metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret /*|| (param_id != EXEC_TCP_CONNECT && param_id != EXEC_TCP_ACCEPT)*/|| ret_val == 0) {
		PRINT_DEBUG("Exiting, meta errors: id=%d, index=%d, uniqueSockID=%llu, ret=%d, param_id=%d, ret_val=%d",
				id, index, uniqueSockID, ret, param_id, ret_val);
		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
	} else {
		PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		ack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
	}

	freeFinsFrame(ff);
	pthread_exit(NULL);
}

void setsockopt_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval) {
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("index=%d, uniqueSockID=%llu, level=%d, optname=%d, optlen=%d", index, uniqueSockID, level, optname, optlen);
	sem_wait(&daemonSockets_sem);
	if (daemonSockets[index].uniqueSockID != uniqueSockID) {
		PRINT_DEBUG("Socket closed, canceling setsockopt_tcp.");
		sem_post(&daemonSockets_sem);

		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		return;
	}

	state = daemonSockets[index].state;
	host_ip = daemonSockets[index].host_ip;
	host_port = daemonSockets[index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemonSockets[index].dst_ip;
		rem_port = daemonSockets[index].dst_port;
	}

	PRINT_DEBUG("");
	sem_post(&daemonSockets_sem);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_DEBUG("metadata creation failed");

		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
		return;
	}
	metadata_create(params);

	int send_dst = -1;
	//uint32_t param_id = 0;
	//int len = 0;
	//uint8_t *val = NULL;

	metadata_writeToElement(params, "param", &optname, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (state > SS_UNCONNECTED) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	switch (optname) {
	case SO_DEBUG:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_DEBUG = *(int *) optval;

			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_DEBUG, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_REUSEADDR:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_REUSEADDR = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_REUSEADDR, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
	case SO_DONTROUTE:
	case SO_BROADCAST:
	case SO_SNDBUF:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_SNDBUF = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_SNDBUF, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_RCVBUF = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_RCVBUF, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_KEEPALIVE = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_KEEPALIVE, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_OOBINLINE:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_OOBINLINE = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_OOBINLINE, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_NO_CHECK:
	case SO_PRIORITY:
		if (optlen >= sizeof(int)) {
			daemonSockets[index].sockopts.FSO_PRIORITY = *(int *) optval;
			metadata_writeToElement(params, "value", &daemonSockets[index].sockopts.FSO_PRIORITY, META_TYPE_INT);
			send_dst = 1;
		}
		break;
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
		//TODO later
	case SO_PEERCRED:
		//TODO later
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
	case SO_MARK:
	case SO_RXQ_OVFL:
	case SO_ATTACH_FILTER:
	case SO_DETACH_FILTER:
		break;
	default:
		//nack?
		PRINT_DEBUG("default=%d", optname);
		break;
	}

	if (send_dst == -1) {
		PRINT_DEBUG("freeing meta=%p", params);
		metadata_destroy(params);
		nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
	} else if (send_dst == 0) {
		PRINT_DEBUG("freeing meta=%p", params);
		metadata_destroy(params);
		ack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
	} else {
		if (daemon_fcf_to_tcp(CTRL_READ_PARAM, params)) {
			struct daemon_tcp_thread_data *thread_data = (struct daemon_tcp_thread_data *) malloc(sizeof(struct daemon_tcp_thread_data));
			thread_data->id = thread_count++;
			thread_data->uniqueSockID = uniqueSockID;
			thread_data->index = index;
			thread_data->call_id = call_id;
			thread_data->call_index = call_index;
			thread_data->flags = 0; //TODO implement?

			pthread_t thread;
			if (pthread_create(&thread, NULL, setsockopt_tcp_thread, (void *) thread_data)) {
				PRINT_ERROR("ERROR: unable to create setsockopt_tcp_thread thread.");
				nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
				free(thread_data);
				metadata_destroy(params);
			} else {
				pthread_detach(thread);
			}
		} else {
			PRINT_DEBUG("socketdaemon failed to accomplish accept");
			nack_send_new(uniqueSockID, index, call_id, call_index, setsockopt_call, 0);
			metadata_destroy(params);
		}
	}

	/** check the opt_name to find which bit to access in the options variable then use
	 * the following code to handle the bits individually
	 * setting a bit   number |= 1 << x;  That will set bit x.
	 * Clearing a bit number &= ~(1 << x); That will clear bit x.
	 * The XOR operator (^) can be used to toggle a bit. number ^= 1 << x; That will toggle bit x.
	 * Checking a bit      value = number & (1 << x);
	 */
	//uint32_t socketoptions;
}
