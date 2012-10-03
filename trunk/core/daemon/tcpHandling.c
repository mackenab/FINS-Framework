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

extern sem_t daemon_sockets_sem;
extern struct daemon_socket daemon_sockets[MAX_SOCKETS];

sem_t daemon_calls_sem; //TODO remove?
struct daemon_call daemon_calls[MAX_CALLS];

extern int daemon_thread_count;
extern sem_t daemon_thread_sem;

int daemon_fdf_to_tcp(u_char *data, uint32_t data_len, metadata *params) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = TCP_ID;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		free(ff);
		return 0;
	}
}

int daemon_fcf_to_tcp(metadata *params, uint32_t serial_num, uint16_t opcode) {
	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	//TODO get the address from local copy of switch table
	ff->dataOrCtrl = CONTROL;
	ff->destinationID.id = TCP_ID;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->ctrlFrame.senderID = DAEMON_ID;
	ff->ctrlFrame.serialNum = serial_num;
	ff->ctrlFrame.opcode = opcode;

	PRINT_DEBUG("ff=%p, meta=%p", ff, params);
	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		free(ff);
		return 0;
	}
}

void socket_out_tcp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol) {
	int ret;

	PRINT_DEBUG("Entered: hdr=%p domain=%d type=%d proto=%d", hdr, domain, type, protocol);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	ret = daemon_sockets_insert(hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("sock_index=%d ret=%d", hdr->sock_index, ret);
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	if (ret) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void bind_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr) {

	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("Entered: hdr=%p", hdr);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family=%d", addr->sin_family);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	host_ip = ntohl(addr->sin_addr.s_addr);
	host_port = ntohs(addr->sin_port);

	PRINT_DEBUG("bind address: host=%u (%s):%d host_IP_netformat=%u", host_ip, inet_ntoa(addr->sin_addr), host_port, htonl(host_ip));

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	//TODO check if already bound, return already bound error

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!daemon_sockets_check_ports(host_port, host_ip) && !daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR) { //TODO change, need to check if in TIME_WAIT state
		PRINT_DEBUG("this port is not free");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		return;
	}

	/** TODO lock and unlock the protecting semaphores before making
	 * any modifications to the contents of the daemonSockets database
	 */

	if (host_ip == any_ip_addr) {
		daemon_sockets[hdr->sock_index].host_ip = my_host_ip_addr;
	} else {
		daemon_sockets[hdr->sock_index].host_ip = host_ip;
	}

	daemon_sockets[hdr->sock_index].host_port = host_port;
	PRINT_DEBUG("bind address: host=%u:%u (%u)", daemon_sockets[hdr->sock_index].host_ip, host_port, htonl(daemon_sockets[hdr->sock_index].host_ip));
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
	//daemonSockets[hdr->sock_index].host_IP.s_addr = ntohl(daemonSockets[hdr->sock_index].host_IP.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

	free(addr);
	return;

}

void listen_out_tcp(struct nl_wedge_to_daemon *hdr, int backlog) {
	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("Entered: hdr=%p backlog=%d", hdr, backlog);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	socket_state state = daemon_sockets[hdr->sock_index].state;
	daemon_sockets[hdr->sock_index].listening = 1;
	daemon_sockets[hdr->sock_index].backlog = backlog;

	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("listen address: host=%u/%d", host_ip, host_port);

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */
	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_LISTEN;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "backlog", &backlog, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);

	if (daemon_fcf_to_tcp(params, gen_control_serial_num(), CTRL_EXEC)) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_DEBUG("Exited: failed to send ff");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		metadata_destroy(params);
	}
}

void connect_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags) {
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p flags=%d", hdr, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, ( SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, EAFNOSUPPORT);
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

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket removed/changed");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, ENOTSOCK); //TODO check?
		free(addr);
		return;
	}
	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	socket_state state = daemon_sockets[hdr->sock_index].state;
	if (state == SS_CONNECTING) {
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, EALREADY);
			free(addr);
			return;
		} else {
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0); //TODO EADDRINUSE, check?
			free(addr);
			return;
		}
	} else if (state > SS_CONNECTING) {
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, EISCONN);
		free(addr);
		return;
	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */

//if statements make sure socket is in SS_UNCONNECTED
	daemon_sockets[hdr->sock_index].listening = 0;
	daemon_sockets[hdr->sock_index].dst_ip = rem_ip;
	daemon_sockets[hdr->sock_index].dst_port = rem_port;
	daemon_sockets[hdr->sock_index].state = SS_CONNECTING;

	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	if (daemon_sockets[hdr->sock_index].host_ip == any_ip_addr) { //TODO change this when have multiple interfaces
		daemon_sockets[hdr->sock_index].host_ip = my_host_ip_addr;
	}
	host_ip = daemon_sockets[hdr->sock_index].host_ip;

	/**
	 * Default current host port to be assigned is 58088
	 * It is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (host_port == 0) {
		PRINT_DEBUG("");
		while (1) {
			host_port = (uint16_t) randoming(MIN_port, MAX_port);
			if (daemon_sockets_check_ports(host_port, host_ip)) {
				break;
			}
		}
		PRINT_DEBUG("");
		daemon_sockets[hdr->sock_index].host_port = host_port;
	}

	/** Reverse again because it was reversed by the application itself
	 * In our example it is not reversed */
//daemonSockets[hdr->sock_index].host_ip.s_addr = ntohl(daemonSockets[hdr->sock_index].host_ip.s_addr);
	/** TODO convert back to the network endian form before
	 * sending to the fins core
	 */

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		exit(-1);
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_CONNECT;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
	metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);

	uint32_t serial_num = gen_control_serial_num();
	if (daemon_fcf_to_tcp(params, serial_num, CTRL_EXEC)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, &daemon_calls[hdr->call_index]);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_DEBUG("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Insert fail: hdr=%p", hdr);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		PRINT_DEBUG("Exited: failed to send ff");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		metadata_destroy(params);
	}

	free(addr);
}

void accept_out_tcp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags) {
	uint32_t host_ip;
	uint32_t host_port;
	int blocking_flag;

	PRINT_DEBUG("Entered: hdr=%p sock_id_new=%llu sock_index_new=%d flags=%d", hdr, sock_id_new, sock_index_new, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket removed/changed");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	if (!daemon_sockets[hdr->sock_index].listening) {
		PRINT_DEBUG("socket not listening");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = (uint32_t) daemon_sockets[hdr->sock_index].host_port;
	blocking_flag = daemon_sockets[hdr->sock_index].blockingFlag;

	socket_state state = daemon_sockets[hdr->sock_index].state;

	PRINT_DEBUG("accept address: host=%u/%d", host_ip, host_port);

	//TODO process flags?

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	uint32_t exec_call = EXEC_TCP_ACCEPT;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);

	uint32_t serial_num = gen_control_serial_num();
	if (daemon_fcf_to_tcp(params, serial_num, CTRL_EXEC)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;

			daemon_calls[hdr->call_index].sock_id_new = sock_id_new; //TODO redo so not in call? or in struct inside call as void *pt;
			daemon_calls[hdr->call_index].sock_index_new = sock_index_new;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, &daemon_calls[hdr->call_index]);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_DEBUG("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Insert fail: hdr=%p", hdr);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		PRINT_DEBUG("Exited: failed to send ff");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		metadata_destroy(params);
	}
}

void getname_out_tcp(struct nl_wedge_to_daemon *hdr, int peer) {
	int state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p peer=%d", hdr, peer);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	if (peer == 0) { //getsockname
		host_ip = daemon_sockets[hdr->sock_index].host_ip;
		host_port = daemon_sockets[hdr->sock_index].host_port;
	} else if (peer == 1) { //getpeername
		state = daemon_sockets[hdr->sock_index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
			rem_port = daemon_sockets[hdr->sock_index].dst_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
		state = daemon_sockets[hdr->sock_index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
			rem_port = daemon_sockets[hdr->sock_index].dst_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else {
		//TODO error
	}

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	struct sockaddr_in *addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
	if (addr == NULL) {
		PRINT_ERROR("addr creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
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
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = hdr->call_type;
	hdr_ret->call_id = hdr->call_id;
	hdr_ret->call_index = hdr->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0;
	u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = len;
	pt += sizeof(int);

	memcpy(pt, addr, len);
	pt += len;

	if (pt - msg != msg_len) {
		PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		free(addr);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
	}

	free(msg);
	free(addr);
}

void ioctl_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, u_char *buf, ssize_t buf_len) {
	uint32_t len;
	int msg_len;
	u_char *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	u_char *pt;

	PRINT_DEBUG("Entered: hdr=%p cmd=%d len=%d", hdr, cmd, buf_len);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	len = daemon_sockets[hdr->sock_index].buf_data;

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	switch (cmd) {
	case FIONREAD:
		PRINT_DEBUG("FIONREAD cmd=%d", cmd);
		//figure out buffered data

		//send msg to wedge
		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t);
		msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			exit(-1);
		}

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(uint32_t *) pt = len;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	default:
		PRINT_DEBUG("default cmd=%d", cmd);
		return;
	}

	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
		free(msg);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void sendmsg_out_tcp(struct nl_wedge_to_daemon *hdr, u_char *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *addr, int addr_len) {
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, flags=%d", hdr, data_len, flags);
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

	if (data_len == 0) {
		PRINT_DEBUG("data_len == 0, send ACK");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		if (addr)
			free(addr);
		return;
	}

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("CRASH !! socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		free(data);
		if (addr)
			free(addr);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	/** check if this socket already connected to a destined address or not */
	if (daemon_sockets[hdr->sock_index].state < SS_CONNECTING) {
		/** socket is not connected to an address. Send call will fail */

		PRINT_DEBUG("socketdaemon failed to accomplish send, socket found unconnected !!!");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		//TODO buffer data & send ACK

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		free(data);
		if (addr)
			free(addr);
		return;
	}

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	dst_port = daemon_sockets[hdr->sock_index].dst_port;

	dst_ip = daemon_sockets[hdr->sock_index].dst_ip;

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
	host_port = daemon_sockets[hdr->sock_index].host_port;
	/**
	 * the current value of host_IP is zero but to be filled later with
	 * the current IP using the IPv4 modules unless a binding has occured earlier
	 */
	host_ip = daemon_sockets[hdr->sock_index].host_ip;

	PRINT_DEBUG("host=%u/%d, dst=%u/%d", host_ip, host_port, dst_ip, dst_port);

	PRINT_DEBUG("");

	//int blocking_flag = 1; //TODO get from flags

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "src_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "src_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);
	metadata_writeToElement(params, "dst_port", &dst_port, META_TYPE_INT);

	uint32_t serial_num = gen_control_serial_num();
	metadata_writeToElement(params, "serial_num", &serial_num, META_TYPE_INT);

	if (daemon_fdf_to_tcp(data, data_len, params)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;
			daemon_calls[hdr->call_index].data = data_len;
			//thread_data->flags = flags;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, &daemon_calls[hdr->call_index]);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_DEBUG("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Insert fail: hdr=%p", hdr);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		PRINT_DEBUG("Exited: failed to send ff");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		metadata_destroy(params);
		free(data);
	}

	if (addr)
		free(addr);
}

/**
 * @function recvfrom_udp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvmsg_out_tcp(struct nl_wedge_to_daemon *hdr, int data_len, int flags, uint32_t msg_flags) {
	PRINT_DEBUG("Entered: hdr=%p data_len=%d flags=%d msg_flags=%d", hdr, data_len, flags, msg_flags);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, (SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);
	PRINT_DEBUG( "MSG_CMSG_CLOEXEC=%d, MSG_DONTWAIT=%d, MSG_ERRQUEUE=%d, MSG_OOB=%d, MSG_PEEK=%d, MSG_TRUNC=%d, MSG_WAITALL=%d",
			(MSG_CMSG_CLOEXEC & flags)>0, (MSG_DONTWAIT & flags)>0, (MSG_ERRQUEUE & flags)>0, (MSG_OOB & flags)>0, (MSG_PEEK & flags)>0, (MSG_TRUNC & flags)>0, (MSG_WAITALL & flags)>0);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & msg_flags)>0, (SOCK_CLOEXEC & msg_flags)>0, (O_NONBLOCK & msg_flags)>0, (O_ASYNC & msg_flags)>0);
	PRINT_DEBUG( "MSG_EOR=%d, MSG_TRUNC=%d, MSG_CTRUNC=%d, MSG_OOB=%d, MSG_ERRQUEUE=%d",
			(MSG_EOR & msg_flags)>0, (MSG_TRUNC & msg_flags)>0, (MSG_CTRUNC & msg_flags)>0, (MSG_OOB & msg_flags)>0, (MSG_ERRQUEUE & msg_flags)>0);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("Socket closed, canceling read block.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	if (daemon_sockets[hdr->sock_index].buf_data > 0) {
		struct finsFrame *ff = read_queue(daemon_sockets[hdr->sock_index].dataQueue);
		if (ff == NULL) { //TODO shoulnd't happen
			PRINT_DEBUG("todo error");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		daemon_sockets[hdr->sock_index].buf_data -= ff->dataFrame.pduLength;

		socket_state state = daemon_sockets[hdr->sock_index].state;
		uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
		uint16_t host_port = daemon_sockets[hdr->sock_index].host_port;
		uint32_t rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
		uint16_t rem_port = daemon_sockets[hdr->sock_index].dst_port;

		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		struct sockaddr_in addr;
		addr.sin_addr.s_addr = htonl(rem_ip);
		addr.sin_port = htons((uint16_t) rem_port);
		/*
		 uint32_t src_ip;
		 if (metadata_readFromElement(ff->metaData, "src_ip", &src_ip) == CONFIG_FALSE) {
		 addr.sin_addr.s_addr = 0;
		 } else {
		 addr.sin_addr.s_addr = htonl(src_ip);
		 }

		 uint32_t src_port;
		 if (metadata_readFromElement(ff->metaData, "src_port", &src_port) == CONFIG_FALSE) {
		 addr.sin_port = 0;
		 } else {
		 addr.sin_port = htons((uint16_t) src_port);
		 }*/

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
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
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
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

			free(msg);
			free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		} else {
			//TODO send size back to TCP handlers
			//if (state > SS_UNCONNECTED) { //shouldn't be able to get data if not connected
			PRINT_DEBUG("recvfrom address: host=%u/%d rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
			//} else {
			//	PRINT_DEBUG("recvfrom address: host=%u/%d", host_ip, host_port);
			//}

			metadata *params = (metadata *) malloc(sizeof(metadata));
			if (params == NULL) {
				PRINT_ERROR("metadata creation failed");

				freeFinsFrame(ff);
				exit(-1);
			}
			metadata_create(params);

			uint32_t param_id = SET_PARAM_TCP_HOST_WINDOW;
			metadata_writeToElement(params, "param_id", &param_id, META_TYPE_INT);
			uint32_t value = ff->dataFrame.pduLength;
			metadata_writeToElement(params, "value", &value, META_TYPE_INT);

			metadata_writeToElement(params, "state", &state, META_TYPE_INT);
			metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
			metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
			//if (state > SS_UNCONNECTED) {
			metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
			metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
			//}

			if (daemon_fcf_to_tcp(params, gen_control_serial_num(), CTRL_SET_PARAM)) {
				PRINT_DEBUG("Exited, normal: hdr=%p", hdr);
			} else {
				PRINT_DEBUG("Exited, fail sending flow msgs: hdr=%p", hdr);
				metadata_destroy(params);
			}
		}

		free(msg);
		free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
	} else {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].flags = flags;
			daemon_calls[hdr->call_index].data = data_len;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, &daemon_calls[hdr->call_index]);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				//TODO if nonblocking start timer
			} else {
				PRINT_DEBUG("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Insert fail: hdr=%p", hdr);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	}
}

void release_out_tcp(struct nl_wedge_to_daemon *hdr) { //TODO finish
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("hdr=%p", hdr);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("Socket closed, canceling release_tcp.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
		rem_port = daemon_sockets[hdr->sock_index].dst_port;
	}

	//TODO process flags?

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("release address: host=%u/%d rem=%u/%d", host_ip, host_port, rem_ip, rem_port);
	} else {
		PRINT_DEBUG("release address: host=%u/%d", host_ip, host_port);
	}

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	uint32_t exec_call = (state > SS_UNCONNECTED) ? EXEC_TCP_CLOSE : EXEC_TCP_CLOSE_STUB;
	metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
	//metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "state", &state, META_TYPE_INT);
	metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
	if (state > SS_UNCONNECTED) {
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
	}

	uint32_t serial_num = gen_control_serial_num();
	if (daemon_fcf_to_tcp(params, serial_num, CTRL_EXEC)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, &daemon_calls[hdr->call_index]);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_DEBUG("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Insert fail: hdr=%p", hdr);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		PRINT_DEBUG("Exited: failed to send ff");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		metadata_destroy(params);
	}
}

void poll_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t events) {
	uint32_t mask = 0;

	PRINT_DEBUG("Entered: hdr=%p events=%x", hdr, events);

	PRINT_DEBUG("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x",
			(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

	if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_DEBUG("Socket closed, canceling poll_udp.");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		if (daemon_sockets[hdr->sock_index].buf_data > 0) {
			mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
		}

		PRINT_DEBUG("");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);
	}

	if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
		//mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
		//TODO contact TCP for
	}

	if (mask & events) { //If were immediate events reply; otherwise, block
		int ret_val;
		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(uint32_t *) pt = mask;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
		free(msg);
		if (ret_val) {
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		//TODO redo this, for POLLERR & POLLHUP, atm is kinda wonky
		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			if (sem_wait(&daemon_sockets_sem)) {
				PRINT_ERROR("daemon_sockets_sem wait prob");
				exit(-1);
			}
			if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
				PRINT_DEBUG("Socket closed, canceling poll_tcp.");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				return;
			}

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].data = events;

				struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
				if (call_list_has_space(call_list)) {
					call_list_append(call_list, &daemon_calls[hdr->call_index]);

					PRINT_DEBUG("");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);
				} else {
					PRINT_DEBUG("call_list full");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				}
			} else {
				PRINT_DEBUG("Insert fail: hdr=%p", hdr);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			socket_state state;
			uint32_t host_ip;
			uint16_t host_port;
			uint32_t rem_ip;
			uint16_t rem_port;

			/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			if (sem_wait(&daemon_sockets_sem)) {
				PRINT_ERROR("daemon_sockets_sem wait prob");
				exit(-1);
			}
			if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
				PRINT_DEBUG("Socket closed, canceling poll_tcp.");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				return;
			}

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

			state = daemon_sockets[hdr->sock_index].state;
			host_ip = daemon_sockets[hdr->sock_index].host_ip;
			host_port = daemon_sockets[hdr->sock_index].host_port;
			if (state > SS_UNCONNECTED) {
				rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
				rem_port = daemon_sockets[hdr->sock_index].dst_port;
			}

			PRINT_DEBUG("");
			///*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");sem_post(&daemon_sockets_sem);

			if (state > SS_UNCONNECTED) {
				PRINT_DEBUG("poll address: host=%u/%u rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
			} else {
				PRINT_DEBUG("poll address: host=%u/%u", host_ip, host_port);
			}

			metadata *params = (metadata *) malloc(sizeof(metadata));
			if (params == NULL) {
				PRINT_ERROR("metadata creation failed");
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				exit(-1);
			}
			metadata_create(params);

			uint32_t exec_call = EXEC_TCP_POLL;
			metadata_writeToElement(params, "exec_call", &exec_call, META_TYPE_INT);
			metadata_writeToElement(params, "flags", &events, META_TYPE_INT);

			metadata_writeToElement(params, "state", &state, META_TYPE_INT);
			metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
			metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
			if (state > SS_UNCONNECTED) {
				metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
				metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);
			}

			uint32_t serial_num = gen_control_serial_num();
			if (daemon_fcf_to_tcp(params, serial_num, CTRL_EXEC)) {
				if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
					daemon_calls[hdr->call_index].serial_num = serial_num;
					daemon_calls[hdr->call_index].data = events;

					struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
					if (call_list_has_space(call_list)) {
						call_list_append(call_list, &daemon_calls[hdr->call_index]);

						PRINT_DEBUG("");
						/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
						sem_post(&daemon_sockets_sem);
					} else {
						PRINT_DEBUG("call_list full");
						/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
						sem_post(&daemon_sockets_sem);

						nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
					}
				} else {
					PRINT_DEBUG("Insert fail: hdr=%p", hdr);
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				}
			} else {
				PRINT_DEBUG("Exited: failed to send ff");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				metadata_destroy(params);
			}
		} else {
			PRINT_DEBUG("Unhandled events? events=%x", events);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	}
}

void shutdown_out_tcp(struct nl_wedge_to_daemon *hdr, int how) {

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	//index = find_daemonSocket(uniqueSockID);
	//if (index == -1) {
	//	PRINT_ERROR("socket descriptor not found into daemon sockets");
	//	exit(-1);
	//}
	PRINT_DEBUG("Entered: hdr=%p how=%d", hdr, how);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void getsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {
	uint32_t host_ip;
	uint16_t host_port;
	socket_state state;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("Socket closed, canceling getsockopt_tcp.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
		rem_port = daemon_sockets[hdr->sock_index].dst_port;
	}

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	int send_dst = -1;
	//uint32_t param_id = 0;
	int len = 0;
	uint8_t *val = NULL;

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
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_REUSEADDR:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR; //TODO move into sem's
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
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_OOBINLINE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_OOBINLINE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_NO_CHECK:
	case SO_PRIORITY:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_PRIORITY; //TODO move into sem's
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
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_PASSCRED; //TODO move into sem's
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
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (send_dst == 0) {
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
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
			PRINT_DEBUG("Exited:, No fdf: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		} else {
			PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
		}
		free(msg);
	} else {
		uint32_t serial_num = gen_control_serial_num();
		if (daemon_fcf_to_tcp(params, serial_num, CTRL_READ_PARAM)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].serial_num = serial_num;
				daemon_calls[hdr->call_index].data = optname;

				struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
				if (call_list_has_space(call_list)) {
					call_list_append(call_list, &daemon_calls[hdr->call_index]);

					PRINT_DEBUG("");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);
				} else {
					PRINT_DEBUG("call_list full");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				}
			} else {
				PRINT_DEBUG("Insert fail: hdr=%p", hdr);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Exited: failed to send ff");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			metadata_destroy(params);
		}
	}
}

void setsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {
	socket_state state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("Socket closed, canceling setsockopt_tcp.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].dst_ip;
		rem_port = daemon_sockets[hdr->sock_index].dst_port;
	}

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
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
			daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG = *(int *) optval;

			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_REUSEADDR:
		if (optlen >= sizeof(int)) {
			daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR, META_TYPE_INT);
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
			daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_SNDBUFFORCE:
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_RCVBUFFORCE:
	case SO_KEEPALIVE:
		if (optlen >= sizeof(int)) {
			daemon_sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_OOBINLINE:
		if (optlen >= sizeof(int)) {
			daemon_sockets[hdr->sock_index].sockopts.FSO_OOBINLINE = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_OOBINLINE, META_TYPE_INT);
			send_dst = 1;
		}
		break;
	case SO_NO_CHECK:
	case SO_PRIORITY:
		if (optlen >= sizeof(int)) {
			daemon_sockets[hdr->sock_index].sockopts.FSO_PRIORITY = *(int *) optval;
			metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_PRIORITY, META_TYPE_INT);
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
		PRINT_DEBUG("Error");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (send_dst == 0) {
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		uint32_t serial_num = gen_control_serial_num();
		if (daemon_fcf_to_tcp(params, serial_num, CTRL_SET_PARAM)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].serial_num = serial_num;

				struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
				if (call_list_has_space(call_list)) {
					call_list_append(call_list, &daemon_calls[hdr->call_index]);

					PRINT_DEBUG("");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);
				} else {
					PRINT_DEBUG("call_list full");
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				}
			} else {
				PRINT_DEBUG("Insert fail: hdr=%p", hdr);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		} else {
			PRINT_DEBUG("Exited: failed to send ff");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
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

void connect_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags) {
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, flags);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_CONNECT && exec_call != EXEC_TCP_ACCEPT)) {
		PRINT_DEBUG("Exiting, meta errors: ff=%p, ret=%d, exec_call=%d, ret_val=%d", ff, ret, exec_call, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {
		PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
			PRINT_DEBUG("Exited, socket closed: ff=%p", ff);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(call_id, call_index, call_type, 0);
			freeFinsFrame(ff);
			return;
		}

		if (ret_val) {
			daemon_sockets[sock_index].state = SS_CONNECTED;

			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			ack_send(call_id, call_index, call_type, 0);
		} else {
			daemon_sockets[sock_index].state = SS_UNCONNECTED;

			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(call_id, call_index, call_type, ECONNREFUSED); //TODO change based off of timeout, refused etc
		}

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].dst_ip, daemon_sockets[sock_index].dst_port);

	}

	freeFinsFrame(ff);
}

void accept_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint64_t sock_id_new,
		int sock_index_new, uint32_t flags) {
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	uint32_t rem_ip = 0;
	uint16_t rem_port = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, sock_id_new=%llu, sock_index_new=%d flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, sock_id_new, sock_index_new, flags);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "rem_port", &rem_port) == CONFIG_FALSE;

	if (ret || exec_call != EXEC_TCP_ACCEPT || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: ff=%p, ret=%d, exec_call=%d, ret_val=%d", ff, ret, exec_call, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {
		PRINT_DEBUG("");
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[sock_index].sock_id != sock_id) {
			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("Exited: socket closed: ff=%p", ff);
			nack_send(call_id, call_index, call_type, 0);
		} else {
			ret = daemon_sockets_insert(sock_id_new, sock_index_new, daemon_sockets[sock_index].type, daemon_sockets[sock_index].protocol);
			if (ret) {
				daemon_sockets[sock_index_new].host_ip = daemon_sockets[sock_index].host_ip;
				daemon_sockets[sock_index_new].host_port = daemon_sockets[sock_index].host_port;
				daemon_sockets[sock_index_new].dst_ip = rem_ip;
				daemon_sockets[sock_index_new].dst_port = rem_port;
				daemon_sockets[sock_index_new].state = SS_CONNECTED;
				PRINT_DEBUG("Accept socket created: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
						daemon_sockets[sock_index_new].sock_id, sock_index_new, daemon_sockets[sock_index_new].state, daemon_sockets[sock_index_new].host_ip, daemon_sockets[sock_index_new].host_port, daemon_sockets[sock_index_new].dst_ip, daemon_sockets[sock_index_new].dst_port);

				daemon_sockets[sock_index].state = SS_UNCONNECTED;

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
						daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].dst_ip, daemon_sockets[sock_index].dst_port);

				PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
				ack_send(call_id, call_index, call_type, 0);
			} else {
				PRINT_DEBUG("Exited: insert failed: ff=%p", ff);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(call_id, call_index, call_type, 0);
			}
		}
	}

	freeFinsFrame(ff);
}

void sendmsg_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags) { //TODO remove data? not needed
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	uint32_t ret_msg = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, flags);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg) == CONFIG_FALSE;

	if (ret || exec_call != EXEC_TCP_SEND || ret_val == 0) {
		nack_send(call_id, call_index, call_type, 1);
	} else {
		ack_send(call_id, call_index, call_type, ret_msg);
	}

	freeFinsFrame(ff);
}

void getsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data) {
	uint32_t param_id = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, data);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "param_id", &param_id) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (int) param_id != (int) data || ret_val == 0) { //TODO remove (int)'s?
		PRINT_DEBUG("Exiting, meta errors: ff=%p, ret=%d, exec_call=%d, ret_val=%d", ff, ret, param_id, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {

		//################ //TODO switch by param_id, convert into val/len
		int len = 0;
		uint8_t *val = NULL;
		//################

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(call_id, call_index, call_type, 0);
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = call_type;
		hdr_ret->call_id = call_id;
		hdr_ret->call_index = call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
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

			nack_send(call_id, call_index, call_type, 0);
			freeFinsFrame(ff);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_DEBUG("Exited: fail send_wedge: ff=%p", ff);
			nack_send(call_id, call_index, call_type, 0);
		} else {
			PRINT_DEBUG("Exited: normal: ff=%p", ff);
		}
		free(msg);
	}

	freeFinsFrame(ff);
}

void setsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data) {
	uint32_t param_id = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, data);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "param_id", &param_id) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (int) param_id != (int) data || ret_val == 0) { //TODO remove (int)'s?
		PRINT_DEBUG("Exited: meta errors: ff=%p, ret=%d, param_id=%d, ret_val=%d", ff, ret, param_id, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {
		PRINT_DEBUG("Exited: normal: ff=%p", ff);
		ack_send(call_id, call_index, call_type, 0);
	}

	freeFinsFrame(ff);
}

void release_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index) {
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			ff, call_id, call_index, call_type, sock_id, sock_index);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_CLOSE && exec_call != EXEC_TCP_CLOSE_STUB) || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: ff=%p, ret=%d, exec_call=%d, ret_val=%d", ff, ret, exec_call, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {
		PRINT_DEBUG("");
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[sock_index].sock_id != sock_id) {
			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("Exited: socket closed: ff=%p", ff);
			nack_send(call_id, call_index, call_type, 0);
		} else {
			daemon_sockets_remove(sock_index);
			PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			ack_send(call_id, call_index, call_type, 0);
		}
	}

	freeFinsFrame(ff);
}

void poll_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data) {
	uint32_t exec_call = 0;
	uint32_t ret_val = 0;
	uint32_t ret_msg = 0;

	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, data);

	if (ff->metaData == NULL) {
		PRINT_DEBUG("Exiting, fcf errors: ff=%p, metaData=%d", ff, ff->metaData==NULL);
		nack_send(call_id, call_index, call_type, 0);
		freeFinsFrame(ff);
		return;
	}

	int ret = 0;
	ret += metadata_readFromElement(ff->metaData, "exec_call", &exec_call) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_val", &ret_val) == CONFIG_FALSE;
	ret += metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg) == CONFIG_FALSE;
	//ret += metadata_readFromElement(ff->metaData, "mask", &mask) == CONFIG_FALSE;

	if (ret || (exec_call != EXEC_TCP_POLL) || ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: ff=%p, ret=%d, exec_call=%d, ret_val=%d", ff, ret, exec_call, ret_val);
		nack_send(call_id, call_index, call_type, 0);
	} else {
		PRINT_DEBUG("");
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[sock_index].sock_id != sock_id) {
			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("Exited: socket closed: ff=%p", ff);
			nack_send(call_id, call_index, call_type, 0);
		} else {
			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			//send msg to wedge
			int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t);
			u_char *msg = (u_char *) malloc(msg_len);
			if (msg == NULL) {
				PRINT_ERROR("ERROR: buf alloc fail");
				nack_send(call_id, call_index, call_type, 0);
				exit(-1);
			}

			struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
			hdr_ret->call_type = call_type;
			hdr_ret->call_id = call_id;
			hdr_ret->call_index = call_index;
			hdr_ret->ret = ACK;
			hdr_ret->msg = 0;
			u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

			*(uint32_t *) pt = ret_msg;
			pt += sizeof(uint32_t);

			if (pt - msg != msg_len) {
				PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
				free(msg);
				nack_send(call_id, call_index, call_type, 0);
				return;
			}

			PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_DEBUG("Exited: fail send_wedge: ff=%p", ff);
				nack_send(call_id, call_index, call_type, 0);
			} else {
				PRINT_DEBUG("Exited: normal: ff=%p", ff);
			}
			free(msg);
		}
	}

	freeFinsFrame(ff);
}

void poll_tcp_in(struct daemon_call_list *call_list, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p", call_list, call);

	uint32_t events = call->data;

	PRINT_DEBUG("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x",
			(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

	if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		uint32_t mask = POLLIN | POLLRDNORM; //TODO POLLPRI?

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			nack_send(call->call_id, call->call_index, call->call_type, 0);
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = call->call_type;
		hdr_ret->call_id = call->call_id;
		hdr_ret->call_index = call->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(uint32_t *) pt = mask;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_DEBUG("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			nack_send(call->call_id, call->call_index, call->call_type, 0);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg='%s'", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			nack_send(call->call_id, call->call_index, call->call_type, 0);
		}
		free(msg);

		//TODO remove poll call
		call_list_remove(call_list, call);
		//call_free(call);
		daemon_calls_remove(call->call_index);
	}
}

void recvmsg_in_tcp(struct daemon_call_list *call_list, struct daemon_call *call, struct finsFrame *ff, uint32_t src_ip, uint16_t src_port) {
	PRINT_DEBUG("Entered: ff=%p, call=%p, call_id=%u, src=%u/%u", ff, call, call->call_id, src_ip, src_port);

	uint32_t data_len = call->data;

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = htonl(src_ip);
	addr.sin_port = htons(src_port);

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
		exit(-1);
	}

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = call->call_type;
	hdr_ret->call_id = call->call_id;
	hdr_ret->call_index = call->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0;
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
		PRINT_DEBUG("Exited: write error: ff=%p, call=%p", ff, call);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
		free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("Exited: send_wedge error: ff=%p, call=%p", ff, call);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	} else {

		daemon_sockets[call->sock_index].buf_data -= ff->dataFrame.pduLength;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].dst_ip, daemon_sockets[call->sock_index].dst_port);

		socket_state state = daemon_sockets[call->sock_index].state;
		uint32_t host_ip = daemon_sockets[call->sock_index].host_ip;
		uint16_t host_port = daemon_sockets[call->sock_index].host_port;
		uint32_t rem_ip = daemon_sockets[call->sock_index].dst_ip;
		uint16_t rem_port = daemon_sockets[call->sock_index].dst_port;

		PRINT_DEBUG("recvfrom address: state=%u, host=%u/%u, rem=%u/%u,", state, host_ip, host_port, rem_ip, rem_port);

		metadata *params = (metadata *) malloc(sizeof(metadata));
		if (params == NULL) {
			PRINT_ERROR("metadata creation failed");
			freeFinsFrame(ff);
			exit(-1);
		}
		metadata_create(params);

		uint32_t param_id = SET_PARAM_TCP_HOST_WINDOW;
		metadata_writeToElement(params, "param_id", &param_id, META_TYPE_INT);
		uint32_t value = ff->dataFrame.pduLength;
		metadata_writeToElement(params, "value", &value, META_TYPE_INT);

		metadata_writeToElement(params, "state", &state, META_TYPE_INT);
		metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT);
		metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT);
		metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT);
		metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT);

		if (daemon_fcf_to_tcp(params, gen_control_serial_num(), CTRL_SET_PARAM)) {
			PRINT_DEBUG("Exited, normal: call=%p", call);
		} else {
			PRINT_DEBUG("Exited, fail sending flow msgs: call=%p", call);
			metadata_destroy(params);
		}
	}

	call_list_remove(call_list, call);
	//call_free(call);
	daemon_calls_remove(call->call_index);

	free(msg);
	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
}

void daemon_tcp_in_fdf(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t dst_ip, uint16_t dst_port) {
	PRINT_DEBUG("Entered: ff=%p host:%u/%u, dst=%u/%u", ff, host_ip, host_port, dst_ip, dst_port);

	/**
	 * check if this received datagram destIP and destport matching which socket hostIP
	 * and hostport insidee our sockets database
	 */
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	//int sock_index = daemon_sockets_match(dst_port, dst_ip, IPPROTO_UDP); //TODO change for multicast

	int sock_index = daemon_sockets_match_connection(host_ip, host_port, dst_ip, dst_port, IPPROTO_TCP);
	if (sock_index == -1) {
		sock_index = daemon_sockets_match_connection(host_ip, host_port, 0, 0, IPPROTO_TCP);
	}

	if (sock_index == -1) {
		PRINT_DEBUG("No match, freeing ff");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		if (ff->dataFrame.pdu)
			free(ff->dataFrame.pdu);
		freeFinsFrame(ff);
	} else {
		//uint64_t uniqueSockID = daemonSockets[hdr->sock_index].uniqueSockID;

		PRINT_DEBUG( "Matched: uniqueSockID=%llu index=%d, host=%u/%u, dst=%u/%u, prot=%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].dst_ip, daemon_sockets[sock_index].dst_port, daemon_sockets[sock_index].protocol);

		struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

		struct daemon_call *call = call_list->front;
		while (call) {
			if (call->call_type == poll_call) { //handle poll_udp_out call
				poll_tcp_in(call_list, call);
				break;
			}
			call = call->next;
		}

		call = call_list->front;
		while (call) {
			if (call->call_type == recvmsg_call) {
				recvmsg_in_tcp(call_list, call, ff, host_ip, host_port);

				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
				return;
			}
			call = call->next;
		}

		if (write_queue(ff, daemon_sockets[sock_index].dataQueue)) {
			daemon_sockets[sock_index].buf_data += ff->dataFrame.pduLength;

			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);
		} else {
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("Write queue error: ff=%p", ff);
			if (ff->dataFrame.pdu)
				free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}
	}
}
