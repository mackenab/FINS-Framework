/**
 * @file icmpHandling.c
 *
 *  @date Nov 28, 2010
 *   @author Jonathan Reed
 */

#include "icmpHandling.h"
#include <finstypes.h>

extern sem_t daemon_sockets_sem;
extern struct daemon_socket daemon_sockets[MAX_SOCKETS];

extern sem_t daemon_calls_sem; //TODO remove?
extern struct daemon_call daemon_calls[MAX_CALLS];

extern int daemon_thread_count; //for TO threads
extern sem_t daemon_thread_sem;

int daemon_fdf_to_icmp(u_char *data, uint32_t data_len, metadata *params) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_ERROR("ff creation failed");
		return 0;
	}

	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = ICMP_ID;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	/*#*/PRINT_DEBUG("");
	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		PRINT_ERROR("freeing: ff=%p", ff);
		free(ff);
		return 0;
	}
}

/**
 * End of interfacing socketdaemon with FINS core
 * */
void socket_out_icmp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol) {
	int ret;

	PRINT_DEBUG("Entered: hdr=%p, domain=%d, type=%d, proto=%d", hdr, domain, type, protocol);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	ret = daemon_sockets_insert(hdr->sock_id, hdr->sock_index, type, protocol); //TODO add &icmp_ops
	PRINT_DEBUG("sock_index=%d ret=%d", hdr->sock_index, ret);
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	if (ret) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void bind_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr) {

	uint16_t host_port;
	uint32_t host_ip;

	PRINT_DEBUG("Entered: hdr=%p", hdr);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family=%d", addr->sin_family);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
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

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!daemon_sockets_check_ports(host_port, host_ip) && !daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR) {
		PRINT_ERROR("this port is not free");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		free(addr);
		return;
	}

	/**
	 * Binding
	 */
	daemon_sockets[hdr->sock_index].host_port = host_port;

	if (host_ip == any_ip_addr) { //TODO change this when have multiple interfaces
		daemon_sockets[hdr->sock_index].host_ip = my_host_ip_addr;
	} else {
		daemon_sockets[hdr->sock_index].host_ip = host_ip;
	}

	PRINT_DEBUG("bind: index:%d, host:%u/%u, dst:%u/%u",
			hdr->sock_index, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);
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
} // end of bind_icmp

void listen_out_icmp(struct nl_wedge_to_daemon *hdr, int backlog) {
	PRINT_DEBUG("Entered: hdr=%p, backlog=%d", hdr, backlog);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	daemon_sockets[hdr->sock_index].listening = 1;
	daemon_sockets[hdr->sock_index].backlog = backlog;
	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void connect_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags) {

	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, flags=%d", hdr, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
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
	 * once over the same ICMP socket changing the address from one to another. SO the assigning
	 * will take place even if the check functions returns (-1) !!!
	 * */

	/** TODO connect for ICMP means that this address will be the default address to send
	 * to. BUT IT WILL BE ALSO THE ONLY ADDRESS TO RECEIVER FROM
	 *	NOTICE THAT the relation
	 * */

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (daemon_sockets[hdr->sock_index].state > SS_UNCONNECTED) {
		PRINT_DEBUG("old destined address %d, %d", daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);
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
	daemon_sockets[hdr->sock_index].dst_ip = dst_ip;
	daemon_sockets[hdr->sock_index].dst_port = dst_port;
	daemon_sockets[hdr->sock_index].state = SS_CONNECTING;

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

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

void accept_out_icmp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags) {

	PRINT_DEBUG("Entered: hdr=%p, sock_id_new=%llu, index_new=%d, flags=%d", hdr, sock_id_new, sock_index_new, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	//TODO: finish this
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void getname_out_icmp(struct nl_wedge_to_daemon *hdr, int peer) {
	int state;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p, peer=%d", hdr, peer);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
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
		PRINT_ERROR("todo error");
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
		PRINT_ERROR("todo error");
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
		PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
	}

	free(msg);
}

void ioctl_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, u_char *buf, ssize_t buf_len) {
	uint32_t len;
	//u_char *val;
	int msg_len;
	u_char *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	u_char *pt;

	PRINT_DEBUG("Entered: hdr=%p, cmd=%d, len=%d", hdr, cmd, buf_len);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

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

		*(uint32_t *) pt = daemon_sockets[hdr->sock_index].data_buf;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);

			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	case SIOCGSTAMP:
		PRINT_DEBUG("SIOCGSTAMP cmd=%d", cmd);

		len = sizeof(struct timeval);
		//val = &daemon_sockets[hdr->sock_index].latest;

		//send msg to wedge
		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t) + len;
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

		PRINT_DEBUG("stamp=%u.%u", (uint32_t)daemon_sockets[hdr->sock_index].stamp.tv_sec, (uint32_t) daemon_sockets[hdr->sock_index].stamp.tv_usec);

		memcpy(pt, &daemon_sockets[hdr->sock_index].stamp, len);
		pt += len;

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);

			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}
		break;
	default:
		PRINT_ERROR("default cmd=%d", cmd);
		break;
	}
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
		free(msg);
	} else {
		//nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0); //TODO uncomment
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void sendmsg_out_icmp(struct nl_wedge_to_daemon *hdr, u_char *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *addr, int addr_len) {

	uint32_t host_ip = 0;
	uint16_t host_port = 0;
	uint32_t dst_ip = 0;
	uint16_t dst_port = 0;

	struct in_addr *temp;

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

	if (addr_len) {
		if (addr->sin_family != AF_INET) {
			PRINT_ERROR("Wrong address family, send NACK");
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

			free(data);
			if (addr)
				free(addr);
			return;
		}

		dst_ip = ntohl(addr->sin_addr.s_addr);/** it is in network format since application used htonl */
		/** addresses are in host format given that there are by default already filled
		 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */

		/** Keep all ports and addresses in host order until later  action taken */
		dst_port = ntohs(addr->sin_port); /** reverse it since it is in network order after application used htons */
	}

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("CRASH !! socket descriptor not found into daemon sockets");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		free(data);
		if (addr)
			free(addr);
		return;
	}

	if (addr_len == 0) {
		dst_ip = daemon_sockets[hdr->sock_index].dst_ip;
		dst_port = daemon_sockets[hdr->sock_index].dst_ip;
	}

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
	/*
	 if (host_port == 0) {
	 while (1) {
	 host_port = randoming(MIN_port, MAX_port);
	 if (daemon_sockets_check_ports(host_port, host_ip)) {
	 break;
	 }
	 }
	 daemon_sockets[hdr->sock_index].host_port = host_port;
	 }*/

	/*//TODO uncomment? find out if connect rem addr sent through sendmsg
	 if (daemonSockets[hdr->sock_index].state > SS_UNCONNECTED) {
	 dst_port = daemonSockets[hdr->sock_index].dst_port;
	 dst_ip = daemonSockets[hdr->sock_index].dst_ip;
	 }*/

	uint32_t ttl = daemon_sockets[hdr->sock_index].sockopts.FIP_TTL;
	uint32_t tos = daemon_sockets[hdr->sock_index].sockopts.FIP_TOS;

	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	//PRINT_DEBUG("index=%d, dst=%u/%d, host=%u/%d", hdr->sock_index, dst_ip, dst_port, host_ip, host_port);

	//########################
	temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = htonl(host_ip);
	PRINT_DEBUG("index=%d, host=%s/%u (%u)", hdr->sock_index, inet_ntoa(*temp), host_port, host_ip);
	temp->s_addr = htonl(dst_ip);
	PRINT_DEBUG("index=%d, dst=%s/%u (%u)", hdr->sock_index, inet_ntoa(*temp), dst_port, dst_ip);
	free(temp);
	//########################

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	//metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "src_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);

	metadata_writeToElement(params, "ttl", &ttl, META_TYPE_INT);
	metadata_writeToElement(params, "tos", &tos, META_TYPE_INT);

	if (daemon_fdf_to_icmp(data, data_len, params)) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_ERROR("socketdaemon failed to accomplish sendto");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		metadata_destroy(params);
		free(data);
	}

	if (addr)
		free(addr);
}

/**
 * @function recvfrom_icmp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since ICMPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvmsg_out_icmp(struct nl_wedge_to_daemon *hdr, int data_len, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, flags=%d", hdr, data_len, flags);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, (SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);
	PRINT_DEBUG( "MSG_CMSG_CLOEXEC=%d, MSG_DONTWAIT=%d, MSG_ERRQUEUE=%d, MSG_OOB=%d, MSG_PEEK=%d, MSG_TRUNC=%d, MSG_WAITALL=%d",
			(MSG_CMSG_CLOEXEC & flags)>0, (MSG_DONTWAIT & flags)>0, (MSG_ERRQUEUE & flags)>0, (MSG_OOB & flags)>0, (MSG_PEEK & flags)>0, (MSG_TRUNC & flags)>0, (MSG_WAITALL & flags)>0);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].dst_ip, daemon_sockets[hdr->sock_index].dst_port);

	if (flags & MSG_ERRQUEUE) {
		if (daemon_sockets[hdr->sock_index].error_buf > 0) {
			struct finsFrame *ff = read_queue(daemon_sockets[hdr->sock_index].error_queue);
			if (ff == NULL) { //TODO shoulnd't happen
				PRINT_ERROR("todo error");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				return;
			}

			daemon_sockets[hdr->sock_index].error_buf--;

			metadata *params = ff->metaData;

			int ret = 0;

			ret += metadata_readFromElement(params, "stamp", &daemon_sockets[hdr->sock_index].stamp) == CONFIG_FALSE;

			if (ret) {
				PRINT_ERROR("todo error");
			}
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			struct sockaddr_in addr;
			uint32_t dst_ip;
			if (metadata_readFromElement(params, "dst_ip", &dst_ip) == CONFIG_FALSE) {
				addr.sin_addr.s_addr = 0;
			} else {
				addr.sin_addr.s_addr = htonl(dst_ip);
			}

			addr.sin_port = 0;

			if (data_len < ff->ctrlFrame.data_len) {
				//TODO finish, slice off piece of pdu
			}

			//#######
			PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
			u_char *temp = (u_char *) malloc(ff->ctrlFrame.data_len + 1);
			memcpy(temp, ff->ctrlFrame.data, ff->ctrlFrame.data_len);
			temp[ff->ctrlFrame.data_len] = '\0';
			PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->ctrlFrame.data_len, temp);
			free(temp);
			//#######

			int addr_len = sizeof(struct sockaddr_in);

			int msg_len = sizeof(struct nl_daemon_to_wedge) + 2 * sizeof(int) + addr_len + ff->ctrlFrame.data_len;
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
			hdr_ret->msg = MSG_ERRQUEUE; //TODO change to set msg_flags
			u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

			*(int *) pt = addr_len;
			pt += sizeof(int);

			memcpy(pt, &addr, addr_len);
			pt += sizeof(struct sockaddr_in);

			*(int *) pt = ff->ctrlFrame.data_len;
			pt += sizeof(int);

			memcpy(pt, ff->ctrlFrame.data, ff->ctrlFrame.data_len);
			pt += ff->ctrlFrame.data_len;

			if (pt - msg != msg_len) {
				PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

				free(msg);
				//free(ff->ctrlFrame.data);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			}

			free(msg);
			//free(ff->ctrlFrame.data);
			freeFinsFrame(ff);
			return;
		}
	} else {
		if (daemon_sockets[hdr->sock_index].data_buf > 0) {
			struct finsFrame *ff = read_queue(daemon_sockets[hdr->sock_index].data_queue);
			if (ff == NULL) { //TODO shoulnd't happen
				PRINT_ERROR("todo error");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
				return;
			}

			daemon_sockets[hdr->sock_index].data_buf -= ff->dataFrame.pduLength;

			metadata *params = ff->metaData;

			int ret = 0;

			ret += metadata_readFromElement(params, "stamp", &daemon_sockets[hdr->sock_index].stamp) == CONFIG_FALSE;

			if (ret) {
				PRINT_ERROR("todo error");
			}
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			struct sockaddr_in addr;
			uint32_t src_ip;
			if (metadata_readFromElement(params, "src_ip", &src_ip) == CONFIG_FALSE) {
				addr.sin_addr.s_addr = 0;
			} else {
				addr.sin_addr.s_addr = htonl(src_ip);
			}

			addr.sin_port = 0;

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
			hdr_ret->msg = 0; //TODO change to set msg_flags
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
				PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

				free(msg);
				//free(ff->dataFrame.pdu);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			}

			free(msg);
			//free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
			return;
		}
	}

	if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
		daemon_calls[hdr->call_index].flags = flags;
		daemon_calls[hdr->call_index].data = data_len;

		struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
		if (call_list_has_space(call_list)) {
			call_list_append(call_list, &daemon_calls[hdr->call_index]);

			if (flags & (SOCK_NONBLOCK | MSG_DONTWAIT)) {
				daemon_start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
			}
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("call_list full");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		PRINT_ERROR("Insert fail: hdr=%p", hdr);
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void release_out_icmp(struct nl_wedge_to_daemon *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	daemon_sockets_remove(hdr->sock_index);

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void poll_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t events) {
	PRINT_DEBUG("Entered: hdr=%p events=%x", hdr, events);

	uint32_t mask = 0;

	if (events) { //initial
		PRINT_DEBUG("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x",
				(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			if (sem_wait(&daemon_sockets_sem)) {
				PRINT_ERROR("daemon_sockets_sem wait prob");
				exit(-1);
			}
			if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
				PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
						hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
				return;
			}

			if (daemon_sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
			}

			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);
		}

		if (events & (POLLERR)) {
			/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			if (sem_wait(&daemon_sockets_sem)) {
				PRINT_ERROR("daemon_sockets_sem wait prob");
				exit(-1);
			}
			if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
				PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
						hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
				return;
			}

			if (daemon_sockets[hdr->sock_index].error_buf > 0) {
				mask |= POLLERR; //TODO POLLPRI?
			}

			PRINT_DEBUG("");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
		}

		PRINT_DEBUG("mask=%x, AND=%x", mask, mask & events);
		if (mask & events) {
			ack_send(hdr->call_id, hdr->call_index, hdr->call_type, mask);
		} else {
			/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
			if (sem_wait(&daemon_sockets_sem)) {
				PRINT_ERROR("daemon_sockets_sem wait prob");
				exit(-1);
			}
			if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
				PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
						hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
				return;
			}

			struct daemon_call *call = call_create(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index);
			call->data = events;
			call->flags = 0;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, call);

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				PRINT_ERROR("call_list full");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			}
		}
	} else { //final
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
					hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
			return;
		}

		struct daemon_call *call = call_list_find(daemon_sockets[hdr->sock_index].call_list, hdr->call_pid, hdr->call_type, hdr->sock_id);
		if (call) {
			events = call->data;
			mask = call->flags;

			call_list_remove(daemon_sockets[hdr->sock_index].call_list, call);
			call_free(call);

			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("no corresponding call");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

		if (mask) {
			ack_send(hdr->call_id, hdr->call_index, hdr->call_type, mask);
		} else {
			PRINT_DEBUG("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x",
					(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

			if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
				/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
				if (sem_wait(&daemon_sockets_sem)) {
					PRINT_ERROR("daemon_sockets_sem wait prob");
					exit(-1);
				}
				if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
					PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
							hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
					return;
				}

				if (daemon_sockets[hdr->sock_index].data_buf > 0) {
					mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
				}

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			}

			if (events & (POLLERR)) {
				/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
				if (sem_wait(&daemon_sockets_sem)) {
					PRINT_ERROR("daemon_sockets_sem wait prob");
					exit(-1);
				}
				if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
					PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu",
							hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
					/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
					return;
				}

				if (daemon_sockets[hdr->sock_index].error_buf > 0) {
					mask |= POLLERR; //TODO POLLPRI?
				}

				PRINT_DEBUG("");
				/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
				sem_post(&daemon_sockets_sem);
			}

			if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
				mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
			}

			ack_send(hdr->call_id, hdr->call_index, hdr->call_type, mask);
		}
	}
}

/** .......................................................................*/

void shutdown_out_icmp(struct nl_wedge_to_daemon *hdr, int how) {
	PRINT_DEBUG("Entered: hdr=%p how=%d", hdr, how);

	/**
	 *
	 * TODO Implement the checking of the shut_RD, shut_RW flags before making any operations
	 * applied on a TCP socket
	 */

	//index = find_daemonSocket(uniqueSockID);
	/** TODO unlock access to the daemonsockets */
	/*
	 if (index == -1) {
	 PRINT_DEBUG("socket descriptor not found into daemon sockets");
	 return;
	 }

	 PRINT_DEBUG("index = %d", index);
	 */

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void setsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {
	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	/*
	 * 7 levels+:
	 * IPPROTO_IP
	 * IPPROTO_IPv6
	 * IPPROTO_ICMP
	 * IPPROTO_RAW
	 * IPPROTO_TCP
	 * IPPROTO_ICMP
	 *
	 * SOL_IP - must match IPPROTO_xxx
	 * SOL_RAW
	 * SOL_TCP - not declared??
	 * SOL_SOCKET
	 */

	switch (level) {
	case IPPROTO_IP:
		switch (optname) {
		case IP_TOS:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FIP_TOS = *(int *) optval;
				PRINT_DEBUG("FIP_TOS=%d", daemon_sockets[hdr->sock_index].sockopts.FIP_TOS);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case IP_RECVERR:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR = *(int *) optval;
				PRINT_DEBUG("FIP_RECVERR=%d", daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case IP_MTU_DISCOVER:
			//TODO
			PRINT_ERROR("todo");
			break;
		case IP_RECVTTL:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL = *(int *) optval;
				PRINT_DEBUG("FIP_RECVTTL=%d", daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case IP_TTL:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FIP_TTL = *(int *) optval;
				PRINT_DEBUG("FIP_TTL=%d", daemon_sockets[hdr->sock_index].sockopts.FIP_TTL);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		default:
			break;
		}
		break;
	case IPPROTO_RAW:
		switch (optname) {
		case ICMP_FILTER:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FICMP_FILTER = *(int *) optval;
				PRINT_DEBUG("FICMP_FILTER=%d", daemon_sockets[hdr->sock_index].sockopts.FICMP_FILTER);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		default:
			break;
		}
		break;
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FTCP_NODELAY = *(int *) optval;
				PRINT_DEBUG("FTCP_NODELAY=%d", daemon_sockets[hdr->sock_index].sockopts.FTCP_NODELAY);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		default:
			break;
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_DEBUG:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG = *(int *) optval;
				PRINT_DEBUG("FSO_DEBUG=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case SO_REUSEADDR:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR = *(int *) optval;
				PRINT_DEBUG("FSO_REUSEADDR=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case SO_TYPE:
		case SO_PROTOCOL:
		case SO_DOMAIN:
		case SO_ERROR:
		case SO_DONTROUTE:
		case SO_BROADCAST:
			break;
		case SO_SNDBUF:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF = *(int *) optval;
				PRINT_DEBUG("FSO_SNDBUF=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case SO_SNDBUFFORCE:
			break;
		case SO_RCVBUF:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF = 2 * (*(int *) optval); //TODO add conditions
				PRINT_DEBUG("FSO_RCVBUF=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case SO_RCVBUFFORCE:
		case SO_KEEPALIVE:
		case SO_OOBINLINE:
		case SO_NO_CHECK:
		case SO_PRIORITY:
		case SO_LINGER:
		case SO_BSDCOMPAT:
			break;
		case SO_TIMESTAMP:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP = *(int *) optval;
				PRINT_DEBUG("FSO_TIMESTAMP=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP);
			} else {
				PRINT_ERROR("todo error");
			}
			break;
		case SO_TIMESTAMPNS:
		case SO_TIMESTAMPING:
		case SO_RCVTIMEO:
			//TODO less - gets 8 byte value, timestamp??
		case SO_SNDTIMEO:
			//TODO less - gets 8 byte value, timestamp??
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
			PRINT_DEBUG("todo");
			break;
		default:
			PRINT_ERROR("default=%d", optname);
			break;
		}
		break;
	default:
		break;
	}

	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void getsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {
	int len = 0;
	char *val;

	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	switch (level) {
	case IPPROTO_IP:
		switch (optname) {
		case IP_TOS:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FIP_TOS);
			break;
		case IP_RECVERR:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR);
			break;
		case IP_MTU_DISCOVER:
			//TODO
			PRINT_ERROR("todo");
			break;
		case IP_RECVTTL:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL);
			break;
		case IP_TTL:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FIP_TTL);
			break;
		default:
			break;
		}
		break;
	case IPPROTO_RAW:
		switch (optname) {
		case ICMP_FILTER:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FICMP_FILTER);
			break;
		default:
			break;
		}
		break;
	case IPPROTO_TCP:
		switch (optname) {
		case TCP_NODELAY:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FTCP_NODELAY);
			break;
		default:
			break;
		}
		break;
	case SOL_SOCKET:
		switch (optname) {
		case SO_DEBUG:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG);
			break;
		case SO_REUSEADDR:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR);
			break;
		case SO_TYPE:
		case SO_PROTOCOL:
		case SO_DOMAIN:
		case SO_ERROR:
		case SO_DONTROUTE:
		case SO_BROADCAST:
			break;
		case SO_SNDBUF:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF);
			break;
		case SO_SNDBUFFORCE:
			break;
		case SO_RCVBUF:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF);
			break;
		case SO_RCVBUFFORCE:
		case SO_KEEPALIVE:
		case SO_OOBINLINE:
		case SO_NO_CHECK:
		case SO_PRIORITY:
		case SO_LINGER:
		case SO_BSDCOMPAT:
			break;
		case SO_TIMESTAMP:
			len = sizeof(int);
			val = (char *) &(daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP);
			break;
		case SO_TIMESTAMPNS:
		case SO_TIMESTAMPING:
		case SO_RCVTIMEO:
			//TODO less - gets 8 byte value, timestamp??
		case SO_SNDTIMEO:
			//TODO less - gets 8 byte value, timestamp??
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
			PRINT_DEBUG("todo");
			break;
		default:
			PRINT_ERROR("default=%d", optname);
			break;
		}
		break;
	default:
		break;
	}
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	//if (len) {
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
		PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {

	}
	free(msg);
}

void poll_in_icmp(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, flags=%u", call_list, call, flags);

	uint32_t events = call->data;

	PRINT_DEBUG("POLLIN=%x POLLPRI=%x POLLOUT=%x POLLERR=%x POLLHUP=%x POLLNVAL=%x POLLRDNORM=%x POLLRDBAND=%x POLLWRNORM=%x POLLWRBAND=%x",
			(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

	uint32_t mask = 0;

	if (flags & POLLERR) {
		mask |= POLLERR;
	}

	if (flags & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
	}

	if (events & mask) {
		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge);
		u_char *msg = (u_char *) malloc(msg_len);
		if (msg == NULL) {
			PRINT_ERROR("ERROR: buf alloc fail");
			exit(-1);
		}

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = poll_event_call;
		hdr_ret->sock_id = call->sock_id;
		hdr_ret->sock_index = call->sock_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = call->call_pid;
		u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
			free(msg);
			return;
		}

		PRINT_DEBUG("msg_len=%d msg='%s'", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: send_wedge error: call=%p", call);
		} else {

		}
		free(msg);

		call->flags = events & mask;
	}
}

void recvmsg_in_icmp(struct daemon_call_list *call_list, struct daemon_call *call, metadata *params, u_char *data, uint32_t data_len, uint32_t addr_ip,
		uint32_t flags) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, params=%p, data=%p, len=%u, addr_ip=%u, flags=%u", call_list, call, params, data, data_len, addr_ip, flags);

	uint32_t call_len = call->data; //buffer size

	int ret = 0;

	ret += metadata_readFromElement(params, "stamp", &daemon_sockets[call->sock_index].stamp) == CONFIG_FALSE;

	if (ret) {
		PRINT_ERROR("todo error");
	}
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)daemon_sockets[call->sock_index].stamp.tv_sec, (uint32_t)daemon_sockets[call->sock_index].stamp.tv_usec);

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = htonl(addr_ip);
	addr.sin_port = 0;

	if (call_len < data_len) {
		//TODO finish, slice off piece of pdu
	}

	//#######
	PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
	u_char *temp = (u_char *) malloc(data_len + 1);
	memcpy(temp, data, data_len);
	temp[data_len] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", data_len, temp);
	free(temp);
	//#######

	int addr_len = sizeof(struct sockaddr_in);

	int msg_len = sizeof(struct nl_daemon_to_wedge) + 2 * sizeof(int) + addr_len + data_len;
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
	hdr_ret->msg = flags;
	u_char *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, &addr, addr_len);
	pt += sizeof(struct sockaddr_in);

	*(int *) pt = data_len;
	pt += sizeof(int);

	memcpy(pt, data, data_len);
	pt += data_len;

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d len=%d\n", pt - msg, msg_len);
		free(msg);

		PRINT_DEBUG("Exited: write error: call_list=%p, call=%p", call_list, call);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: send_wedge error: call_list=%p, call=%p", call_list, call);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	} else {
		PRINT_DEBUG("Exited: Normal: call_list=%p, call=%p", call_list, call);
	}
	free(msg);

	call_list_remove(call_list, call);
	daemon_calls_remove(call->call_index);
}

void daemon_icmp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: ff=%p src_ip=%u, dst_ip=%u", ff, src_ip, dst_ip);

	metadata *params = ff->metaData;

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	//TODO move to interface?
	metadata_writeToElement(params, "stamp", &current, CONFIG_TYPE_INT64);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}

	struct daemon_call_list *call_list;
	struct daemon_call *call;
	int unsent;
	metadata *params_copy;
	struct finsFrame *ff_copy;

	int i;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id != -1 && daemon_sockets[i].protocol == IPPROTO_ICMP && daemon_sockets[i].host_ip == dst_ip) {
			PRINT_DEBUG( "Matched: sock_id=%llu sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
					daemon_sockets[i].sock_id, i, daemon_sockets[i].host_ip, daemon_sockets[i].host_port, daemon_sockets[i].dst_ip, daemon_sockets[i].dst_port, daemon_sockets[i].protocol);

			//TODO check if this datagram comes from the address this socket has been previously connected to it (Only if the socket is already connected to certain address)

			call_list = daemon_sockets[i].call_list;

			call = call_list->front;
			while (call) {
				if (call->call_type == poll_call && !call->flags) { //signal all poll calls in list
					poll_in_icmp(call_list, call, POLLIN);
					break; //TODO remove? %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
				}
				call = call->next;
			}

			unsent = 1;
			call = call_list->front;
			while (call) {
				if (call->call_type == recvmsg_call && !(call->flags & (MSG_ERRQUEUE))) { //signal first recvmsg for data
					recvmsg_in_icmp(call_list, call, params, ff->dataFrame.pdu, ff->dataFrame.pduLength, src_ip, 0);
					unsent = 0;
					break;
				}
				call = call->next;
			}

			if (unsent) {
				params_copy = (metadata *) malloc(sizeof(metadata));
				if (params_copy == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_copy);
				if (metadata_copy(params, params_copy) == CONFIG_FALSE) {
					PRINT_ERROR("todo error");
				}

				ff_copy = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_copy == NULL) {
					PRINT_ERROR("ff_copy alloc failed");
					exit(-1);
				}

				ff_copy->dataOrCtrl = ff->dataOrCtrl;
				ff_copy->destinationID.id = ff->destinationID.id;
				ff_copy->destinationID.next = ff->destinationID.next;
				ff_copy->metaData = params_copy;

				ff_copy->dataFrame.directionFlag = ff->dataFrame.directionFlag;
				ff_copy->dataFrame.pduLength = ff->dataFrame.pduLength; //Add in the header size for this, too
				ff_copy->dataFrame.pdu = (u_char *) malloc(ff_copy->dataFrame.pduLength);
				if (ff_copy->dataFrame.pdu == NULL) {
					PRINT_ERROR("failed to create pdu: ff=%p", ff_copy);
					exit(-1);
				}
				memcpy(ff_copy->dataFrame.pdu, ff->dataFrame.pdu, ff_copy->dataFrame.pduLength);

				if (write_queue(ff_copy, daemon_sockets[i].data_queue)) {
					daemon_sockets[i].data_buf += ff_copy->dataFrame.pduLength;
					PRINT_DEBUG("stored, sock_index=%d, ff=%p, meta=%p", i, ff_copy, params_copy);
				} else {
					PRINT_ERROR("Write queue error: ff=%p", ff_copy);
					//if (ff_copy->dataFrame.pduLength)
					//	free(ff_copy->dataFrame.pdu);
					freeFinsFrame(ff_copy);
				}
			}
		}
	}
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	//if (ff->dataFrame.pduLength)
	//	free(ff->dataFrame.pdu);
	freeFinsFrame(ff);
	return;
}

void daemon_icmp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: ff=%p src_ip=%u, dst_ip=%u", ff, src_ip, dst_ip);

	metadata *params = ff->metaData;

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	//TODO move to interface?
	metadata_writeToElement(params, "stamp", &current, CONFIG_TYPE_INT64);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}

	struct daemon_call_list *call_list;
	struct daemon_call *call;
	int unsent;
	metadata *params_copy;
	struct finsFrame *ff_copy;

	int i;
	for (i = 0; i < MAX_SOCKETS; i++) {
		if (daemon_sockets[i].sock_id != -1 && daemon_sockets[i].protocol == IPPROTO_ICMP && daemon_sockets[i].host_ip == src_ip) {
			PRINT_DEBUG( "Matched: sock_id=%llu sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
					daemon_sockets[i].sock_id, i, daemon_sockets[i].host_ip, daemon_sockets[i].host_port, daemon_sockets[i].dst_ip, daemon_sockets[i].dst_port, daemon_sockets[i].protocol);

			//TODO check if this datagram comes from the address this socket has been previously connected to it (Only if the socket is already connected to certain address)

			call_list = daemon_sockets[i].call_list;

			call = call_list->front;
			while (call) {
				if (call->call_type == poll_call && !call->flags) { //signal all poll calls in list
					poll_in_icmp(call_list, call, POLLERR);
				}
				call = call->next;
			}

			unsent = 1;
			call = call_list->front;
			while (call) {
				if (call->call_type == recvmsg_call && (call->flags & (MSG_ERRQUEUE))) { //signal first recvmsg for data
					recvmsg_in_icmp(call_list, call, params, ff->ctrlFrame.data, ff->ctrlFrame.data_len, dst_ip, MSG_ERRQUEUE);
					unsent = 0;
					break;
				}
				call = call->next;
			}

			if (unsent) {
				params_copy = (metadata *) malloc(sizeof(metadata));
				if (params_copy == NULL) {
					PRINT_ERROR("metadata creation failed");
					exit(-1);
				}
				metadata_create(params_copy);
				if (metadata_copy(params, params_copy) == CONFIG_FALSE) {
					PRINT_ERROR("todo error");
				}

				ff_copy = (struct finsFrame *) malloc(sizeof(struct finsFrame));
				if (ff_copy == NULL) {
					PRINT_ERROR("ff_copy alloc failed");
					exit(-1);
				}

				ff_copy->dataOrCtrl = ff->dataOrCtrl;
				ff_copy->destinationID.id = ff->destinationID.id;
				ff_copy->destinationID.next = ff->destinationID.next;
				ff_copy->metaData = params_copy;

				ff_copy->ctrlFrame.senderID = ff->ctrlFrame.senderID;
				ff_copy->ctrlFrame.serial_num = ff->ctrlFrame.serial_num;
				ff_copy->ctrlFrame.opcode = ff->ctrlFrame.opcode;
				ff_copy->ctrlFrame.param_id = ff->ctrlFrame.param_id;
				ff_copy->ctrlFrame.ret_val = ff->ctrlFrame.ret_val;
				ff_copy->ctrlFrame.data_len = ff->ctrlFrame.data_len; //Add in the header size for this, too
				ff_copy->ctrlFrame.data = (u_char *) malloc(ff_copy->ctrlFrame.data_len);
				if (ff_copy->ctrlFrame.data == NULL) {
					PRINT_ERROR("failed to create pdu: ff=%p", ff_copy);
					exit(-1);
				}
				memcpy(ff_copy->ctrlFrame.data, ff->ctrlFrame.data, ff_copy->ctrlFrame.data_len);

				if (write_queue(ff_copy, daemon_sockets[i].error_queue)) {
					daemon_sockets[i].error_buf++; //TODO change to byte size?
				} else {
					PRINT_ERROR("Write queue error: ff=%p", ff_copy);
					//if (ff_copy->ctrlFrame.data_len)
					//	free(ff_copy->ctrlFrame.data);
					freeFinsFrame(ff_copy);
				}
			}
		}
	}
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	//if (ff->ctrlFrame.data_len)
	//	free(ff->ctrlFrame.data);
	freeFinsFrame(ff);
}

