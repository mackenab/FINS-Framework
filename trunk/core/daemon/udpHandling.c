/**
 * @file udpHandling.c
 *
 *  @date Nov 28, 2010
 *   @author Jonathan Reed
 */

#include "udpHandling.h"
#include <finstypes.h>

extern sem_t daemon_sockets_sem;
extern struct daemon_socket daemon_sockets[MAX_SOCKETS];

extern sem_t daemon_calls_sem; //TODO remove?
extern struct daemon_call daemon_calls[MAX_CALLS];

extern int daemon_thread_count; //for TO threads
extern sem_t daemon_thread_sem;

int daemon_fdf_to_udp(u_char *data, uint32_t data_len, metadata *params) {

	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
	if (ff == NULL) {
		PRINT_DEBUG("ff creation failed");
		return 0;
	}

	/**TODO get the address automatically by searching the local copy of the
	 * switch table
	 */
	ff->dataOrCtrl = DATA;
	ff->destinationID.id = UDP_ID;
	ff->destinationID.next = NULL;
	ff->metaData = params;

	ff->dataFrame.directionFlag = DOWN;
	ff->dataFrame.pduLength = data_len;
	ff->dataFrame.pdu = data;

	/*#*/PRINT_DEBUG("");
	if (daemon_to_switch(ff)) {
		return 1;
	} else {
		PRINT_DEBUG("freeing: ff=%p", ff);
		free(ff);
		return 0;
	}
}

/**
 * End of interfacing socketdaemon with FINS core
 * */
void socket_out_udp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol) {
	int ret;

	PRINT_DEBUG("Entered: hdr=%p, domain=%d, type=%d, proto=%d", hdr, domain, type, protocol);

	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	ret = daemon_sockets_insert(hdr->sock_id, hdr->sock_index, type, protocol); //TODO add &udp_ops
	PRINT_DEBUG("sock_index=%d ret=%d", hdr->sock_index, ret);
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	if (ret) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void bind_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr) {

	uint16_t host_port;
	uint32_t host_ip;

	PRINT_DEBUG("Entered: hdr=%p", hdr);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family=%d", addr->sin_family);
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
		PRINT_DEBUG("this port is not free");
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

	PRINT_DEBUG("bind: index:%d, host:%d/%d, dst:%d/%d",
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
} // end of bind_udp

void listen_out_udp(struct nl_wedge_to_daemon *hdr, int backlog) {
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

void connect_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags) {

	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, flags=%d", hdr, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d) O_NONBLOCK=%d (%d) O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	if (addr->sin_family != AF_INET) {
		PRINT_DEBUG("Wrong address family");
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
	 * once over the same UDP socket changing the address from one to another. SO the assigning
	 * will take place even if the check functions returns (-1) !!!
	 * */

	/** TODO connect for UDP means that this address will be the default address to send
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

void accept_out_udp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags) {

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

void getname_out_udp(struct nl_wedge_to_daemon *hdr, int peer) {
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
}

void ioctl_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, u_char *buf, ssize_t buf_len) {
	uint32_t len;
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

void sendmsg_out_udp(struct nl_wedge_to_daemon *hdr, u_char *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *addr, int addr_len) {

	uint32_t host_ip;
	uint16_t host_port;
	uint32_t dst_ip;
	uint16_t dst_port;

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
			PRINT_DEBUG("Wrong address family, send NACK");
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

	PRINT_DEBUG("");
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
	if (host_port == 0) {
		while (1) {
			host_port = randoming(MIN_port, MAX_port);
			if (daemon_sockets_check_ports(host_port, host_ip)) {
				break;
			}
		}
		daemon_sockets[hdr->sock_index].host_port = host_port;
	}

	/*//TODO uncomment? find out if connect rem addr sent through sendmsg
	 if (daemonSockets[hdr->sock_index].state > SS_UNCONNECTED) {
	 dst_port = daemonSockets[hdr->sock_index].dst_port;
	 dst_ip = daemonSockets[hdr->sock_index].dst_ip;
	 }*/

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("index=%d, dst=%u/%d, host=%u/%d", hdr->sock_index, dst_ip, dst_port, host_ip, host_port);

	temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = htonl(dst_ip);
	PRINT_DEBUG("index=%d, dst=%s/%d (%u)", hdr->sock_index, inet_ntoa(*temp), host_port, (*temp).s_addr);
	temp->s_addr = htonl(host_ip);
	PRINT_DEBUG("index=%d, host=%s/%d (%u)", hdr->sock_index, inet_ntoa(*temp), host_port, (*temp).s_addr);
	free(temp);
	PRINT_DEBUG("");

	metadata *params = (metadata *) malloc(sizeof(metadata));
	if (params == NULL) {
		PRINT_ERROR("metadata creation failed");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		exit(-1);
	}
	metadata_create(params);

	//metadata_writeToElement(params, "flags", &flags, META_TYPE_INT);

	metadata_writeToElement(params, "src_ip", &host_ip, META_TYPE_INT);
	metadata_writeToElement(params, "src_port", &host_port, META_TYPE_INT);
	metadata_writeToElement(params, "dst_ip", &dst_ip, META_TYPE_INT);
	metadata_writeToElement(params, "dst_port", &dst_port, META_TYPE_INT);

	if (daemon_fdf_to_udp(data, data_len, params)) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_DEBUG("socketdaemon failed to accomplish sendto");
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
void recvmsg_out_udp(struct nl_wedge_to_daemon *hdr, int data_len, int flags, uint32_t msg_flags) {
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
		PRINT_ERROR("Socket closed, canceling read block.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

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
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		struct sockaddr_in addr;
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
			//PRINT_DEBUG("Exiting, fail send_wedge: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		} else {
			//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
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

				if (flags & (SOCK_NONBLOCK | MSG_DONTWAIT)) {
					daemon_start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
				}
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
	}
}

void release_out_udp(struct nl_wedge_to_daemon *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket closed, canceling release_udp.");
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

void poll_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t events) {
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
			PRINT_ERROR("Socket closed, canceling poll_udp.");
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
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
	}

	if (mask & events) {
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
		/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		if (sem_wait(&daemon_sockets_sem)) {
			PRINT_ERROR("daemon_sockets_sem wait prob");
			exit(-1);
		}
		if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_ERROR("Socket closed, canceling poll_udp.");
			/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			return;
		}

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
	}
}

/** .......................................................................*/

void shutdown_out_udp(struct nl_wedge_to_daemon *hdr, int how) {
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

void setsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {

	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket closed, canceling getsockopt_udp.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

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
		daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG = *(int *) optval;
		PRINT_DEBUG("FSO_DEBUG=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG);
		break;
	case SO_REUSEADDR:
		daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR = *(int *) optval;
		PRINT_DEBUG("FSO_REUSEADDR=%d", daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR);
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

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

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

void getsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval) {
	int len;
	char *val;
	int ret_val;

	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	/*#*/PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	if (sem_wait(&daemon_sockets_sem)) {
		PRINT_ERROR("daemon_sockets_sem wait prob");
		exit(-1);
	}
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket closed, canceling getsockopt_udp.");
		/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("");
	/*#*/PRINT_DEBUG("post@@@@@@@@@@@@@@@@@@@@@@@");
	sem_post(&daemon_sockets_sem);

	/*
	 metadata *udpout_meta = (metadata *) malloc(sizeof(metadata));
	 metadata_create(udpout_meta);
	 metadata_writeToElement(udpout_meta, "dstport", &dstprt, META_TYPE_INT);
	 */

	switch (optname) {
	case SO_DEBUG:
		//daemonSockets[hdr->sock_index].sockopts.FSO_DEBUG = *(int *)optval;
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
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	ret_val = send_wedge(nl_sockfd, msg, msg_len, 0);
	free(msg);
	if (ret_val) {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void poll_in_udp(struct daemon_call_list *call_list, struct daemon_call *call) {
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

void recvmsg_in_udp(struct daemon_call_list *call_list, struct daemon_call *call, struct finsFrame *ff, uint32_t src_ip, uint16_t src_port) {
	//int non_blocking_flag = flags & (SOCK_NONBLOCK | O_NONBLOCK | MSG_DONTWAIT); //TODO get from flags
	PRINT_DEBUG("Entered: ff=%p, call=%p, src=%u/%u", ff, call, src_ip, src_port);

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
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("msg_len=%d msg=%s", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_DEBUG("Exited: send_wedge error: ff=%p, call=%p", ff, call);
		nack_send(call->call_id, call->call_index, call->call_type, 0);
	} else {
		PRINT_DEBUG("Exited: Normal: ff=%p, call=%p", ff, call);
	}

	call_list_remove(call_list, call);
	//call_free(call);
	daemon_calls_remove(call->call_index);
}

void daemon_udp_in_fdf(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t dst_ip, uint16_t dst_port) {
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
	int sock_index = daemon_sockets_match(dst_port, dst_ip, IPPROTO_UDP); //TODO change for multicast
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

		/*
		 * check if this datagram comes from the address this socket has been previously
		 * connected to it (Only if the socket is already connected to certain address)
		 */

		struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

		struct daemon_call *call = call_list->front;
		while (call) {
			if (call->call_type == poll_call) { //handle poll_udp_out call
				poll_in_udp(call_list, call);
				break;
			}
			call = call->next;
		}

		call = call_list->front;
		while (call) {
			if (call->call_type == recvmsg_call) { //TODO handle recvmsg_udp call
				recvmsg_in_udp(call_list, call, ff, host_ip, host_port);

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
