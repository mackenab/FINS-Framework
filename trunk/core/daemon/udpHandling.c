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

extern struct daemon_call daemon_calls[MAX_CALLS];
extern struct daemon_call_list *expired_call_list;

/**
 * End of interfacing socketdaemon with FINS core
 * */
void socket_out_udp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol) {
	PRINT_DEBUG("Entered: hdr=%p, domain=%d, type=%d, proto=%d", hdr, domain, type, protocol);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int ret = daemon_sockets_insert(hdr->sock_id, hdr->sock_index, type, protocol); //TODO add &udp_ops
	PRINT_DEBUG("sock_index=%d, ret=%d", hdr->sock_index, ret);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (ret) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void bind_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr) {

	uint16_t host_port;
	uint32_t host_ip;

	PRINT_DEBUG("Entered: hdr=%p", hdr);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family=%d", addr->sin_family);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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
	PRINT_DEBUG("bind address: host=%s/%d, host_IP_netformat=%d", inet_ntoa(addr->sin_addr), host_port, addr->sin_addr.s_addr);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!daemon_sockets_check_ports(host_port, host_ip) && !daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR) {
		PRINT_ERROR("this port is not free");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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
			hdr->sock_index, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	daemon_sockets[hdr->sock_index].listening = 1;
	daemon_sockets[hdr->sock_index].backlog = backlog;

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void connect_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags) {
	uint32_t dst_ip;
	uint16_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, flags=%d", hdr, flags);PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d), O_NONBLOCK=%d (%d), O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	if (daemon_sockets[hdr->sock_index].state > SS_UNCONNECTED) {
		PRINT_DEBUG("old destined address %d, %d", daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);PRINT_DEBUG("new destined address %d, %d", dst_ip, dst_port);
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
	daemon_sockets[hdr->sock_index].state = SS_CONNECTING;
	daemon_sockets[hdr->sock_index].rem_ip = dst_ip;
	daemon_sockets[hdr->sock_index].rem_port = dst_port;

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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

	PRINT_DEBUG("Entered: hdr=%p, sock_id_new=%llu, index_new=%d, flags=%d", hdr, sock_id_new, sock_index_new, flags);PRINT_DEBUG("SOCK_NONBLOCK=%d (%d), SOCK_CLOEXEC=%d (%d), O_NONBLOCK=%d (%d), O_ASYNC=%d (%d)",
			SOCK_NONBLOCK & flags, SOCK_NONBLOCK, SOCK_CLOEXEC & flags, SOCK_CLOEXEC, O_NONBLOCK & flags, O_NONBLOCK, O_ASYNC & flags, O_ASYNC);

	//TODO: finish this
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	if (peer == 0) { //getsockname
		host_ip = daemon_sockets[hdr->sock_index].host_ip;
		host_port = daemon_sockets[hdr->sock_index].host_port;

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
		if ((uint16_t) host_port == 0) {
			while (1) {
				host_port = (uint16_t) randoming(MIN_port, MAX_port);
				if (daemon_sockets_check_ports((uint16_t) host_port, host_ip)) {
					break;
				}
			}
			daemon_sockets[hdr->sock_index].host_port = (uint16_t) host_port;
		}
	} else if (peer == 1) { //getpeername
		state = daemon_sockets[hdr->sock_index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
			rem_port = daemon_sockets[hdr->sock_index].rem_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
		state = daemon_sockets[hdr->sock_index].state;
		if (state > SS_UNCONNECTED) {
			rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
			rem_port = daemon_sockets[hdr->sock_index].rem_port;
		} else {
			rem_ip = 0;
			rem_port = 0;
		}
	} else {
		//TODO error
		PRINT_ERROR("todo error");
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	struct sockaddr_in *addr = (struct sockaddr_in *) secure_malloc(sizeof(struct sockaddr_in));

	if (peer == 0) { //getsockname
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(host_ip);
		addr->sin_port = htons(host_port);
	} else if (peer == 1) { //getpeername
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(rem_ip);
		addr->sin_port = htons(rem_port);
	} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
		addr->sin_family = AF_INET;
		addr->sin_addr.s_addr = htonl(rem_ip);
		addr->sin_port = htons(rem_port);
	} else {
		//TODO error
		PRINT_ERROR("todo error");
	}PRINT_DEBUG("addr=(%s/%d) netw=%u", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), addr->sin_addr.s_addr);

	int len = sizeof(struct sockaddr_in);

	//send msg to wedge
	int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + len;
	uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = hdr->call_type;
	hdr_ret->call_id = hdr->call_id;
	hdr_ret->call_index = hdr->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0;
	uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = len;
	pt += sizeof(int);

	memcpy(pt, addr, len);
	pt += len;

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
		free(msg);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else {
		PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
	}

	free(msg);
	free(addr);
}

void ioctl_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, uint8_t *buf, ssize_t buf_len) {
	uint32_t len;
	//uint8_t *val;
	int msg_len;
	uint8_t *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	uint8_t *pt;

	PRINT_DEBUG("Entered: hdr=%p, cmd=%d, len=%d", hdr, cmd, buf_len);PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	switch (cmd) {
	case FIONREAD:
		PRINT_DEBUG("FIONREAD cmd=%d", cmd);
		//figure out buffered data

		//send msg to wedge
		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t);
		msg = (uint8_t *) secure_malloc(msg_len);

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
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGSTAMP:
		PRINT_DEBUG("SIOCGSTAMP cmd=%d", cmd);

		len = sizeof(struct timeval);
		//val = &daemon_sockets[hdr->sock_index].latest;

		//send msg to wedge
		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(uint32_t) + len;
		msg = (uint8_t *) secure_malloc(msg_len);

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
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	default:
		PRINT_ERROR("default cmd=%d", cmd);
		break;
	}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
		free(msg);
	} else {
		//nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO uncomment
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	}
}

void sendmsg_out_udp(struct nl_wedge_to_daemon *hdr, uint8_t *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *addr, int addr_len) {

	uint32_t host_ip;
	uint32_t host_port;
	uint32_t dst_ip;
	uint32_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, flags=%d, addr_len=%d", hdr, data_len, flags, addr_len);PRINT_DEBUG("MSG_CONFIRM=%d (%d), MSG_DONTROUTE=%d (%d), MSG_DONTWAIT=%d (%d), MSG_EOR=%d (%d), MSG_MORE=%d (%d), MSG_NOSIGNAL=%d (%d), MSG_OOB=%d (%d)",
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

	if (data_len == 0) { //TODO check this prob wrong!
		PRINT_ERROR("todo/redo");
		PRINT_DEBUG("data_len == 0, send ACK");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		if (addr)
			free(addr);
		return;
	}

	if (addr_len) {
		if (addr->sin_family != AF_INET) {
			PRINT_ERROR("Wrong address family, send NACK");
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

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

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("CRASH !! socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

		free(data);
		if (addr)
			free(addr);
		return;
	}

	if (addr_len == 0) {
		dst_ip = daemon_sockets[hdr->sock_index].rem_ip;
		dst_port = daemon_sockets[hdr->sock_index].rem_port;
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
	if ((uint16_t) host_port == 0) {
		while (1) {
			host_port = (uint16_t) randoming(MIN_port, MAX_port);
			if (daemon_sockets_check_ports((uint16_t) host_port, host_ip)) {
				break;
			}
		}
		daemon_sockets[hdr->sock_index].host_port = (uint16_t) host_port;
	}

	/*//TODO uncomment? find out if connect rem addr sent through sendmsg
	 if (daemonSockets[hdr->sock_index].state > SS_UNCONNECTED) {
	 dst_port = daemonSockets[hdr->sock_index].rem_port;
	 dst_ip = daemonSockets[hdr->sock_index].rem_ip;
	 }*/

	uint32_t ttl = daemon_sockets[hdr->sock_index].sockopts.FIP_TTL;
	uint32_t tos = daemon_sockets[hdr->sock_index].sockopts.FIP_TOS;

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("index=%d, dst=%u/%u, host=%u/%u", hdr->sock_index, dst_ip, (uint16_t)dst_port, host_ip, (uint16_t)host_port);

	//########################
#ifdef DEBUG
	struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
	temp->s_addr = htonl(host_ip);
	PRINT_DEBUG("index=%d, host=%s/%u (%u)", hdr->sock_index, inet_ntoa(*temp), (uint16_t)host_port, host_ip);
	temp->s_addr = htonl(dst_ip);
	PRINT_DEBUG("index=%d, dst=%s/%u (%u)", hdr->sock_index, inet_ntoa(*temp), (uint16_t)dst_port, dst_ip);
	free(temp);
#endif
	//########################

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	//secure_metadata_writeToElement(params, "flags", &flags, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "send_src_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "send_src_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "send_dst_ip", &dst_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "send_dst_port", &dst_port, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "send_ttl", &ttl, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "send_tos", &tos, META_TYPE_INT32);

	if (daemon_fdf_to_switch(UDP_ID, data, data_len, params)) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, data_len);
	} else {
		PRINT_ERROR("socketdaemon failed to accomplish sendto");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

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
void recvmsg_out_udp(struct nl_wedge_to_daemon *hdr, int data_len, uint32_t msg_controllen, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, msg_controllen=%u, flags=%d", hdr, data_len, msg_controllen, flags);

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, (SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);PRINT_DEBUG( "MSG_CMSG_CLOEXEC=%d, MSG_DONTWAIT=%d, MSG_ERRQUEUE=%d, MSG_OOB=%d, MSG_PEEK=%d, MSG_TRUNC=%d, MSG_WAITALL=%d",
			(MSG_CMSG_CLOEXEC & flags)>0, (MSG_DONTWAIT & flags)>0, (MSG_ERRQUEUE & flags)>0, (MSG_OOB & flags)>0, (MSG_PEEK & flags)>0, (MSG_TRUNC & flags)>0, (MSG_WAITALL & flags)>0);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	if (flags & MSG_ERRQUEUE) {
		if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR) {
			if (daemon_sockets[hdr->sock_index].error_buf > 0) {
				struct finsFrame *ff = read_queue(daemon_sockets[hdr->sock_index].error_queue);
				if (ff == NULL) { //TODO shoulnd't happen
					PRINT_ERROR("todo error");
					PRINT_DEBUG("post$$$$$$$$$$$$$$$");
					sem_post(&daemon_sockets_sem);

					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
					return;
				}

				daemon_sockets[hdr->sock_index].error_buf--;

				metadata *params = ff->metaData;
				secure_metadata_readFromElement(params, "recv_stamp", &daemon_sockets[hdr->sock_index].stamp);

				uint32_t control_len = 0;
				uint8_t *control_msg;

				if (msg_controllen < CONTROL_LEN_MAX) {
					if (msg_controllen == 0) {
						msg_controllen = CONTROL_LEN_DEFAULT;
					}

					control_msg = (uint8_t *) secure_malloc(msg_controllen);
					uint8_t *control_pt = control_msg;

					uint32_t cmsg_data_len;
					uint32_t cmsg_space;
					struct cmsghdr *cmsg;
					uint8_t *cmsg_data;

					if (daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP) {
						cmsg_data_len = sizeof(struct timeval);
						cmsg_space = CMSG_SPACE(cmsg_data_len);

						if (control_len + cmsg_space <= msg_controllen) {
							cmsg = (struct cmsghdr *) control_pt;
							cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
							cmsg->cmsg_level = SOL_SOCKET;
							cmsg->cmsg_type = SO_TIMESTAMP;
							PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x",
									cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

							cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
							memcpy(cmsg_data, &daemon_sockets[hdr->sock_index].stamp, cmsg_data_len);

							control_len += cmsg_space;
							control_pt += cmsg_space;
						} else {
							PRINT_ERROR("todo error");
						}
					}

					if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL) {
						int32_t recv_ttl = 255;
						if (metadata_readFromElement(params, "recv_ttl", &recv_ttl) == META_TRUE) {
							cmsg_data_len = sizeof(int32_t);
							cmsg_space = CMSG_SPACE(cmsg_data_len);

							if (control_len + cmsg_space <= msg_controllen) {
								cmsg = (struct cmsghdr *) control_pt;
								cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
								cmsg->cmsg_level = IPPROTO_IP;
								cmsg->cmsg_type = IP_TTL;
								PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x",
										cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

								cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
								*(int32_t *) cmsg_data = recv_ttl;

								control_len += cmsg_space;
								control_pt += cmsg_space;
							} else {
								PRINT_ERROR("todo error");
							}
						} else {
							PRINT_ERROR("no recv_ttl, meta=%p", params);
						}
					}

					if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR) {
						uint32_t err_src_ip;
						secure_metadata_readFromElement(params, "recv_src_ip", &err_src_ip);

						cmsg_data_len = sizeof(struct errhdr);
						cmsg_space = CMSG_SPACE(cmsg_data_len);

						if (control_len + cmsg_space <= msg_controllen) {
							cmsg = (struct cmsghdr *) control_pt;
							cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
							cmsg->cmsg_level = IPPROTO_IP;
							cmsg->cmsg_type = IP_RECVERR;
							PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x",
									cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

							struct errhdr *err = (struct errhdr *) CMSG_DATA(cmsg);
							err->ee.ee_errno = EHOSTUNREACH; //113
							err->ee.ee_origin = SO_EE_ORIGIN_ICMP; //2
							err->ee.ee_type = 11;

							err->ee.ee_code = 0;
							err->ee.ee_pad = 0;
							err->ee.ee_info = 0;
							err->ee.ee_data = 0;

							err->offender.sin_family = AF_INET;
							err->offender.sin_addr.s_addr = htonl(err_src_ip);
							err->offender.sin_port = htons(0);

							control_len += cmsg_space;
							control_pt += cmsg_space;
						} else {
							PRINT_ERROR("todo error");
						}
					}

					PRINT_DEBUG("control_msg=%p, control_pt=%p, diff=%u, control_len=%u, check=%u",
							control_msg, control_pt, control_pt - control_msg, control_len, control_pt - control_msg == control_len);
				} else {
					PRINT_ERROR("todo error");
					//TODO send some error
				}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				struct sockaddr_in addr;
				addr.sin_family = AF_INET;

				uint32_t dst_ip;
				if (metadata_readFromElement(params, "send_dst_ip", &dst_ip) == META_FALSE) {
					addr.sin_addr.s_addr = 0;
				} else {
					addr.sin_addr.s_addr = htonl(dst_ip);
				}

				uint32_t dst_port;
				if (metadata_readFromElement(params, "send_dst_port", &dst_port) == META_FALSE) {
					addr.sin_port = 0;
				} else {
					addr.sin_port = htons((uint16_t) dst_port);
				}

				if (data_len < ff->ctrlFrame.data_len) {
					//TODO finish, slice off piece of pdu
				}

				//#######
#ifdef DEBUG
				PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
				uint8_t *temp = (uint8_t *) malloc(ff->ctrlFrame.data_len + 1);
				memcpy(temp, ff->ctrlFrame.data, ff->ctrlFrame.data_len);
				temp[ff->ctrlFrame.data_len] = '\0';
				PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->ctrlFrame.data_len, temp);
				free(temp);
#endif
				//#######

				int addr_len = sizeof(struct sockaddr_in);

				int msg_len = sizeof(struct nl_daemon_to_wedge) + 3 * sizeof(int) + addr_len + ff->ctrlFrame.data_len + control_len;
				uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

				struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
				hdr_ret->call_type = hdr->call_type;
				hdr_ret->call_id = hdr->call_id;
				hdr_ret->call_index = hdr->call_index;
				hdr_ret->ret = ACK;
				hdr_ret->msg = MSG_ERRQUEUE; //TODO change to set msg_flags
				uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

				*(int *) pt = addr_len;
				pt += sizeof(int);

				memcpy(pt, &addr, addr_len);
				pt += sizeof(struct sockaddr_in);

				*(int *) pt = ff->ctrlFrame.data_len;
				pt += sizeof(int);

				memcpy(pt, ff->ctrlFrame.data, ff->ctrlFrame.data_len);
				pt += ff->ctrlFrame.data_len;

				*(int *) pt = control_len;
				pt += sizeof(int);

				memcpy(pt, control_msg, control_len);
				pt += control_len;

				if (pt - msg != msg_len) {
					PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

					if (control_msg)
						free(control_msg);
					free(msg);
					freeFinsFrame(ff);
					return;
				}

				PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
				if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
					PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
					nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
				} else {
					//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
				}

				if (control_msg)
					free(control_msg);
				free(msg);
				freeFinsFrame(ff);
				return;
			} else {
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				//NACK
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 11); //Resource temporarily unavailable
				return;
			}
		} else {
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			//NACK
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 11); //Resource temporarily unavailable
			return;
		}
	} else {
		PRINT_DEBUG("before: sock_index=%d, data_buf=%d", hdr->sock_index, daemon_sockets[hdr->sock_index].data_buf);
		if (daemon_sockets[hdr->sock_index].data_buf > 0) {
			struct finsFrame *ff = read_queue(daemon_sockets[hdr->sock_index].data_queue);
			if (ff == NULL) { //TODO shoulnd't happen
				PRINT_ERROR("todo error");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
				return;
			}

			daemon_sockets[hdr->sock_index].data_buf -= ff->dataFrame.pduLength;
			PRINT_DEBUG("after: sock_index=%d, data_buf=%d", hdr->sock_index, daemon_sockets[hdr->sock_index].data_buf);

			metadata *params = ff->metaData;
			secure_metadata_readFromElement(params, "recv_stamp", &daemon_sockets[hdr->sock_index].stamp);

			uint32_t control_len = 0;
			uint8_t *control_msg;

			if (msg_controllen < CONTROL_LEN_MAX) {
				if (msg_controllen == 0) {
					msg_controllen = CONTROL_LEN_DEFAULT;
				}

				control_msg = (uint8_t *) secure_malloc(msg_controllen);
				uint8_t *control_pt = control_msg;

				uint32_t cmsg_data_len;
				uint32_t cmsg_space;
				struct cmsghdr *cmsg;
				uint8_t *cmsg_data;

				if (daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP) {
					cmsg_data_len = sizeof(struct timeval);
					cmsg_space = CMSG_SPACE(cmsg_data_len);

					if (control_len + cmsg_space <= msg_controllen) {
						cmsg = (struct cmsghdr *) control_pt;
						cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
						cmsg->cmsg_level = SOL_SOCKET;
						cmsg->cmsg_type = SO_TIMESTAMP;
						PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

						cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
						memcpy(cmsg_data, &daemon_sockets[hdr->sock_index].stamp, cmsg_data_len);

						control_len += cmsg_space;
						control_pt += cmsg_space;
					} else {
						PRINT_ERROR("todo error");
					}
				}

				if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL) {
					int32_t recv_ttl = 255;
					if (metadata_readFromElement(params, "recv_ttl", &recv_ttl) == META_TRUE) {
						cmsg_data_len = sizeof(int32_t);
						cmsg_space = CMSG_SPACE(cmsg_data_len);

						if (control_len + cmsg_space <= msg_controllen) {
							cmsg = (struct cmsghdr *) control_pt;
							cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
							cmsg->cmsg_level = IPPROTO_IP;
							cmsg->cmsg_type = IP_TTL;
							PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x",
									cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

							cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
							*(int32_t *) cmsg_data = recv_ttl;

							control_len += cmsg_space;
							control_pt += cmsg_space;
						} else {
							PRINT_ERROR("todo error");
						}
					} else {
						PRINT_ERROR("no recv_ttl, meta=%p", params);
					}
				}

				PRINT_DEBUG("control_msg=%p, control_pt=%p, diff=%u, control_len=%u, check=%u",
						control_msg, control_pt, control_pt - control_msg, control_len, control_pt - control_msg == control_len);
			} else {
				PRINT_ERROR("todo error");
				//TODO send some error
			}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			struct sockaddr_in addr;
			addr.sin_family = AF_INET;

			uint32_t src_ip;
			if (metadata_readFromElement(params, "recv_src_ip", &src_ip) == META_FALSE) {
				addr.sin_addr.s_addr = 0;
			} else {
				addr.sin_addr.s_addr = htonl(src_ip);
			}

			uint32_t src_port;
			if (metadata_readFromElement(params, "recv_src_port", &src_port) == META_FALSE) {
				addr.sin_port = 0;
			} else {
				addr.sin_port = htons((uint16_t) src_port);
			}

			if (data_len < ff->dataFrame.pduLength) {
				//TODO finish, slice off piece of pdu
			}

			//#######
#ifdef DEBUG
			PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
			uint8_t *temp = (uint8_t *) malloc(ff->dataFrame.pduLength + 1);
			memcpy(temp, ff->dataFrame.pdu, ff->dataFrame.pduLength);
			temp[ff->dataFrame.pduLength] = '\0';
			PRINT_DEBUG("pduLen=%d, pdu='%s'", ff->dataFrame.pduLength, temp);
			free(temp);

			if (0) { //TODO change to func, print_hex
				uint8_t *print_buf = (uint8_t *) secure_malloc(3 * (ff->dataFrame.pduLength) + 1);
				uint8_t *print_pt = print_buf;
				uint8_t *pt = ff->dataFrame.pdu;
				int i;
				for (i = 0; i < ff->dataFrame.pduLength; i++) {
					if (i == 0) {
						sprintf((char *) print_pt, "%02x", *(pt + i));
						print_pt += 2;
					} else if (i % 4 == 0) {
						sprintf((char *) print_pt, ":%02x", *(pt + i));
						print_pt += 3;
					} else {
						sprintf((char *) print_pt, " %02x", *(pt + i));
						print_pt += 3;
					}
				}
				*print_pt = '\0';
				PRINT_DEBUG("buf='%s'", (char *)print_buf);
				free(print_buf);
			}
#endif
			//#######

			int addr_len = sizeof(struct sockaddr_in);

			int msg_len = sizeof(struct nl_daemon_to_wedge) + 3 * sizeof(int) + addr_len + ff->dataFrame.pduLength + control_len;
			uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

			struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
			hdr_ret->call_type = hdr->call_type;
			hdr_ret->call_id = hdr->call_id;
			hdr_ret->call_index = hdr->call_index;
			hdr_ret->ret = ACK;
			hdr_ret->msg = 0; //TODO change to set msg_flags
			uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

			*(int *) pt = addr_len;
			pt += sizeof(int);

			memcpy(pt, &addr, addr_len);
			pt += sizeof(struct sockaddr_in);

			*(int *) pt = ff->dataFrame.pduLength;
			pt += sizeof(int);

			memcpy(pt, ff->dataFrame.pdu, ff->dataFrame.pduLength);
			pt += ff->dataFrame.pduLength;

			*(int *) pt = control_len;
			pt += sizeof(int);

			memcpy(pt, control_msg, control_len);
			pt += control_len;

			if (pt - msg != msg_len) {
				PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

				if (control_msg)
					free(control_msg);
				free(msg);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			} else {
				//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
			}

			if (control_msg)
				free(control_msg);
			free(msg);
			freeFinsFrame(ff);
			return;
		}
	}

	if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
		daemon_calls[hdr->call_index].flags = flags;
		daemon_calls[hdr->call_index].data = data_len;
		daemon_calls[hdr->call_index].ret = msg_controllen;

		struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
		if (call_list_has_space(call_list)) {
			call_list_append(call_list, &daemon_calls[hdr->call_index]);

			if (flags & (MSG_DONTWAIT)) {
				start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
			}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("call_list full");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Insert fail: hdr=%p", hdr);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void release_out_udp(struct nl_wedge_to_daemon *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
	uint32_t host_port = (uint32_t) daemon_sockets[hdr->sock_index].host_port;
	uint32_t rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
	uint32_t rem_port = (uint32_t) daemon_sockets[hdr->sock_index].rem_port;

	daemon_sockets_remove(hdr->sock_index);

	PRINT_DEBUG("");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

	//TODO send FCF to UDP module clearing error buffers of any msgs from this socket
	if (host_port != 0 && 0) { //TODO remove if keep rolling sent_list queue
		metadata *params_req = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(params_req);

		secure_metadata_writeToElement(params_req, "host_ip", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params_req, "host_port", &host_port, META_TYPE_INT32);
		secure_metadata_writeToElement(params_req, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params_req, "rem_port", &rem_port, META_TYPE_INT32);

		if (daemon_fcf_to_switch(UDP_ID, params_req, gen_control_serial_num(), CTRL_EXEC, EXEC_UDP_CLEAR_SENT)) {
			PRINT_DEBUG("Exited, normal: hdr=%p", hdr);
		} else {
			PRINT_ERROR("Exited, fail sending flow msgs: hdr=%p", hdr);
			metadata_destroy(params_req);
		}
	}
}

void poll_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t events) {
	PRINT_DEBUG("Entered: hdr=%p, events=0x%x", hdr, events);

	uint32_t mask = 0;

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL);
		return;
	}
	if (events) { //initial
		PRINT_DEBUG("POLLIN=%x, POLLPRI=%x, POLLOUT=%x, POLLERR=%x, POLLHUP=%x, POLLNVAL=%x, POLLRDNORM=%x, POLLRDBAND=%x, POLLWRNORM=%x, POLLWRBAND=%x",
				(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

		if (events & (POLLERR)) {
			if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR) {
				if (daemon_sockets[hdr->sock_index].error_buf > 0) {
					mask |= POLLERR;
				}
			} else {
				//PRINT_ERROR("todo: POLLERR");
			}
		}

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			if (daemon_sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
			}
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
		}

		if (events & (POLLHUP)) {
			//mask |= POLLHUP; //TODO implement
		}

		uint32_t ret_mask = events & mask;
		PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
		if (ret_mask) {
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			ack_send(hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
		} else {
			struct daemon_call *call = call_create(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index);
			call->data = events;
			call->ret = 0;

			struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
			if (call_list_has_space(call_list)) {
				call_list_append(call_list, call);

				PRINT_DEBUG("");PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				PRINT_ERROR("call_list full");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		}
	} else { //final
		struct daemon_call *call = call_list_find_pid(daemon_sockets[hdr->sock_index].call_list, hdr->call_pid, hdr->call_type, hdr->sock_id);
		if (call) {
			events = call->data;
			mask = call->ret;

			call_list_remove(daemon_sockets[hdr->sock_index].call_list, call);
			if (call->alloc) {
				call_free(call);
			} else {
				PRINT_ERROR("todo error");
			}

			uint32_t ret_mask = events & mask;
			PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
			if (ret_mask) {
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				ack_send(hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
			} else {
				PRINT_DEBUG(
						"POLLIN=%x, POLLPRI=%x, POLLOUT=%x, POLLERR=%x, POLLHUP=%x, POLLNVAL=%x, POLLRDNORM=%x, POLLRDBAND=%x, POLLWRNORM=%x, POLLWRBAND=%x",
						(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

				if (events & (POLLERR)) {
					if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR) {
						if (daemon_sockets[hdr->sock_index].error_buf > 0) {
							mask |= POLLERR;
						}
					} else {
						//PRINT_ERROR("todo: POLLERR");
					}
				}

				if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
					if (daemon_sockets[hdr->sock_index].data_buf > 0) {
						mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
					}
				}

				if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
					mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
				}

				if (events & (POLLHUP)) {
					//mask |= POLLHUP; //TODO implement
				}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				ret_mask = events & mask;
				PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
				ack_send(hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
			}
		} else {
			PRINT_ERROR("final: no corresponding call: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
					hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);

			if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR) {
				if (daemon_sockets[hdr->sock_index].error_buf > 0) {
					mask |= POLLERR;
				}
			} else {
				PRINT_ERROR("todo: POLLERR");
			}

			if (daemon_sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
			}

			mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

			//mask |= POLLHUP; //TODO implement
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("mask=0x%x", mask);
			ack_send(hdr->call_id, hdr->call_index, hdr->call_type, mask);
		}
	}
}

/** .......................................................................*/

void shutdown_out_udp(struct nl_wedge_to_daemon *hdr, int how) {
	PRINT_DEBUG("Entered: hdr=%p, how=%d", hdr, how);

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

void setsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval) {
	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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
			PRINT_ERROR("todo: IP_MTU_DISCOVER");
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
			PRINT_ERROR("todo");
			break;
		default:
			PRINT_ERROR("default=%d", optname);
			break;
		}
		break;
	default:
		break;
	}

	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

	if (optlen > 0)
		free(optval);
}

void getsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval) {
	int len = 0;
	char *val;

	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("Socket Mismatch: sock_index=%d, sock_id=%llu, hdr->sock_id=%llu", hdr->sock_index, daemon_sockets[hdr->sock_index].sock_id, hdr->sock_id);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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
			PRINT_ERROR("todo");
			break;
		default:
			PRINT_ERROR("default=%d", optname);
			break;
		}
		break;
	default:
		break;
	}PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	//if (len) {
	//send msg to wedge
	int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
	uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = hdr->call_type;
	hdr_ret->call_id = hdr->call_id;
	hdr_ret->call_index = hdr->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0;
	uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = len;
	pt += sizeof(int);

	if (len > 0) {
		memcpy(pt, val, len);
		pt += len;
	}

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
		free(msg);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else {

	}
	free(msg);
	//} else {
	//	nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	//}
}

void poll_in_udp(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, flags=%u", call_list, call, flags);

	uint32_t events = call->data;

	PRINT_DEBUG("POLLIN=%x, POLLPRI=%x, POLLOUT=%x, POLLERR=%x, POLLHUP=%x, POLLNVAL=%x, POLLRDNORM=%x, POLLRDBAND=%x, POLLWRNORM=%x, POLLWRBAND=%x",
			(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

	uint32_t mask = 0;

	if (flags & (POLLERR)) {
		if (events & (POLLERR)) {
			mask |= POLLERR;
		}
	}

	if (flags & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
		}
	}

	uint32_t ret_mask = events & mask;
	PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
	if (ret_mask) {
		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge);
		uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = poll_event_call;
		hdr_ret->sock_id = call->sock_id;
		hdr_ret->sock_index = call->sock_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = ret_mask;
		uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			return;
		}

		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: send_wedge error: call=%p", call);
		} else {

		}
		free(msg);

		call->ret |= ret_mask;
	}
}

void recvmsg_in_udp(struct daemon_call_list *call_list, struct daemon_call *call, metadata *params, uint8_t *data, uint32_t data_len, uint32_t addr_ip,
		uint16_t addr_port, uint32_t flags) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, meta=%p, data=%p, len=%u, addr=%u/%u, flags=%u",
			call_list, call, params, data, data_len, addr_ip, addr_port, flags);

	uint32_t call_len = call->data; //buffer size
	uint32_t msg_controllen = call->ret;

	secure_metadata_readFromElement(params, "recv_stamp", &daemon_sockets[call->sock_index].stamp);

	PRINT_DEBUG("stamp=%u.%u", (uint32_t)daemon_sockets[call->sock_index].stamp.tv_sec, (uint32_t)daemon_sockets[call->sock_index].stamp.tv_usec);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(addr_ip);
	addr.sin_port = htons(addr_port);

	if (call_len < data_len) {
		//TODO finish, slice off piece of pdu
	}

	//#######
#ifdef DEBUG
	PRINT_DEBUG("address: %s:%d (%u)", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), addr.sin_addr.s_addr);
	uint8_t *temp = (uint8_t *) malloc(data_len + 1);
	memcpy(temp, data, data_len);
	temp[data_len] = '\0';
	PRINT_DEBUG("pduLen=%d, pdu='%s'", data_len, temp);
	free(temp);

	if (0) { //TODO change to func, print_hex
		uint8_t *print_buf = (uint8_t *) secure_malloc(3 * data_len + 1);
		uint8_t *print_pt = print_buf;
		uint8_t *pt = data;
		int i;
		for (i = 0; i < data_len; i++) {
			if (i == 0) {
				sprintf((char *) print_pt, "%02x", *(pt + i));
				print_pt += 2;
			} else if (i % 4 == 0) {
				sprintf((char *) print_pt, ":%02x", *(pt + i));
				print_pt += 3;
			} else {
				sprintf((char *) print_pt, " %02x", *(pt + i));
				print_pt += 3;
			}
		}
		*print_pt = '\0';
		PRINT_DEBUG("buf='%s'", (char *)print_buf);
		free(print_buf);
	}
#endif
	//#######

	uint32_t control_len = 0;
	uint8_t *control_msg;

	if (msg_controllen < CONTROL_LEN_MAX) {
		if (msg_controllen == 0) {
			msg_controllen = CONTROL_LEN_DEFAULT;
		}

		control_msg = (uint8_t *) secure_malloc(msg_controllen);
		uint8_t *control_pt = control_msg;

		uint32_t cmsg_data_len;
		uint32_t cmsg_space;
		struct cmsghdr *cmsg;
		uint8_t *cmsg_data;

		if (daemon_sockets[call->sock_index].sockopts.FSO_TIMESTAMP) {
			cmsg_data_len = sizeof(struct timeval);
			cmsg_space = CMSG_SPACE(cmsg_data_len);

			if (control_len + cmsg_space <= msg_controllen) {
				cmsg = (struct cmsghdr *) control_pt;
				cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SO_TIMESTAMP;
				PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

				cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
				memcpy(cmsg_data, &daemon_sockets[call->sock_index].stamp, cmsg_data_len);

				control_len += cmsg_space;
				control_pt += cmsg_space;
			} else {
				PRINT_ERROR("todo error");
			}
		}

		if (daemon_sockets[call->sock_index].sockopts.FIP_RECVTTL) {
			int32_t recv_ttl = 255;
			if (metadata_readFromElement(params, "recv_ttl", &recv_ttl) == META_TRUE) {
				cmsg_data_len = sizeof(int32_t);
				cmsg_space = CMSG_SPACE(cmsg_data_len);

				if (control_len + cmsg_space <= msg_controllen) {
					cmsg = (struct cmsghdr *) control_pt;
					cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
					cmsg->cmsg_level = IPPROTO_IP;
					cmsg->cmsg_type = IP_TTL;
					PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

					cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
					*(int32_t *) cmsg_data = recv_ttl;

					control_len += cmsg_space;
					control_pt += cmsg_space;
				} else {
					PRINT_ERROR("todo error");
				}
			} else {
				PRINT_ERROR("no recv_ttl, meta=%p", params);
			}
		}

		if (daemon_sockets[call->sock_index].sockopts.FIP_RECVERR && (flags & MSG_ERRQUEUE)) { //TODO remove?
			uint32_t err_src_ip;
			uint32_t icmp_type;
			secure_metadata_readFromElement(params, "recv_src_ip", &err_src_ip); //add port?
			secure_metadata_readFromElement(params, "recv_icmp_type", &icmp_type);

			cmsg_data_len = sizeof(struct errhdr);
			cmsg_space = CMSG_SPACE(cmsg_data_len);

			if (control_len + cmsg_space <= msg_controllen) {
				cmsg = (struct cmsghdr *) control_pt;
				cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_RECVERR;
				PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

				struct errhdr *err = (struct errhdr *) CMSG_DATA(cmsg);
				err->ee.ee_errno = EHOSTUNREACH; //113
				err->ee.ee_origin = SO_EE_ORIGIN_ICMP; //2
				err->ee.ee_type = icmp_type; //11

				err->ee.ee_code = 0;
				err->ee.ee_pad = 0;
				err->ee.ee_info = 0;
				err->ee.ee_data = 0;

				err->ee.ee_code = 0;
				err->ee.ee_pad = 0;
				err->ee.ee_info = 0;
				err->ee.ee_data = 0;

				err->offender.sin_family = AF_INET;
				err->offender.sin_addr.s_addr = htonl(err_src_ip);
				err->offender.sin_port = htons(0);

				control_len += cmsg_space;
				control_pt += cmsg_space;
			} else {
				PRINT_ERROR("todo error");
			}
		}

		PRINT_DEBUG("control_msg=%p, control_pt=%p, diff=%u, control_len=%u, check=%u",
				control_msg, control_pt, control_pt - control_msg, control_len, control_pt - control_msg == control_len);
	} else {
		PRINT_ERROR("todo error");
		//TODO send some error
	}

	int addr_len = sizeof(struct sockaddr_in);

	int msg_len = sizeof(struct nl_daemon_to_wedge) + 3 * sizeof(int) + addr_len + data_len + control_len;
	uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = call->call_type;
	hdr_ret->call_id = call->call_id;
	hdr_ret->call_index = call->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = flags;
	uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(int *) pt = addr_len;
	pt += sizeof(int);

	memcpy(pt, &addr, addr_len);
	pt += sizeof(struct sockaddr_in);

	*(int *) pt = data_len;
	pt += sizeof(int);

	memcpy(pt, data, data_len);
	pt += data_len;

	*(int *) pt = control_len;
	pt += sizeof(int);

	memcpy(pt, control_msg, control_len);
	pt += control_len;

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
		if (control_msg)
			free(control_msg);
		free(msg);

		PRINT_DEBUG("Exited: write error: call_list=%p, call=%p", call_list, call);
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		return;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: send_wedge error: call_list=%p, call=%p", call_list, call);
		nack_send(call->call_id, call->call_index, call->call_type, 1);
	} else {
		PRINT_DEBUG("Exited: Normal: call_list=%p, call=%p", call_list, call);
	}
	if (control_msg)
		free(control_msg);
	free(msg);

	call_list_remove(call_list, call);
	daemon_calls_remove(call->call_index);
}

void daemon_udp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: ff=%p, src_ip=%u, dst_ip=%u", ff, src_ip, dst_ip);

	uint32_t src_port;
	uint32_t dst_port;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "recv_src_port", &src_port);
	secure_metadata_readFromElement(params, "recv_dst_port", &dst_port);

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	//TODO move to interface?
	//secure_metadata_writeToElement(params, "stamp", &current, META_TYPE_INT64);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int sock_index = daemon_sockets_match((uint16_t) dst_port, dst_ip, IPPROTO_UDP); //TODO change for multicast
	if (sock_index == -1) {
		PRINT_ERROR("No match, freeing: ff=%p, src=%u/%u, dst=%u/%u", ff, src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port); //TODO change back  to PRINT_ERROR
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		freeFinsFrame(ff);
	} else {
		PRINT_DEBUG( "Matched: sock_id=%llu, sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port, daemon_sockets[sock_index].protocol);

		//TODO check if this datagram comes from the address this socket has been previously connected to it (Only if the socket is already connected to certain address)

		struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

		struct daemon_call *call = call_list->front;
		while (call) {
			if (call->call_type == poll_call) { //signal all poll calls in list
				poll_in_udp(call_list, call, POLLIN);
			}
			call = call->next;
		}

		call = call_list->front;
		while (call) {
			if (call->call_type == recvmsg_call && !(call->flags & (MSG_ERRQUEUE))) { //signal first recvmsg for data
				recvmsg_in_udp(call_list, call, params, ff->dataFrame.pdu, ff->dataFrame.pduLength, src_ip, (uint16_t) src_port, 0);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);
				return;
			}
			call = call->next;
		}

		if (write_queue(ff, daemon_sockets[sock_index].data_queue)) {
			daemon_sockets[sock_index].data_buf += ff->dataFrame.pduLength;

			int data_buf = daemon_sockets[sock_index].data_buf;
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("stored, sock_index=%d, ff=%p, meta=%p, data_buf=%d", sock_index, ff, params, data_buf);
		} else {
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			PRINT_ERROR("Write queue error: ff=%p", ff);
			freeFinsFrame(ff);
		}
	}
}

void daemon_udp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: ff=%p, src_ip=%u, dst_ip=%u", ff, src_ip, dst_ip);

	uint32_t src_port;
	uint32_t dst_port;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_src_port", &src_port);
	secure_metadata_readFromElement(params, "send_dst_port", &dst_port);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int sock_index = daemon_sockets_match((uint16_t) src_port, src_ip, IPPROTO_UDP); //TODO change for multicast
	if (sock_index == -1) {
		PRINT_ERROR("No match, freeing: ff=%p, src=%u/%u, dst=%u/%u", ff, src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		freeFinsFrame(ff);
	} else {
		PRINT_DEBUG( "Matched: sock_id=%llu, sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port, daemon_sockets[sock_index].protocol);

		if (daemon_sockets[sock_index].sockopts.FIP_RECVERR) {
			struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

			struct daemon_call *call = call_list->front;
			while (call) {
				if (call->call_type == poll_call) { //signal all poll calls in list
					poll_in_udp(call_list, call, POLLERR);
				}
				call = call->next;
			}

			call = call_list->front;
			while (call) {
				if (call->call_type == recvmsg_call && (call->flags & (MSG_ERRQUEUE))) { //signal first recvmsg for data
					recvmsg_in_udp(call_list, call, params, ff->ctrlFrame.data, ff->ctrlFrame.data_len, src_ip, (uint16_t) src_port, MSG_ERRQUEUE);
					PRINT_DEBUG("post$$$$$$$$$$$$$$$");
					sem_post(&daemon_sockets_sem);
					return;
				}
				call = call->next;
			}

			if (write_queue(ff, daemon_sockets[sock_index].error_queue)) {
				daemon_sockets[sock_index].error_buf++;

				int error_buf = daemon_sockets[sock_index].error_buf;
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				PRINT_DEBUG("stored, sock_index=%d, ff=%p, meta=%p, error_buf=%d", sock_index, ff, params, error_buf);
			} else {
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				PRINT_ERROR("Write queue error: ff=%p", ff);
				freeFinsFrame(ff);
			}
		} else {
			PRINT_ERROR("todo");
		}
	}
}

void recvmsg_timeout_udp(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	call_list_remove(daemon_sockets[call->sock_index].call_list, call);

	switch (daemon_sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //nack EAGAIN or EWOULDBLOCK
		break;
	case SS_CONNECTING:
		nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //nack EAGAIN or EWOULDBLOCK
		break;
	default:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	}

	daemon_calls_remove(call->call_index);
}
