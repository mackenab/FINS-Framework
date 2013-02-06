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

extern struct daemon_call daemon_calls[MAX_CALLS];
extern struct daemon_call_list *expired_call_list;

void socket_out_tcp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol) {
	PRINT_DEBUG("Entered: hdr=%p, domain=%d, type=%d, proto=%d", hdr, domain, type, protocol);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int ret = daemon_sockets_insert(hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("sock_index=%d, ret=%d", hdr->sock_index, ret);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	if (ret) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void bind_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr) {
	uint32_t host_ip;
	uint16_t host_port;

	PRINT_DEBUG("Entered: hdr=%p", hdr);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family=%d", addr->sin_family);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	host_ip = ntohl(addr->sin_addr.s_addr);
	host_port = ntohs(addr->sin_port);

	PRINT_DEBUG("bind address: host=%u (%s):%d, host_IP_netformat=%u", host_ip, inet_ntoa(addr->sin_addr), host_port, htonl(host_ip));

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	//TODO check if already bound, return already bound error

	/** check if the same port and address have been both used earlier or not
	 * it returns (-1) in case they already exist, so that we should not reuse them
	 * */
	if (!daemon_sockets_check_ports(host_port, host_ip) && !daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR) { //TODO change, need to check if in TIME_WAIT state
		PRINT_ERROR("this port is not free");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
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

void listen_out_tcp(struct nl_wedge_to_daemon *hdr, int backlog) {
	uint32_t host_ip;
	uint32_t host_port;

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
	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	uint32_t state = daemon_sockets[hdr->sock_index].state;
	daemon_sockets[hdr->sock_index].listening = 1;
	daemon_sockets[hdr->sock_index].backlog = backlog;

	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	PRINT_DEBUG("");
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	PRINT_DEBUG("listen address: host=%u/%u", host_ip, host_port);

	/** Keep all ports and addresses in host order until later  action taken
	 * in IPv4 module
	 *  */
	/** addresses are in host format given that there are by default already filled
	 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */
	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	secure_metadata_writeToElement(params, "backlog", &backlog, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);

	if (daemon_fcf_to_switch(TCP_ID, params, gen_control_serial_num(), CTRL_EXEC, EXEC_TCP_LISTEN)) {
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(params);
	}
}

void connect_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags) {
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;

	PRINT_DEBUG("Entered: hdr=%p, flags=%d", hdr, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

	if (addr->sin_family != AF_INET) {
		PRINT_ERROR("Wrong address family");
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, EAFNOSUPPORT);
		free(addr);
		return;
	}

	/** TODO fix host port below, it is not initialized with any variable !!! */
	/** the check below is to make sure that the port is not previously allocated */
	rem_ip = ntohl((addr->sin_addr).s_addr);
	rem_port = (uint16_t) ntohs(addr->sin_port);

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
	PRINT_DEBUG("address: rem=%u (%s):%u, rem_IP_netformat=%u", rem_ip, inet_ntoa(addr->sin_addr), rem_port, htonl(rem_ip));

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket removed/changed");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, ENOTSOCK); //TODO check?
		free(addr);
		return;
	}

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	/**
	 * NOTICE THAT the relation between the host and the destined address is many to one.
	 * more than one local socket maybe connected to the same destined address
	 */
	switch (daemon_sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		if (daemon_sockets[hdr->sock_index].error_call == hdr->call_type) {
			uint32_t error_msg = daemon_sockets[hdr->sock_index].error_msg;

			daemon_sockets[hdr->sock_index].error_call = 0; //TODO remove?
			daemon_sockets[hdr->sock_index].error_msg = 0;
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, error_msg);
			return;
		}
		break;
	case SS_CONNECTING:
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].flags = flags;

				start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("todo");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		}
		free(addr);
		return;
	case SS_CONNECTED:
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, EISCONN);
		free(addr);
		return;
	default:
		PRINT_ERROR("todo");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		free(addr);
		return;
	}

	/**TODO check if the port is free for binding or previously allocated
	 * Current code assume that the port is authorized to be accessed
	 * and also available
	 * */

	//if statements make sure socket is in SS_UNCONNECTED
	daemon_sockets[hdr->sock_index].state = SS_CONNECTING;
	daemon_sockets[hdr->sock_index].listening = 0;
	daemon_sockets[hdr->sock_index].rem_ip = rem_ip;
	daemon_sockets[hdr->sock_index].rem_port = rem_port;
	uint32_t state = daemon_sockets[hdr->sock_index].state;

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
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	secure_metadata_writeToElement(params, "flags", &flags, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, EXEC_TCP_CONNECT)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;

			if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
				start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
			}
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(params);
	}

	free(addr);
}

void accept_out_tcp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags) {
	uint32_t host_ip;
	uint32_t host_port;

	PRINT_DEBUG("Entered: hdr=%p, sock_id_new=%llu, sock_index_new=%d, flags=%d", hdr, sock_id_new, sock_index_new, flags);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket removed/changed");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}
	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	if (!daemon_sockets[hdr->sock_index].listening) {
		PRINT_ERROR("socket not listening");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	uint32_t state = daemon_sockets[hdr->sock_index].state;
	switch (state) {
	case SS_UNCONNECTED:
		//TODO check daemon_sockets[hdr->sock_index].sock_id_new / sock_index_new, such that if nonblocking & expired accept accomplished
		//TODO check daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		break;
	case SS_CONNECTING:
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].flags = flags;

				daemon_calls[hdr->call_index].sock_id_new = sock_id_new; //TODO redo so not in call? or in struct inside call as void *pt;
				daemon_calls[hdr->call_index].sock_index_new = sock_index_new;

				start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("todo");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		}
		return;
	default:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;

	PRINT_DEBUG("accept address: host=%u/%u", host_ip, host_port);

	//TODO process flags?

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	secure_metadata_writeToElement(params, "flags", &flags, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, EXEC_TCP_ACCEPT)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;

			daemon_calls[hdr->call_index].sock_id_new = sock_id_new; //TODO redo so not in call? or in struct inside call as void *pt;
			daemon_calls[hdr->call_index].sock_index_new = sock_index_new;

			if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
				start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
			}

			daemon_sockets[hdr->sock_index].state = SS_CONNECTING;

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(params);
	}
}

void getname_out_tcp(struct nl_wedge_to_daemon *hdr, int peer) {
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

	PRINT_DEBUG("");
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
	}
	PRINT_DEBUG("addr=(%s/%d) netw=%u", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), addr->sin_addr.s_addr);

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
		free(addr);

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

void ioctl_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, uint8_t *buf, ssize_t buf_len) {
	uint32_t len;
	int msg_len;
	uint8_t *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	uint8_t *pt;

	PRINT_DEBUG("Entered: hdr=%p, cmd=%d, len=%d", hdr, cmd, buf_len);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_ERROR("socket descriptor not found into daemon sockets");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	len = daemon_sockets[hdr->sock_index].data_buf;

	PRINT_DEBUG("");
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

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

		*(uint32_t *) pt = len;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
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
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (msg_len) {
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		} else {

		}
		free(msg);
	} else {
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void sendmsg_out_tcp(struct nl_wedge_to_daemon *hdr, uint8_t *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *addr, int addr_len) {
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t dst_ip;
	uint32_t dst_port;

	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, flags=%d, addr_len=%d", hdr, data_len, flags, addr_len);
	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

	if (data_len == 0) { //TODO check this prob wrong!
		PRINT_ERROR("todo/redo");
		PRINT_DEBUG("data_len == 0, send ACK");
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);

		if (addr)
			free(addr);
		return;
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

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	switch (daemon_sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		//TODO buffer data & send ACK

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

		free(data);
		if (addr)
			free(addr);
		return;
	case SS_CONNECTING:
	case SS_CONNECTED:
		break;
	case SS_DISCONNECTING:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

		free(data);
		if (addr)
			free(addr);
		return;
	default:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);

		free(data);
		if (addr)
			free(addr);
		return;
	}

	dst_port = daemon_sockets[hdr->sock_index].rem_port;
	dst_ip = daemon_sockets[hdr->sock_index].rem_ip;

	/**
	 * Default current host port is supposed to be randomly selected from the range found in
	 * /proc/sys/net/ipv4/ip_local_port_range
	 * default range in Ubuntu is 32768 - 61000
	 * The value has been chosen randomly when the socket firstly inserted into the daemonsockets
	 * check insert_daemonSocket(processid, sockfd, fakeID, type, protocol);
	 */
	host_port = daemon_sockets[hdr->sock_index].host_port;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;

	PRINT_DEBUG("host=%u/%u, dst=%u/%u", host_ip, host_port, dst_ip, dst_port);

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	secure_metadata_writeToElement(params, "flags", &flags, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "rem_ip", &dst_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "rem_port", &dst_port, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	secure_metadata_writeToElement(params, "serial_num", &serial_num, META_TYPE_INT32);

	if (daemon_fdf_to_switch(TCP_ID, data, data_len, params)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;
			daemon_calls[hdr->call_index].flags = flags;
			daemon_calls[hdr->call_index].data = data_len;

			if (flags & (MSG_DONTWAIT)) {
				//start_timer(daemon_calls[hdr->call_index].to_fd, DAEMON_BLOCK_DEFAULT);
			}
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

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
void recvmsg_out_tcp(struct nl_wedge_to_daemon *hdr, int data_len, uint32_t msg_controllen, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, msg_controllen=%u, flags=%d", hdr, data_len, msg_controllen, flags);

	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

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

	switch (daemon_sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		//TODO buffer data & send ACK

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	case SS_CONNECTING:
	case SS_CONNECTED:
		break;
	case SS_DISCONNECTING:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	default:
		PRINT_ERROR("todo error");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	if (flags & MSG_ERRQUEUE) {
		//TODO no error queue for TCP
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

			uint32_t state = daemon_sockets[hdr->sock_index].state;
			uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
			uint32_t host_port = daemon_sockets[hdr->sock_index].host_port;
			uint32_t rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
			uint32_t rem_port = daemon_sockets[hdr->sock_index].rem_port;

			metadata *params = ff->metaData;
			secure_metadata_readFromElement(params, "recv_stamp", &daemon_sockets[hdr->sock_index].stamp);

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(rem_ip);
			addr.sin_port = htons((uint16_t) rem_port);

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

				if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVTTL && 0) { //TODO find out how tcp does this
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

				if (daemon_sockets[hdr->sock_index].sockopts.FIP_RECVERR && (flags & MSG_ERRQUEUE)) { //TODO find out how tcp does this
					//TODO tcp has no error queue
				}

				PRINT_DEBUG("control_msg=%p, control_pt=%p, diff=%u, control_len=%u, check=%u",
						control_msg, control_pt, control_pt - control_msg, control_len, control_pt - control_msg == control_len);
			} else {
				PRINT_ERROR("todo error");
				//TODO send some error
			}

			int addr_len = sizeof(struct sockaddr_in);

			int msg_len = sizeof(struct nl_daemon_to_wedge) + 3 * sizeof(int) + addr_len + ff->dataFrame.pduLength + control_len;
			uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

			struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
			hdr_ret->call_type = hdr->call_type;
			hdr_ret->call_id = hdr->call_id;
			hdr_ret->call_index = hdr->call_index;
			hdr_ret->ret = ACK;
			hdr_ret->msg = flags; //TODO change to set msg_flags
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

				free(msg);
				freeFinsFrame(ff);
				return;
			}

			PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
			if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
				PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			} else {
				//TODO send size back to TCP handlers
				//if (state > SS_UNCONNECTED) { //shouldn't be able to get data if not connected
				PRINT_DEBUG("recvfrom address: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
				//} else {
				//	PRINT_DEBUG("recvfrom address: host=%u/%d", host_ip, host_port);
				//}

				metadata *params_resp = (metadata *) secure_malloc(sizeof(metadata));
				metadata_create(params_resp);

				uint32_t value = ff->dataFrame.pduLength;
				secure_metadata_writeToElement(params_resp, "value", &value, META_TYPE_INT32);

				secure_metadata_writeToElement(params_resp, "state", &state, META_TYPE_INT32);
				secure_metadata_writeToElement(params_resp, "host_ip", &host_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params_resp, "host_port", &host_port, META_TYPE_INT32);
				//if (state > SS_UNCONNECTED) {
				secure_metadata_writeToElement(params_resp, "rem_ip", &rem_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params_resp, "rem_port", &rem_port, META_TYPE_INT32);
				//}

				if (daemon_fcf_to_switch(TCP_ID, params_resp, gen_control_serial_num(), CTRL_SET_PARAM, SET_PARAM_TCP_HOST_WINDOW)) {
					PRINT_DEBUG("Exited, normal: hdr=%p", hdr);
				} else {
					PRINT_ERROR("Exited, fail sending flow msgs: hdr=%p", hdr);
					metadata_destroy(params_resp);
				}
			}

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
			}
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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

void release_out_tcp(struct nl_wedge_to_daemon *hdr) { //TODO finish
	uint32_t state;
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;

	PRINT_DEBUG("hdr=%p", hdr);
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

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
		rem_port = daemon_sockets[hdr->sock_index].rem_port;
	}

	//TODO process flags?

	if (state > SS_UNCONNECTED) {
		PRINT_DEBUG("release address: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
	} else {
		PRINT_DEBUG("release address: host=%u/%u", host_ip, host_port);
	}

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	//secure_metadata_writeToElement(params, "flags", &flags, META_TYPE_INT32);

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
	if (state > SS_UNCONNECTED) {
		secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
	}

	uint32_t serial_num = gen_control_serial_num();
	uint32_t exec_call = (state > SS_UNCONNECTED) ? EXEC_TCP_CLOSE : EXEC_TCP_CLOSE_STUB;
	PRINT_DEBUG("serial_num=%u, state=%u, exec_call=%u", serial_num, state, exec_call);

	if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, exec_call)) {
		if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			daemon_calls[hdr->call_index].serial_num = serial_num;

			PRINT_DEBUG("");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(params);
	}
}

void poll_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t events) {
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
			//if (daemon_sockets[hdr->sock_index].error_buf > 0) {mask |= POLLERR;}
		}

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			if (daemon_sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
			}
		}

		if (events & (POLLHUP)) {
			//mask |= POLLHUP; //TODO implement
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

			uint32_t state = daemon_sockets[hdr->sock_index].state;
			uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
			uint32_t host_port = daemon_sockets[hdr->sock_index].host_port;
			uint32_t rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
			uint32_t rem_port = daemon_sockets[hdr->sock_index].rem_port;

			if (state > SS_UNCONNECTED) {
				PRINT_DEBUG("poll address: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
			} else {
				PRINT_DEBUG("poll address: host=%u/%u", host_ip, host_port);
			}

			metadata *params = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(params);

			uint32_t initial = 1;
			secure_metadata_writeToElement(params, "initial", &initial, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "flags", &events, META_TYPE_INT32);

			secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
			if (state > SS_UNCONNECTED) {
				secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
			}

			uint32_t serial_num = gen_control_serial_num();
			if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, EXEC_TCP_POLL)) {
				if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
					daemon_calls[hdr->call_index].serial_num = serial_num;
					daemon_calls[hdr->call_index].data = events;
					daemon_calls[hdr->call_index].flags = initial; //is initial
					daemon_calls[hdr->call_index].ret = mask;

					struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
					if (call_list_has_space(call_list)) {
						call_list_append(call_list, &daemon_calls[hdr->call_index]);

						PRINT_DEBUG("");
						PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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
			} else {
				PRINT_ERROR("Exited: failed to send ff");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
				metadata_destroy(params);
			}
			return;
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

				PRINT_DEBUG("");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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
					//if (daemon_sockets[hdr->sock_index].error_buf > 0) {mask |= POLLERR;}
				}

				if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
					if (daemon_sockets[hdr->sock_index].data_buf > 0) {
						mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
					}
				}

				if (events & (POLLHUP)) {
					//mask |= POLLHUP; //TODO implement
				}

				if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
					PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
							daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

					uint32_t state = daemon_sockets[hdr->sock_index].state;
					uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
					uint32_t host_port = daemon_sockets[hdr->sock_index].host_port;
					uint32_t rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
					uint32_t rem_port = daemon_sockets[hdr->sock_index].rem_port;

					if (state > SS_UNCONNECTED) {
						PRINT_DEBUG("poll address: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
					} else {
						PRINT_DEBUG("poll address: host=%u/%u", host_ip, host_port);
					}

					metadata *params = (metadata *) secure_malloc(sizeof(metadata));
					metadata_create(params);

					uint32_t initial = 0;
					secure_metadata_writeToElement(params, "initial", &initial, META_TYPE_INT32);
					secure_metadata_writeToElement(params, "flags", &events, META_TYPE_INT32);

					secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
					secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
					secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
					if (state > SS_UNCONNECTED) {
						secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
						secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
					}

					uint32_t serial_num = gen_control_serial_num();
					if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, EXEC_TCP_POLL)) {
						if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
							daemon_calls[hdr->call_index].serial_num = serial_num;
							daemon_calls[hdr->call_index].data = events;
							daemon_calls[hdr->call_index].flags = initial; //is final
							daemon_calls[hdr->call_index].ret = mask;

							struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
							if (call_list_has_space(call_list)) {
								call_list_append(call_list, &daemon_calls[hdr->call_index]);

								PRINT_DEBUG("");
								PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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
					} else {
						PRINT_ERROR("Exited: failed to send ff");
						PRINT_DEBUG("post$$$$$$$$$$$$$$$");
						sem_post(&daemon_sockets_sem);

						nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
						metadata_destroy(params);
					}
					return;
				}
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				ret_mask = events & mask;
				PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
				ack_send(hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
			}
		} else {
			PRINT_ERROR("final: no corresponding call: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
					hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);

			//if (daemon_sockets[hdr->sock_index].error_buf > 0) {mask |= POLLERR;}

			if (daemon_sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
			}

			//mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

			//mask |= POLLHUP; //TODO implement

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

			uint32_t state = daemon_sockets[hdr->sock_index].state;
			uint32_t host_ip = daemon_sockets[hdr->sock_index].host_ip;
			uint32_t host_port = daemon_sockets[hdr->sock_index].host_port;
			uint32_t rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
			uint32_t rem_port = daemon_sockets[hdr->sock_index].rem_port;

			if (state > SS_UNCONNECTED) {
				PRINT_DEBUG("poll address: host=%u/%u, rem=%u/%u", host_ip, host_port, rem_ip, rem_port);
			} else {
				PRINT_DEBUG("poll address: host=%u/%u", host_ip, host_port);
			}

			metadata *params = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(params);

			uint32_t initial = 0;
			secure_metadata_writeToElement(params, "initial", &initial, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "flags", &events, META_TYPE_INT32);

			secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
			if (state > SS_UNCONNECTED) {
				secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
			}

			uint32_t serial_num = gen_control_serial_num();
			if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_EXEC, EXEC_TCP_POLL)) {
				if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
					daemon_calls[hdr->call_index].serial_num = serial_num;
					daemon_calls[hdr->call_index].data = events;
					daemon_calls[hdr->call_index].flags = initial; //is final
					daemon_calls[hdr->call_index].ret = mask;

					struct daemon_call_list *call_list = daemon_sockets[hdr->sock_index].call_list;
					if (call_list_has_space(call_list)) {
						call_list_append(call_list, &daemon_calls[hdr->call_index]);

						PRINT_DEBUG("");
						PRINT_DEBUG("post$$$$$$$$$$$$$$$");
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
			} else {
				PRINT_ERROR("Exited: failed to send ff");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
				metadata_destroy(params);
			}
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
	PRINT_DEBUG("Entered: hdr=%p, how=%d", hdr, how);

	ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void getsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval) {
	uint32_t state;
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;

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

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
		rem_port = daemon_sockets[hdr->sock_index].rem_port;
	}

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	int send_dst = -1;
	int len = 0;
	uint8_t *val = NULL;

	uint32_t param_id = optname;

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
	if (state > SS_UNCONNECTED) {
		secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
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
		break;
	case SO_SNDBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_SNDBUFFORCE:
		break;
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_RCVBUFFORCE:
		break;
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
		break;
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
		break;
	case SO_PASSCRED:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &daemon_sockets[hdr->sock_index].sockopts.FSO_PASSCRED; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_PEERCRED:
		//TODO trickier
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
		PRINT_ERROR("default=%d", optname);
		break;
	}

	if (send_dst == -1) {
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		PRINT_ERROR("send_dst == -1");

		metadata_destroy(params);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else if (send_dst == 0) {
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);

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
			PRINT_DEBUG("Exited:, No fdf: hdr=%p", hdr);
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
	} else {
		uint32_t serial_num = gen_control_serial_num();
		if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_READ_PARAM, param_id)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].serial_num = serial_num;
				daemon_calls[hdr->call_index].data = optname;

				PRINT_DEBUG("");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("Exited: failed to send ff");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			metadata_destroy(params);
		}
	}
}

void setsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval) {
	uint32_t state;
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip;
	uint32_t rem_port;

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

	PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
			daemon_sockets[hdr->sock_index].sock_id, hdr->sock_index, daemon_sockets[hdr->sock_index].state, daemon_sockets[hdr->sock_index].host_ip, daemon_sockets[hdr->sock_index].host_port, daemon_sockets[hdr->sock_index].rem_ip, daemon_sockets[hdr->sock_index].rem_port);

	state = daemon_sockets[hdr->sock_index].state;
	host_ip = daemon_sockets[hdr->sock_index].host_ip;
	host_port = daemon_sockets[hdr->sock_index].host_port;
	if (state > SS_UNCONNECTED) {
		rem_ip = daemon_sockets[hdr->sock_index].rem_ip;
		rem_port = daemon_sockets[hdr->sock_index].rem_port;
	}

	metadata *params = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(params);

	int send_dst = -1;
	//int len = 0;
	//uint8_t *val = NULL;

	uint32_t param_id = optname;

	secure_metadata_writeToElement(params, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_ip", &host_ip, META_TYPE_INT32);
	secure_metadata_writeToElement(params, "host_port", &host_port, META_TYPE_INT32);
	if (state > SS_UNCONNECTED) {
		secure_metadata_writeToElement(params, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params, "rem_port", &rem_port, META_TYPE_INT32);
	}

	switch (level) {
	case SOL_IP:
		PRINT_ERROR("todo error");
		break;
	case SOL_RAW:
		PRINT_ERROR("todo error");
		break;
	case SOL_TCP:
		switch (optname) {
		case TCP_NODELAY:
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

				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_DEBUG, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_REUSEADDR:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR = *(int *) optval;
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR, META_TYPE_INT32);
				send_dst = 1;
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
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_SNDBUF, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_SNDBUFFORCE:
			break;
		case SO_RCVBUF:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF = *(int *) optval;
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_RCVBUF, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_RCVBUFFORCE:
			break;
		case SO_KEEPALIVE:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE = *(int *) optval;
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_OOBINLINE:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_OOBINLINE = *(int *) optval;
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_OOBINLINE, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_NO_CHECK:
			break;
		case SO_PRIORITY:
			if (optlen >= sizeof(int)) {
				daemon_sockets[hdr->sock_index].sockopts.FSO_PRIORITY = *(int *) optval;
				secure_metadata_writeToElement(params, "value", &daemon_sockets[hdr->sock_index].sockopts.FSO_PRIORITY, META_TYPE_INT32);
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
			PRINT_ERROR("default=%d", optname);
			break;
		}
		break;
	default:
		break;
	}

	if (send_dst == -1) {
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		PRINT_ERROR("Error");

		metadata_destroy(params);
		nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else if (send_dst == 0) {
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		metadata_destroy(params);
		ack_send(hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		uint32_t serial_num = gen_control_serial_num();
		if (daemon_fcf_to_switch(TCP_ID, params, serial_num, CTRL_SET_PARAM, param_id)) {
			if (daemon_calls_insert(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				daemon_calls[hdr->call_index].serial_num = serial_num;

				PRINT_DEBUG("");
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&daemon_sockets_sem);

				nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("Exited: failed to send ff");
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(hdr->call_id, hdr->call_index, hdr->call_type, 1);
			metadata_destroy(params);
		}
	}
}

void connect_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, flags);

	if (ff->ctrlFrame.param_id != EXEC_TCP_CONNECT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	if (ff->ctrlFrame.ret_val) {
		daemon_sockets[sock_index].state = SS_CONNECTED;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		ack_send(call_id, call_index, call_type, 0);
	} else {
		daemon_sockets[sock_index].state = SS_UNCONNECTED;
		daemon_sockets[sock_index].error_call = call_type;
		daemon_sockets[sock_index].error_msg = ret_msg;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	freeFinsFrame(ff);
}

void accept_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint64_t sock_id_new,
		int sock_index_new, uint32_t flags) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, sock_id_new=%llu, sock_index_new=%d, flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, sock_id_new, sock_index_new, flags);

	if (ff->ctrlFrame.param_id != EXEC_TCP_ACCEPT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	uint32_t rem_ip;
	uint32_t rem_port;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);
	secure_metadata_readFromElement(params, "rem_ip", &rem_ip);
	secure_metadata_readFromElement(params, "rem_port", &rem_port);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[sock_index].sock_id != sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	if (ff->ctrlFrame.ret_val) {
		if (daemon_sockets_insert(sock_id_new, sock_index_new, daemon_sockets[sock_index].type, daemon_sockets[sock_index].protocol)) {
			daemon_sockets[sock_index_new].state = SS_CONNECTED;
			daemon_sockets[sock_index_new].host_ip = daemon_sockets[sock_index].host_ip;
			daemon_sockets[sock_index_new].host_port = daemon_sockets[sock_index].host_port;
			daemon_sockets[sock_index_new].rem_ip = rem_ip;
			daemon_sockets[sock_index_new].rem_port = (uint16_t) rem_port;

			PRINT_DEBUG("Accept socket created: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[sock_index_new].sock_id, sock_index_new, daemon_sockets[sock_index_new].state, daemon_sockets[sock_index_new].host_ip, daemon_sockets[sock_index_new].host_port, daemon_sockets[sock_index_new].rem_ip, daemon_sockets[sock_index_new].rem_port);

			daemon_sockets[sock_index].state = SS_UNCONNECTED;
			daemon_sockets[sock_index].sock_id_new = -1;
			daemon_sockets[sock_index].sock_index_new = -1;

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			ack_send(call_id, call_index, call_type, 0);
		} else {
			PRINT_ERROR("Exited: insert failed: ff=%p", ff);

			daemon_sockets[sock_index].state = SS_UNCONNECTED;
			daemon_sockets[sock_index].error_call = call_type;
			daemon_sockets[sock_index].error_msg = 0; //TODO fill in special value?

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port);

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(call_id, call_index, call_type, 1);
		}
	} else {
		daemon_sockets[sock_index].state = SS_UNCONNECTED;
		daemon_sockets[sock_index].error_call = call_type;
		daemon_sockets[sock_index].error_msg = ret_msg;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].state, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		nack_send(call_id, call_index, call_type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	freeFinsFrame(ff);
}

void sendmsg_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags) { //TODO remove data? not needed
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, flags);

	if (ff->ctrlFrame.param_id != EXEC_TCP_SEND) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);

	if (ff->ctrlFrame.ret_val) {
		ack_send(call_id, call_index, call_type, ret_msg);
	} else {
		nack_send(call_id, call_index, call_type, ret_msg);
	}

	freeFinsFrame(ff);
}

void getsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, data);

	if ((int) ff->ctrlFrame.param_id != (int) data || ff->ctrlFrame.ret_val == 0) { //TODO remove (int)'s?
		PRINT_DEBUG("Exiting, meta errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
	} else {

		//################ //TODO switch by param_id, convert into val/len
		int len = 0;
		uint8_t *val = NULL;
		//################

		//send msg to wedge
		int msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + (len > 0 ? len : 0);
		uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

		struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = call_type;
		hdr_ret->call_id = call_id;
		hdr_ret->call_index = call_index;
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

			nack_send(call_id, call_index, call_type, 1);
			freeFinsFrame(ff);
			return;
		}

		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
		if (send_wedge(nl_sockfd, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: ff=%p", ff);
			nack_send(call_id, call_index, call_type, 1);
		} else {
			PRINT_DEBUG("Exited: normal: ff=%p", ff);
		}
		free(msg);
	}

	freeFinsFrame(ff);
}

void setsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call_id, call_index, call_type, sock_id, sock_index, data);

	if ((int) ff->ctrlFrame.param_id != (int) data || ff->ctrlFrame.ret_val == 0) { //TODO remove (int)'s?
		PRINT_DEBUG("Exited: meta errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
	} else {
		PRINT_DEBUG("Exited: normal: ff=%p", ff);
		ack_send(call_id, call_index, call_type, 0);
	}

	freeFinsFrame(ff);
}

void release_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			ff, call_id, call_index, call_type, sock_id, sock_index);

	if ((ff->ctrlFrame.param_id != EXEC_TCP_CLOSE && ff->ctrlFrame.param_id != EXEC_TCP_CLOSE_STUB) || ff->ctrlFrame.ret_val == 0) {
		PRINT_DEBUG("Exiting, NACK: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
	} else {
		PRINT_DEBUG("");
		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&daemon_sockets_sem);
		if (daemon_sockets[sock_index].sock_id != sock_id) {
			PRINT_ERROR("Exited: socket closed: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			nack_send(call_id, call_index, call_type, 1);
		} else {
			daemon_sockets_remove(sock_index);
			PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			ack_send(call_id, call_index, call_type, 0);
		}
	}

	freeFinsFrame(ff);
}

void poll_in_tcp_fcf(struct finsFrame *ff, uint32_t call_id, int call_index, int call_pid, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data,
		uint32_t flags) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u, flags=%u",
			ff, call_id, call_index, call_pid, call_type, sock_id, sock_index, data, flags);

	uint32_t ret_msg = 0;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);
	//secure_metadata_readFromElement(params, "mask", &mask);

	if ((ff->ctrlFrame.param_id != EXEC_TCP_POLL) || ff->ctrlFrame.ret_val == 0) {
		PRINT_ERROR("Exiting, NACK: ff=%p, param_id=%d, ret_val=%u", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(call_id, call_index, call_type, 1);
	} else {
		if (ret_msg) {
			ack_send(call_id, call_index, call_type, ret_msg);
		} else {
			if (flags) { //flags == initial

				PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
				secure_sem_wait(&daemon_sockets_sem);
				if (daemon_sockets[sock_index].sock_id != sock_id) {
					PRINT_ERROR("Exited: socket closed: ff=%p", ff);
					PRINT_DEBUG("post$$$$$$$$$$$$$$$");
					sem_post(&daemon_sockets_sem);

					nack_send(call_id, call_index, call_type, POLLNVAL);
				} else {
					struct daemon_call *call = call_create(call_id, call_index, call_pid, call_type, sock_id, sock_index);
					call->data = data;
					call->ret = 0;

					struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;
					if (call_list_has_space(call_list)) {
						call_list_append(call_list, call);

						PRINT_DEBUG("");
						PRINT_DEBUG("post$$$$$$$$$$$$$$$");
						sem_post(&daemon_sockets_sem);

						ack_send(call_id, call_index, call_type, 0);
					} else {
						PRINT_ERROR("call_list full");
						PRINT_DEBUG("post$$$$$$$$$$$$$$$");
						sem_post(&daemon_sockets_sem);

						nack_send(call_id, call_index, call_type, 1);
					}
				}
			} else {
				ack_send(call_id, call_index, call_type, 0);
			}
		}
	}

	freeFinsFrame(ff);
}

void poll_in_tcp_fdf(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags) {
	PRINT_DEBUG("Entered: call_list=%p, call=%p, flags=%u", call_list, call, flags);

	uint32_t events = call->data;

	PRINT_DEBUG(
			"POLLIN=0x%x, POLLPRI=0x%x, POLLOUT=0x%x, POLLERR=0x%x, POLLHUP=0x%x, POLLNVAL=0x%x, POLLRDNORM=0x%x, POLLRDBAND=0x%x, POLLWRNORM=0x%x, POLLWRBAND=0x%x",
			events & POLLIN, events & POLLPRI, events & POLLOUT, events & POLLERR, events & POLLHUP, events & POLLNVAL, events & POLLRDNORM, events & POLLRDBAND, events & POLLWRNORM, events & POLLWRBAND);

	uint32_t mask = 0;

	if (flags & POLLERR) {
		mask |= POLLERR;
	}

	if (flags & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		mask |= POLLIN | POLLRDNORM; //TODO POLLPRI?
	}

	if (flags & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
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

void recvmsg_in_tcp_fdf(struct daemon_call_list *call_list, struct daemon_call *call, metadata *params, uint8_t *data, uint32_t data_len, uint32_t addr_ip,
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
			//TODO find out how tcp does this
		}

		if (daemon_sockets[call->sock_index].sockopts.FIP_RECVERR && (flags & MSG_ERRQUEUE)) {
			//TODO tcp has no error queue
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
		//PRINT_DEBUG("before: sock_index=%d, data_buf=%d", hdr->sock_index, daemon_sockets[hdr->sock_index].data_buf);
		//daemon_sockets[call->sock_index].data_buf -= data_len;
		//PRINT_DEBUG("after: sock_index=%d, data_buf=%d", hdr->sock_index, daemon_sockets[hdr->sock_index].data_buf);

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);

		uint32_t state = daemon_sockets[call->sock_index].state;
		uint32_t host_ip = daemon_sockets[call->sock_index].host_ip;
		uint32_t host_port = daemon_sockets[call->sock_index].host_port;
		uint32_t rem_ip = daemon_sockets[call->sock_index].rem_ip;
		uint32_t rem_port = daemon_sockets[call->sock_index].rem_port;

		PRINT_DEBUG("recvfrom address: state=%u, host=%u/%u, rem=%u/%u,", state, host_ip, host_port, rem_ip, rem_port);

		metadata *params_reply = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(params_reply);

		uint32_t value = data_len;
		secure_metadata_writeToElement(params_reply, "value", &value, META_TYPE_INT32);

		secure_metadata_writeToElement(params_reply, "state", &state, META_TYPE_INT32);
		secure_metadata_writeToElement(params_reply, "host_ip", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params_reply, "host_port", &host_port, META_TYPE_INT32);
		secure_metadata_writeToElement(params_reply, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(params_reply, "rem_port", &rem_port, META_TYPE_INT32);

		if (daemon_fcf_to_switch(TCP_ID, params_reply, gen_control_serial_num(), CTRL_SET_PARAM, SET_PARAM_TCP_HOST_WINDOW)) {
			PRINT_DEBUG("Exited, normal: call=%p", call);
		} else {
			PRINT_ERROR("Exited, fail sending flow msgs: call=%p", call);
			metadata_destroy(params);
		}
	}
	if (control_msg)
		free(control_msg);
	free(msg);

	call_list_remove(call_list, call);
	daemon_calls_remove(call->call_index);
}

void daemon_tcp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
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
	secure_metadata_writeToElement(params, "recv_stamp", &current, META_TYPE_INT64);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int sock_index = daemon_sockets_match_connection(src_ip, (uint16_t) src_port, dst_ip, (uint16_t) dst_port, IPPROTO_TCP);
	if (sock_index == -1) {
		sock_index = daemon_sockets_match_connection(src_ip, (uint16_t) src_port, 0, 0, IPPROTO_TCP);
	}
	if (sock_index == -1) {
		PRINT_ERROR("No match, freeing: ff=%p, src=%u/%u, dst=%u/%u", ff, src_ip, (uint16_t)src_port, dst_ip, (uint16_t)dst_port);
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
				poll_in_tcp_fdf(call_list, call, POLLIN);
			}
			call = call->next;
		}

		call = call_list->front;
		while (call) {
			if (call->call_type == recvmsg_call && !(call->flags & (MSG_ERRQUEUE))) { //signal first recvmsg for data
				recvmsg_in_tcp_fdf(call_list, call, params, ff->dataFrame.pdu, ff->dataFrame.pduLength, dst_ip, (uint16_t) dst_port, 0);
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

void daemon_tcp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip) {
	PRINT_DEBUG("Entered: ff=%p, src_ip=%u, dst_ip=%u", ff, src_ip, dst_ip);

	uint32_t src_port;
	uint32_t dst_port;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "src_port", &src_port);
	secure_metadata_readFromElement(params, "dst_port", &dst_port);

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	//TODO move to interface?
	//secure_metadata_writeToElement(params, "stamp", &current, META_TYPE_INT64);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	//src == host & dst == rem
	int sock_index = daemon_sockets_match_connection(src_ip, (uint16_t) src_port, dst_ip, (uint16_t) dst_port, IPPROTO_TCP);
	if (sock_index == -1) {
		sock_index = daemon_sockets_match_connection(src_ip, (uint16_t) src_port, 0, 0, IPPROTO_TCP);
	}

	if (sock_index == -1) {
		PRINT_ERROR("No match, freeing: ff=%p, src=%u/%u, dst=%u/%u", ff, src_ip, (uint16_t) src_port, dst_ip, (uint16_t)dst_port);
	} else {
		PRINT_DEBUG( "Matched: sock_id=%llu, sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port, daemon_sockets[sock_index].protocol);

		//TODO check if this datagram comes from the address this socket has been previously connected to it (Only if the socket is already connected to certain address)

		struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

		struct daemon_call *call = call_list->front;
		while (call) {
			if (call->call_type == poll_call) { //signal all poll calls in list
				poll_in_tcp_fdf(call_list, call, POLLERR);
			}
			call = call->next;
		}
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	freeFinsFrame(ff);
}

void daemon_tcp_in_poll(struct finsFrame *ff, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: ff=%p, ret_msg=%u", ff, ret_msg);

	uint32_t state;
	uint32_t host_ip;
	uint32_t host_port;
	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "state", &state);
	secure_metadata_readFromElement(params, "host_ip", &host_ip);
	secure_metadata_readFromElement(params, "host_port", &host_port);
	if (state > SS_UNCONNECTED) {
		secure_metadata_readFromElement(params, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(params, "rem_port", &rem_port);
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	int sock_index = daemon_sockets_match_connection(host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port, IPPROTO_TCP);
	if (sock_index == -1) {
		sock_index = daemon_sockets_match_connection(host_ip, (uint16_t) host_port, 0, 0, IPPROTO_TCP);
	}

	if (sock_index == -1) {
		PRINT_ERROR("No match, freeing: ff=%p, src=%u/%u, dst=%u/%u", ff, host_ip, (uint16_t) host_port, rem_ip, (uint16_t)rem_port);
	} else {
		PRINT_DEBUG( "Matched: sock_id=%llu, sock_index=%d, host=%u/%u, dst=%u/%u, prot=%u",
				daemon_sockets[sock_index].sock_id, sock_index, daemon_sockets[sock_index].host_ip, daemon_sockets[sock_index].host_port, daemon_sockets[sock_index].rem_ip, daemon_sockets[sock_index].rem_port, daemon_sockets[sock_index].protocol);

		struct daemon_call_list *call_list = daemon_sockets[sock_index].call_list;

		struct daemon_call *call = call_list->front;
		while (call) {
			if (call->call_type == poll_call) { //signal all poll calls in list
				poll_in_tcp_fdf(call_list, call, ret_msg);
			}
			call = call->next;
		}
	}
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&daemon_sockets_sem);

	freeFinsFrame(ff);
}

void connect_timeout_tcp(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	switch (daemon_sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		if (daemon_sockets[call->sock_index].error_call == call->call_type) {
			nack_send(call->call_id, call->call_index, call->call_type, daemon_sockets[call->sock_index].error_msg);

			daemon_sockets[call->sock_index].error_call = 0; //TODO remove?
			daemon_sockets[call->sock_index].error_msg = 0;
		}
		break;
	case SS_CONNECTING:
		nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //nack EAGAIN or EWOULDBLOCK, or should it be EINPROGRESS?

		if (call->serial_num) { //was sent outside of module
			struct daemon_call *clone = call_clone(call);
			call_list_append(expired_call_list, clone);
		}
		break;
	case SS_CONNECTED:
		ack_send(call->call_id, call->call_index, call->call_type, 0);
		break;
	default:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	}

	daemon_calls_remove(call->call_index); //passed call should be &daemon_calls[call->call_index]
}

void accept_timeout_tcp(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	switch (daemon_sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		//TODO check daemon_sockets[hdr->sock_index].sock_id_new / sock_index_new, such that if nonblocking & expired accept accomplished
		if (daemon_sockets[call->sock_index].error_call == call->call_type) {
			nack_send(call->call_id, call->call_index, call->call_type, daemon_sockets[call->sock_index].error_msg);

			daemon_sockets[call->sock_index].error_call = 0; //TODO remove?
			daemon_sockets[call->sock_index].error_msg = 0;
		} else if (daemon_sockets[call->sock_index].sock_id_new != -1 && daemon_sockets[call->sock_index].sock_index_new != -1) {
			ack_send(call->call_id, call->call_index, call->call_type, 0);

			daemon_sockets[call->sock_index].sock_id_new = 0; //TODO remove?
			daemon_sockets[call->sock_index].sock_index_new = 0;
		} else {
			nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //TODO fix; this is a patch such that if 2 accepts are called at the same time in different threads
		}
		break;
	case SS_CONNECTING:
		nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //nack EAGAIN or EWOULDBLOCK, or should it be EINPROGRESS?

		if (call->serial_num) { //was sent outside of module
			struct daemon_call *clone = call_clone(call);
			call_list_append(expired_call_list, clone);
		}
		break;
	default:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	}

	daemon_calls_remove(call->call_index); //passed call should be &daemon_calls[call->call_index]
}

void recvmsg_timeout_tcp(struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);

	call_list_remove(daemon_sockets[call->sock_index].call_list, call);

	switch (daemon_sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	case SS_CONNECTING:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	case SS_CONNECTED:
		nack_send(call->call_id, call->call_index, call->call_type, EAGAIN); //nack EAGAIN or EWOULDBLOCK
		break;
	default:
		PRINT_ERROR("todo error");
		nack_send(call->call_id, call->call_index, call->call_type, 1);
		break;
	}

	daemon_calls_remove(call->call_index);
}

void connect_expired_tcp(struct finsFrame *ff, struct daemon_call *call, uint8_t reply) { //almost equiv to connect_in_tcp //TODO combine the two?
	PRINT_DEBUG("Entered: ff=%p, call=%p, reply=%d", ff, call, reply);

	if (ff->ctrlFrame.param_id != EXEC_TCP_CONNECT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, 1);
		call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, 1);
		call_free(call);
		freeFinsFrame(ff);
		return;
	}

	if (ff->ctrlFrame.ret_val) {
		daemon_sockets[call->sock_index].state = SS_CONNECTED;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (reply)
			ack_send(call->call_id, call->call_index, call->call_type, 0);
	} else {
		daemon_sockets[call->sock_index].state = SS_UNCONNECTED;
		daemon_sockets[call->sock_index].error_call = call->call_type;
		daemon_sockets[call->sock_index].error_msg = ret_msg;

		daemon_sockets[call->sock_index].host_ip = 0; //TODO don't clear? so that will detect error
		daemon_sockets[call->sock_index].host_port = 0;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	call_free(call);
	freeFinsFrame(ff);
}

void accept_expired_tcp(struct finsFrame *ff, struct daemon_call *call, uint8_t reply) { //change accept_in_tcp to call, add ack/nack flag?
	PRINT_DEBUG("Entered: ff=%p, call=%p, reply=%d", ff, call, reply);

	if (ff->ctrlFrame.param_id != EXEC_TCP_ACCEPT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, 1);
		call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	uint32_t rem_ip;
	uint32_t rem_port;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "ret_msg", &ret_msg);
	secure_metadata_readFromElement(params, "rem_ip", &rem_ip);
	secure_metadata_readFromElement(params, "rem_port", &rem_port);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&daemon_sockets_sem);
	if (daemon_sockets[call->sock_index].sock_id != call->sock_id) { //TODO shouldn't happen, check release
		PRINT_ERROR("Exited, socket closed: ff=%p", ff);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, 1);
		call_free(call);
		freeFinsFrame(ff);
		return;
	}

	if (ff->ctrlFrame.ret_val) {
		if (daemon_sockets_insert(call->sock_id_new, call->sock_index_new, daemon_sockets[call->sock_index].type, daemon_sockets[call->sock_index].protocol)) {
			daemon_sockets[call->sock_index_new].state = SS_CONNECTED;
			daemon_sockets[call->sock_index_new].host_ip = daemon_sockets[call->sock_index].host_ip;
			daemon_sockets[call->sock_index_new].host_port = daemon_sockets[call->sock_index].host_port;
			daemon_sockets[call->sock_index_new].rem_ip = rem_ip;
			daemon_sockets[call->sock_index_new].rem_port = (uint16_t) rem_port;

			PRINT_DEBUG("Accept socket created: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[call->sock_index_new].sock_id, call->sock_index_new, daemon_sockets[call->sock_index_new].state, daemon_sockets[call->sock_index_new].host_ip, daemon_sockets[call->sock_index_new].host_port, daemon_sockets[call->sock_index_new].rem_ip, daemon_sockets[call->sock_index_new].rem_port);

			daemon_sockets[call->sock_index].state = SS_UNCONNECTED;
			if (reply) {
				daemon_sockets[call->sock_index].sock_id_new = -1;
				daemon_sockets[call->sock_index].sock_index_new = -1;
			} else {
				daemon_sockets[call->sock_index].sock_id_new = call->sock_id_new;
				daemon_sockets[call->sock_index].sock_index_new = call->sock_index_new;
			}

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
			if (reply)
				ack_send(call->call_id, call->call_index, call->call_type, 0);
		} else {
			PRINT_ERROR("Exited: insert failed: ff=%p", ff);

			daemon_sockets[call->sock_index].state = SS_UNCONNECTED;
			daemon_sockets[call->sock_index].error_call = call->call_type;
			daemon_sockets[call->sock_index].error_msg = 0; //TODO fill in special value?

			PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
					daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);

			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&daemon_sockets_sem);

			if (reply)
				nack_send(call->call_id, call->call_index, call->call_type, 1);
		}
	} else {
		daemon_sockets[call->sock_index].state = SS_UNCONNECTED;
		daemon_sockets[call->sock_index].error_call = call->call_type;
		daemon_sockets[call->sock_index].error_msg = ret_msg;

		PRINT_DEBUG("curr: sock_id=%llu, sock_index=%d, state=%u, host=%u/%u, dst=%u/%u",
				daemon_sockets[call->sock_index].sock_id, call->sock_index, daemon_sockets[call->sock_index].state, daemon_sockets[call->sock_index].host_ip, daemon_sockets[call->sock_index].host_port, daemon_sockets[call->sock_index].rem_ip, daemon_sockets[call->sock_index].rem_port);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&daemon_sockets_sem);

		if (reply)
			nack_send(call->call_id, call->call_index, call->call_type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	call_free(call);
	freeFinsFrame(ff);
}

