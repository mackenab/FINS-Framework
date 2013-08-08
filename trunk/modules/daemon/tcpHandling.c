/**
 * @file tcpHandling.c
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#include "tcpHandling.h"
#include <finstypes.h>

struct daemon_socket_general_ops tcp_general_ops = { .proto = IPPROTO_TCP, .socket_type_test = socket_tcp_test, .socket_out = socket_out_tcp, .daemon_in_fdf =
		daemon_in_fdf_tcp, .daemon_in_error = daemon_in_error_tcp, .daemon_in_poll = daemon_in_poll_tcp };
static struct daemon_socket_out_ops tcp_out_ops = { .socket_out = socket_out_tcp, .bind_out = bind_out_tcp, .listen_out = listen_out_tcp, .connect_out =
		connect_out_tcp, .accept_out = accept_out_tcp, .getname_out = getname_out_tcp, .ioctl_out = ioctl_out_tcp, .sendmsg_out = sendmsg_out_tcp,
		.recvmsg_out = recvmsg_out_tcp, .getsockopt_out = getsockopt_out_tcp, .setsockopt_out = setsockopt_out_tcp, .release_out = release_out_tcp, .poll_out =
				poll_out_tcp, .mmap_out = mmap_out_tcp, .socketpair_out = socketpair_out_tcp, .shutdown_out = shutdown_out_tcp, .close_out = close_out_tcp,
		.sendpage_out = sendpage_out_tcp, };
static struct daemon_socket_in_ops tcp_in_ops = { .connect_in = connect_in_tcp, .accept_in = accept_in_tcp, .sendmsg_in = sendmsg_in_tcp, .getsockopt_in =
		getsockopt_in_tcp, .setsockopt_in = setsockopt_in_tcp, .release_in = release_in_tcp, .poll_in = poll_in_tcp_fcf, };
static struct daemon_socket_other_ops tcp_other_ops = { .connect_timeout = connect_timeout_tcp, .connect_expired = connect_expired_tcp, .accept_timeout =
		accept_timeout_tcp, .accept_expired = accept_expired_tcp, .recvmsg_timeout = recvmsg_timeout_tcp, };

int match_host_addr4_tcp(struct fins_module *module, uint32_t host_ip, uint16_t host_port) {
	PRINT_DEBUG("Entered: module=%p, host=%u:%u", module, host_ip, host_port);
	struct daemon_data *md = (struct daemon_data *) module->data;

	//must be unique 5-ple (protocol, source ip, source port, dest ip, dest port)
	uint32_t test_host_ip;
	uint16_t test_host_port;

	int i;
	for (i = 0; i < DAEMON_MAX_SOCKETS; i++) {
		if (md->sockets[i].sock_id != -1 && md->sockets[i].protocol == IPPROTO_TCP && md->sockets[i].family == AF_INET) {
			test_host_ip = addr4_get_ip(&md->sockets[i].host_addr);
			test_host_port = addr4_get_port(&md->sockets[i].host_addr);

			if (test_host_port == host_port && (test_host_ip == INADDR_ANY || test_host_ip == host_ip)) {
				return i;
			}
		}
	}

	return -1;
}

int match_conn_addr4_tcp(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port) {
	PRINT_DEBUG("Entered: module=%p, host=%u:%u, rem=%u:%u", module, host_ip, host_port, rem_ip, rem_port);
	struct daemon_data *md = (struct daemon_data *) module->data;

	//must be unique 5-ple (protocol, source ip, source port, dest ip, dest port)
	uint32_t test_host_ip;
	uint16_t test_host_port;
	uint32_t test_rem_ip;
	uint16_t test_rem_port;

	int i;
	for (i = 0; i < DAEMON_MAX_SOCKETS; i++) {
		if (md->sockets[i].sock_id != -1 && md->sockets[i].protocol == IPPROTO_TCP && md->sockets[i].family == AF_INET) {

			test_host_ip = addr4_get_ip(&md->sockets[i].host_addr);
			test_host_port = addr4_get_port(&md->sockets[i].host_addr);
			test_rem_ip = addr4_get_ip(&md->sockets[i].rem_addr);
			test_rem_port = addr4_get_port(&md->sockets[i].rem_addr);

			if (test_host_port == host_port && test_rem_port == rem_port && (test_host_ip == INADDR_ANY || test_host_ip == host_ip)
					&& (test_rem_ip == INADDR_ANY || test_rem_ip == rem_ip)) {
				return i;
			}
		}
	}

	//TODO add check for INADDR_ANY & INPORT_ANY
	return (-1);
}

int socket_tcp_test(int domain, int type, int protocol) {
	return type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP);
}

void socket_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int domain) {
	PRINT_DEBUG("Entered: hdr=%p, domain=%d", hdr, domain);

	int ret = daemon_sockets_insert(module, hdr->sock_id, hdr->sock_index, SOCK_STREAM, IPPROTO_TCP, &tcp_out_ops, &tcp_in_ops, &tcp_other_ops);
	PRINT_DEBUG("sock_index=%d, ret=%d", hdr->sock_index, ret);

	if (ret) {
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void bind_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (md->sockets[hdr->sock_index].family != AF_UNSPEC) {
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EINVAL); //22
		return;
	}

	if (addr->ss_family == AF_INET) {
		uint32_t host_ip = ntohl(addr4_get_ip(addr));
		uint16_t host_port = ntohs(addr4_get_port(addr));
		PRINT_DEBUG("bind address: family=%u, host_ip=%u, host_port=%u", AF_INET, host_ip, host_port);

		if (match_host_addr4_tcp(module, host_ip, host_port) != -1) {
			PRINT_ERROR("this port is not free");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRINUSE);
			return;
		}

		if (host_ip == INADDR_ANY) { //TODO check if this is right? should TCP get INADDR_ANY
			struct addr_record *address = (struct addr_record *) list_find(md->if_main->addr_list, addr_is_v4);
			if (address != NULL) {
				host_ip = addr4_get_ip(&address->ip);
			} else {
				PRINT_WARN("todo error");
			}
		}

		md->sockets[hdr->sock_index].family = AF_INET;
		addr4_set_ip(&md->sockets[hdr->sock_index].host_addr, host_ip);
		addr4_set_port(&md->sockets[hdr->sock_index].host_addr, host_port);
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));
	} else if (addr->ss_family == AF_INET6) {
		//TODO

		md->sockets[hdr->sock_index].family = AF_INET6;
	} else {
		PRINT_ERROR("Wrong address family=%d", addr->ss_family);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
}

void listen_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int backlog) {
	PRINT_DEBUG("Entered: hdr=%p, backlog=%d", hdr, backlog);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (md->sockets[hdr->sock_index].family == AF_UNSPEC) {
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	md->sockets[hdr->sock_index].listening = 1;
	md->sockets[hdr->sock_index].backlog = backlog;

	metadata *meta;
	if (md->sockets[hdr->sock_index].family == AF_INET) {
		uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
		uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		/** Keep all ports and addresses in host order until later  action taken
		 * in IPv4 module
		 *  */
		/** addresses are in host format given that there are by default already filled
		 * host IP and host port. Otherwise, a port and IP has to be assigned explicitly below */
		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	} else { //AF_INET6
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	uint32_t family = md->sockets[hdr->sock_index].family;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "backlog", &backlog, META_TYPE_INT32);

	if (daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, gen_control_serial_num(), CTRL_EXEC, DAEMON_EXEC_TCP_LISTEN)) {
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(meta);
	}
}

void connect_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, flags=%d", hdr, flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

	switch (md->sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check md->daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		if (md->sockets[hdr->sock_index].error_call == hdr->call_type) {
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, md->sockets[hdr->sock_index].error_msg);

			md->sockets[hdr->sock_index].error_call = 0; //TODO remove?
			md->sockets[hdr->sock_index].error_msg = 0;
			return;
		}
		break;
	case SS_CONNECTING:
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				PRINT_DEBUG("inserting call: hdr=%p", hdr);
				md->calls[hdr->call_index].flags = flags;

				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_WARN("todo");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		}
		return;
	case SS_CONNECTED:
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EISCONN);
		return;
	default:
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		return;
	}

	metadata *meta;
	if (addr->ss_family == AF_INET) {
		if (md->sockets[hdr->sock_index].family != AF_UNSPEC && md->sockets[hdr->sock_index].family != AF_INET) {
			PRINT_WARN("todo error");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EAFNOSUPPORT);
			return;
		}

		uint32_t rem_ip = ntohl(addr4_get_ip(addr));
		uint16_t rem_port = ntohs(addr4_get_port(addr));

		PRINT_DEBUG("address: rem=%u ('%s'):%u, rem_IP_netformat=%u", rem_ip, inet_ntoa(((struct sockaddr_in *) addr)->sin_addr), rem_port, htonl(rem_ip));
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		md->sockets[hdr->sock_index].state = SS_CONNECTING;
		md->sockets[hdr->sock_index].listening = 0;
		addr4_set_ip(&md->sockets[hdr->sock_index].rem_addr, rem_ip);
		addr4_set_port(&md->sockets[hdr->sock_index].rem_addr, rem_port);

		uint32_t host_ip;
		uint16_t host_port;

		if (md->sockets[hdr->sock_index].family == AF_UNSPEC) {
			md->sockets[hdr->sock_index].family = AF_INET;

			//auto bind
			struct addr_record *address = (struct addr_record *) list_find(md->if_main->addr_list, addr_is_v4);
			if (address != NULL) {
				host_ip = addr4_get_ip(&address->ip);
			} else {
				PRINT_WARN("todo error");
			}
			addr4_set_ip(&md->sockets[hdr->sock_index].host_addr, host_ip);

			/**
			 * It is supposed to be randomly selected from the range found in
			 * /proc/sys/net/ipv4/ip_local_port_range default range in Ubuntu is 32768 - 61000
			 */
			while (1) {
				host_port = (uint16_t) randoming(MIN_port, MAX_port);
				if (match_host_addr4_tcp(module, host_ip, host_port) == -1) {
					break;
				}
			}
			addr4_set_port(&md->sockets[hdr->sock_index].host_addr, host_port);
		} else {
			host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
		}
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
	} else if (addr->ss_family == AF_INET6) {
		if (md->sockets[hdr->sock_index].family != AF_UNSPEC && md->sockets[hdr->sock_index].family != AF_INET6) {
			PRINT_WARN("todo error");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EAFNOSUPPORT);
			return;
		}
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	} else {
		PRINT_ERROR("Wrong address family=%d", addr->ss_family);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EAFNOSUPPORT);
		return;
	}

	uint32_t family = md->sockets[hdr->sock_index].family;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "flags", &flags, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, DAEMON_EXEC_TCP_CONNECT);
	if (sent > 0) {
		if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			PRINT_DEBUG("inserting call: hdr=%p", hdr);
			md->calls[hdr->call_index].serial_num = serial_num;
			md->calls[hdr->call_index].flags = flags;
			md->calls[hdr->call_index].sent = sent;

			if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			}
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(meta);
	}
}

void accept_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint64_t sock_id_new, int sock_index_new, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id_new=%llu, sock_index_new=%d, flags=%d", hdr, sock_id_new, sock_index_new, flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("SOCK_NONBLOCK=%d (0x%x), SOCK_CLOEXEC=%d (0x%x), O_NONBLOCK=%d (0x%x), O_ASYNC=%d (0x%x)",
			(SOCK_NONBLOCK & flags)>0, SOCK_NONBLOCK, (SOCK_CLOEXEC & flags)>0, SOCK_CLOEXEC, (O_NONBLOCK & flags)>0, O_NONBLOCK, (O_ASYNC & flags)>0, O_ASYNC);
	PRINT_DEBUG(
			"MSG_CMSG_CLOEXEC=%d (0x%x), MSG_DONTWAIT=%d (0x%x), MSG_ERRQUEUE=%d (0x%x), MSG_OOB=%d (0x%x), MSG_PEEK=%d (0x%x), MSG_TRUNC=%d (0x%x), MSG_WAITALL=%d (0x%x)",
			(MSG_CMSG_CLOEXEC & flags)>0, MSG_CMSG_CLOEXEC, (MSG_DONTWAIT & flags)>0, MSG_DONTWAIT, (MSG_ERRQUEUE & flags)>0, MSG_ERRQUEUE, (MSG_OOB & flags)>0, MSG_OOB, (MSG_PEEK & flags)>0, MSG_PEEK, (MSG_TRUNC & flags)>0, MSG_TRUNC, (MSG_WAITALL & flags)>0, MSG_WAITALL);

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

	if (md->sockets[hdr->sock_index].listening == 0) {
		PRINT_ERROR("socket not listening");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	switch (md->sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check md->daemon_sockets[hdr->sock_index].sock_id_new / sock_index_new, such that if nonblocking & expired accept accomplished
		//TODO check md->daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		break;
	case SS_CONNECTING:
		if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
			if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				PRINT_DEBUG("inserting call: hdr=%p", hdr);
				md->calls[hdr->call_index].flags = flags;

				md->calls[hdr->call_index].sock_id_new = sock_id_new; //TODO redo so not in call? or in struct inside call as void *pt;
				md->calls[hdr->call_index].sock_index_new = sock_index_new;

				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_WARN("todo");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO EADDRINUSE, check?
		}
		return;
	default:
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	metadata *meta;
	if (md->sockets[hdr->sock_index].family == AF_INET) {
		uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
		uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
		PRINT_DEBUG("accept address: host=%u:%u", host_ip, host_port);

		//TODO process flags?

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	} else { //AF_INET6
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	uint32_t family = md->sockets[hdr->sock_index].family;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "flags", &flags, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, DAEMON_EXEC_TCP_ACCEPT);
	if (sent > 0) {
		if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			PRINT_DEBUG("inserting call: hdr=%p", hdr);
			md->calls[hdr->call_index].serial_num = serial_num;
			md->calls[hdr->call_index].flags = flags;
			md->calls[hdr->call_index].sent = sent;

			md->calls[hdr->call_index].sock_id_new = sock_id_new; //TODO redo so not in call? or in struct inside call as void *pt;
			md->calls[hdr->call_index].sock_index_new = sock_index_new;

			if (flags & (SOCK_NONBLOCK | O_NONBLOCK)) {
				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			}

			md->sockets[hdr->sock_index].state = SS_CONNECTING;

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(meta);
	}
}

void getname_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int peer) {
	PRINT_DEBUG("Entered: hdr=%p, peer=%d", hdr, peer);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int address_len;
	struct sockaddr_storage address;

	if (md->sockets[hdr->sock_index].family == AF_INET) {
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		uint32_t addr_ip;
		uint16_t addr_port;

		if (peer == 0) { //getsockname
			addr_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			addr_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
		} else if (peer == 1) { //getpeername
			if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
				addr_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
				addr_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
			} else {
				addr_ip = 0;
				addr_port = 0;
			}
		} else if (peer == 2) { //accept4 //TODO figure out supposed to do??
			if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
				addr_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
				addr_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
			} else {
				addr_ip = 0;
				addr_port = 0;
			}
		} else {
			//TODO error
			PRINT_WARN("todo error");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //remove
			return;
		}

		address_len = sizeof(struct sockaddr_in);

		struct sockaddr_in *addr4 = (struct sockaddr_in *) &address;
		addr4->sin_addr.s_addr = htonl(addr_ip);
		addr4->sin_port = htons(addr_port);
		PRINT_DEBUG("addr=('%s':%d) netw=%u", inet_ntoa(addr4->sin_addr), ntohs(addr4->sin_port), addr4->sin_addr.s_addr);
	} else if (md->sockets[hdr->sock_index].family == AF_INET6) {
		PRINT_WARN("todo");
		//TODO
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	} else {
		//AF_UNSPEC, only occurs when not bound
		PRINT_WARN("todo");

		//returns struct sockaddr with just family filled out
		//Family defaults to AF_INET, probably because of the main address of main interface
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //remove
		return;
	}

	address.ss_family = md->sockets[hdr->sock_index].family;

	//send msg to wedge
	int msg_len = sizeof(struct daemon_to_wedge_hdr) + sizeof(int) + address_len;
	uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

	struct daemon_to_wedge_hdr *hdr_ret = (struct daemon_to_wedge_hdr *) msg;
	hdr_ret->call_type = hdr->call_type;
	hdr_ret->call_id = hdr->call_id;
	hdr_ret->call_index = hdr->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0;
	uint8_t *pt = msg + sizeof(struct daemon_to_wedge_hdr);

	*(int *) pt = address_len;
	pt += sizeof(int);

	memcpy(pt, &address, address_len);
	pt += address_len;

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
		free(msg);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (send_wedge(module, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else {
		PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
	}
	free(msg);
}

void ioctl_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t cmd, uint8_t *buf, int buf_len) {
	PRINT_DEBUG("Entered: hdr=%p, cmd=%d, len=%d", hdr, cmd, buf_len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t len;
	//uint8_t *val;
	int msg_len;
	uint8_t *msg = NULL;
	struct daemon_to_wedge_hdr *hdr_ret;
	uint8_t *pt;

	switch (cmd) {
	case FIONREAD:
		PRINT_DEBUG("FIONREAD cmd=%d", cmd);
		//figure out buffered data

		//send msg to wedge
		msg_len = sizeof(struct daemon_to_wedge_hdr) + sizeof(uint32_t);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct daemon_to_wedge_hdr *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct daemon_to_wedge_hdr);

		*(uint32_t *) pt = md->sockets[hdr->sock_index].data_buf;
		pt += sizeof(uint32_t);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGSTAMP:
		PRINT_DEBUG("SIOCGSTAMP cmd=%d", cmd);

		len = sizeof(struct timeval);
		//val = &md->daemon_sockets[hdr->sock_index].latest;

		//send msg to wedge
		msg_len = sizeof(struct daemon_to_wedge_hdr) + sizeof(uint32_t) + len;
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct daemon_to_wedge_hdr *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct daemon_to_wedge_hdr);

		*(uint32_t *) pt = len;
		pt += sizeof(uint32_t);

		PRINT_DEBUG("stamp=%u.%u", (uint32_t)md->sockets[hdr->sock_index].stamp.tv_sec, (uint32_t) md->sockets[hdr->sock_index].stamp.tv_usec);

		memcpy(pt, &md->sockets[hdr->sock_index].stamp, len);
		pt += len;

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	default:
		PRINT_ERROR("default cmd=%d", cmd);
		msg_len = 0;
		break;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (msg_len == 0) {
		//nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1); //TODO uncomment
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	if (send_wedge(module, msg, msg_len, 0)) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
	free(msg);
}

void sendmsg_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t data_len, uint8_t *data, uint32_t flags,
		struct sockaddr_storage *addr, int addr_len) {
	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, flags=%d, addr_len=%d", hdr, data_len, flags, addr_len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("MSG_CONFIRM=%d (%d), MSG_DONTROUTE=%d (%d), MSG_DONTWAIT=%d (%d), MSG_EOR=%d (%d), MSG_MORE=%d (%d), MSG_NOSIGNAL=%d (%d), MSG_OOB=%d (%d)",
			MSG_CONFIRM & flags, MSG_CONFIRM, MSG_DONTROUTE & flags, MSG_DONTROUTE, MSG_DONTWAIT & flags, MSG_DONTWAIT, MSG_EOR & flags, MSG_EOR, MSG_MORE & flags, MSG_MORE, MSG_NOSIGNAL & flags, MSG_NOSIGNAL, MSG_OOB & flags, MSG_OOB);

	/** TODO handle flags cases */

	if (data_len == 0) { //TODO check this prob wrong!
		PRINT_ERROR("todo/redo");
		PRINT_DEBUG("data_len == 0, send ACK");
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	switch (md->sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_WARN("todo error");
		//TODO buffer data & send ACK
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EPIPE);
		free(data);
		return;
	case SS_CONNECTING:
	case SS_CONNECTED:
		break;
	case SS_DISCONNECTING:
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EPIPE);
		free(data);
		return;
	default:
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(data);
		return;
	}

	if (!(md->sockets[hdr->sock_index].status & DAEMON_STATUS_WR)) {
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EPIPE); //TODO change to correct?
		free(data);
		return;
	}

	metadata *meta;
	if (md->sockets[hdr->sock_index].family == AF_INET) {
		uint32_t rem_ip;
		uint32_t rem_port;
		if (addr_len != 0) {
			rem_ip = ntohl(addr4_get_ip(addr));
			rem_port = (uint32_t) ntohs(addr4_get_port(addr));
		} else {
			rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			rem_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
		}

		uint32_t host_ip;
		uint32_t host_port;
		if (md->sockets[hdr->sock_index].family != AF_UNSPEC) {
			host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			host_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
		} else {
			struct addr_record *address = (struct addr_record *) list_find(md->if_main->addr_list, addr_is_v4);
			if (address != NULL) {
				host_ip = addr4_get_ip(&address->ip);
			} else {
				PRINT_WARN("todo error");
			}

			/**
			 * It is supposed to be randomly selected from the range found in
			 * /proc/sys/net/ipv4/ip_local_port_range default range in Ubuntu is 32768 - 61000
			 */
			while (1) {
				host_port = (uint16_t) randoming(MIN_port, MAX_port);
				if (match_host_addr4_tcp(module, host_ip, (uint16_t) host_port) == -1) {
					break;
				}
			}
			addr4_set_port(&md->sockets[hdr->sock_index].host_addr, host_port);
		}

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		//########################
#ifdef DEBUG
		struct in_addr *temp = (struct in_addr *) malloc(sizeof(struct in_addr));
		temp->s_addr = htonl(host_ip);
		PRINT_DEBUG("index=%d, host='%s':%u (%u)", hdr->sock_index, inet_ntoa(*temp), (uint16_t)host_port, host_ip);
		temp->s_addr = htonl(rem_ip);
		PRINT_DEBUG("index=%d, rem='%s':%u (%u)", hdr->sock_index, inet_ntoa(*temp), (uint16_t)rem_port, rem_ip);
		free(temp);
#endif
		//########################

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		secure_metadata_writeToElement(meta, "send_src_ipv4", &host_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "send_src_port", &host_port, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "send_dst_ipv4", &rem_ip, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "send_dst_port", &rem_port, META_TYPE_INT32);
	} else {
		PRINT_WARN("todo");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(data);
		return;
	}

	uint32_t family = addr->ss_family;
	secure_metadata_writeToElement(meta, "send_family", &family, META_TYPE_INT32);
	secure_metadata_writeToElement(meta, "flags", &flags, META_TYPE_INT32);

	//uint32_t ttl = md->sockets[hdr->sock_index].sockopts.FIP_TTL;
	//secure_metadata_writeToElement(meta, "send_ttl", &ttl, META_TYPE_INT32);
	//uint32_t tos = md->sockets[hdr->sock_index].sockopts.FIP_TOS;
	//secure_metadata_writeToElement(meta, "send_tos", &tos, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	secure_metadata_writeToElement(meta, "serial_num", &serial_num, META_TYPE_INT32);

	uint32_t sent = daemon_fdf_to_switch(module, DAEMON_FLOW_TCP, data_len, data, meta);
	if (sent > 0) {
		if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			PRINT_DEBUG("inserting call: hdr=%p", hdr);
			md->calls[hdr->call_index].serial_num = serial_num;
			md->calls[hdr->call_index].flags = flags;
			md->calls[hdr->call_index].buf = data_len;
			md->calls[hdr->call_index].sent = sent;

			if (flags & (MSG_DONTWAIT)) {
				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			}
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(meta);
		free(data);
	}
}

/**
 * @function recvfrom_tcp
 * @param symbol tells if an address has been passed from the application to get the sender address or not
 *	Note this method is coded to be thread safe since UDPreadFrom_fins mimics blocking and needs to be threaded.
 *
 */
void recvmsg_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int buf_len, uint32_t msg_controllen, int flags) {
	PRINT_DEBUG("Entered: hdr=%p, data_len=%d, msg_controllen=%u, flags=%d", hdr, buf_len, msg_controllen, flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("SOCK_NONBLOCK=%d, SOCK_CLOEXEC=%d, O_NONBLOCK=%d, O_ASYNC=%d",
			(SOCK_NONBLOCK & flags)>0, (SOCK_CLOEXEC & flags)>0, (O_NONBLOCK & flags)>0, (O_ASYNC & flags)>0);
	PRINT_DEBUG( "MSG_CMSG_CLOEXEC=%d, MSG_DONTWAIT=%d, MSG_ERRQUEUE=%d, MSG_OOB=%d, MSG_PEEK=%d, MSG_TRUNC=%d, MSG_WAITALL=%d",
			(MSG_CMSG_CLOEXEC & flags)>0, (MSG_DONTWAIT & flags)>0, (MSG_ERRQUEUE & flags)>0, (MSG_OOB & flags)>0, (MSG_PEEK & flags)>0, (MSG_TRUNC & flags)>0, (MSG_WAITALL & flags)>0);

	switch (md->sockets[hdr->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_WARN("todo error");
		//TODO buffer data & send ACK
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	case SS_CONNECTING:
	case SS_CONNECTED:
		break;
	case SS_DISCONNECTING:
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	default:
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	struct daemon_store *store = NULL;
	uint32_t addr_len;
	uint32_t data_len = 0;
	uint8_t *data = NULL;
	metadata *meta;

	if (flags & MSG_ERRQUEUE) {
		//TODO no error queue for TCP
		PRINT_WARN("todo error");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("before: sock_index=%d, data_buf=%d", hdr->sock_index, md->sockets[hdr->sock_index].data_buf);
	if (md->sockets[hdr->sock_index].data_buf > 0) {
		store = (struct daemon_store *) list_remove_front(md->sockets[hdr->sock_index].data_list);
		data_len = store->ff->dataFrame.pduLength;
		data = store->ff->dataFrame.pdu;
		PRINT_DEBUG("removed store: store=%p, ff=%p, data_len=%u, data=%p, pos=%u", store, store->ff, data_len, data, store->pos);

		md->sockets[hdr->sock_index].data_buf -= data_len - store->pos;
		PRINT_DEBUG("after: sock_index=%d, data_buf=%d", hdr->sock_index, md->sockets[hdr->sock_index].data_buf);

		if (store->addr->ss_family == AF_INET) {
			addr_len = sizeof(struct sockaddr_in);
			struct sockaddr_in *addr4 = (struct sockaddr_in *) store->addr;

			uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			uint32_t host_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
			uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			uint32_t rem_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);

			addr4->sin_addr.s_addr = htonl(rem_ip);
			addr4->sin_port = htons(rem_port);

			meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
		} else { //AF_INET6
			addr_len = sizeof(struct sockaddr_in6);
			//struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) store->addr;

			PRINT_WARN("todo");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
	} else {
		PRINT_DEBUG("status=0x%x, test=%d", md->sockets[hdr->sock_index].status, !(md->sockets[hdr->sock_index].status & DAEMON_STATUS_RD));
		if (!(md->sockets[hdr->sock_index].status & DAEMON_STATUS_RD)) {
			uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			uint32_t rem_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);

			addr_len = sizeof(struct sockaddr_in);

			struct sockaddr_storage addr;
			struct sockaddr_in *addr4 = (struct sockaddr_in *) &addr;

			//TODO check addressing & remove if not right?
			addr4->sin_addr.s_addr = htonl(rem_ip);
			addr4->sin_port = htons(rem_port);

			int ret = send_wedge_recvmsg(module, hdr, 0, addr_len, &addr, 0, NULL, 0, NULL);
			if (!ret) {
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
			return;
		}
	}

	if (store != NULL) {
		secure_metadata_readFromElement(store->ff->metaData, "recv_stamp", &md->sockets[hdr->sock_index].stamp);
		PRINT_DEBUG("stamp=%u.%u", (uint32_t)md->sockets[hdr->sock_index].stamp.tv_sec, (uint32_t)md->sockets[hdr->sock_index].stamp.tv_usec);

		uint32_t msg_flags = 0;

		uint32_t msg_len;
		if (buf_len < data_len - store->pos) {
			msg_len = buf_len;
		} else {
			msg_len = data_len - store->pos;
		}
		uint8_t *msg = data + store->pos;

		//#######
#ifdef DEBUG
		uint8_t *temp = (uint8_t *) secure_malloc(msg_len + 1);
		memcpy(temp, msg, msg_len);
		temp[msg_len] = '\0';
		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, temp);
		free(temp);

		if (0) { //TODO change to func, print_hex
			print_hex(msg_len, msg);
		}
#endif
		//#######

		int32_t control_len;
		uint8_t *control;
		int ret_val = recvmsg_control(module, hdr, &msg_flags, store->ff->metaData, msg_controllen, flags, &control_len, &control);

		int ret = send_wedge_recvmsg(module, hdr, msg_flags, addr_len, store->addr, msg_len, msg, control_len, control);
		if (!ret) {
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}

		if (msg_len == data_len - store->pos) {
			daemon_store_free(store);
		} else {
			if (flags & MSG_ERRQUEUE) {
				daemon_store_free(store);
			} else {
				store->pos += msg_len;
				PRINT_DEBUG("prepending store: store=%p, ff=%p, data_len=%u, data=%p, pos=%u", store, store->ff, data_len, data, store->pos);
				list_prepend(md->sockets[hdr->sock_index].data_list, store);
				md->sockets[hdr->sock_index].data_buf += data_len - store->pos;
			}
		}

		if (ret_val != 0) {
			free(control);
		}

		//send size back to TCP handlers
		uint32_t family = md->sockets[hdr->sock_index].family;
		secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
		uint32_t state = md->sockets[hdr->sock_index].state;
		secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
		secure_metadata_writeToElement(meta, "value", &msg_len, META_TYPE_INT32);

		if (daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, gen_control_serial_num(), CTRL_SET_PARAM, SET_PARAM_TCP_HOST_WINDOW)) {
			PRINT_DEBUG("Exited, normal: hdr=%p", hdr);
		} else {
			PRINT_ERROR("Exited, fail sending flow msgs: hdr=%p", hdr);
			metadata_destroy(meta);
		}
		return;
	}

	if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
		PRINT_DEBUG("inserting call: hdr=%p", hdr);
		md->calls[hdr->call_index].flags = flags;
		md->calls[hdr->call_index].buf = buf_len;
		md->calls[hdr->call_index].ret = msg_controllen;

		struct linked_list *call_list = md->sockets[hdr->sock_index].call_list;
		if (list_has_space(call_list)) {
			list_append(call_list, &md->calls[hdr->call_index]);

			if (flags & (MSG_DONTWAIT)) {
				timer_once_start(md->calls[hdr->call_index].to_data->tid, DAEMON_BLOCK_DEFAULT);
			}
		} else {
			PRINT_ERROR("call_list full");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Insert fail: hdr=%p", hdr);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void release_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr) { //TODO finish
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	struct daemon_data *md = (struct daemon_data *) module->data;

	metadata *meta;
	if (md->sockets[hdr->sock_index].family == AF_INET) {
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

		meta = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(meta);

		uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
		secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
		uint32_t host_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
		secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
		if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
			uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
			uint32_t rem_port = (uint32_t) addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
			secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
		}
	} else if (md->sockets[hdr->sock_index].family == AF_INET6) {
		daemon_sockets_remove(module, hdr->sock_index);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	} else { //AF_UNSPEC
		daemon_sockets_remove(module, hdr->sock_index);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	uint32_t family = md->sockets[hdr->sock_index].family;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

	uint32_t serial_num = gen_control_serial_num();
	uint32_t exec_call;
	if (md->sockets[hdr->sock_index].listening != 0) {
		exec_call = DAEMON_EXEC_TCP_CLOSE_STUB;
	} else if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
		exec_call = DAEMON_EXEC_TCP_CLOSE;
	} else {
		daemon_sockets_remove(module, hdr->sock_index);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		return;
	}

	PRINT_DEBUG("serial_num=%u, state=%u, exec_call=%u", serial_num, md->sockets[hdr->sock_index].state, exec_call);

	uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, exec_call);
	if (sent > 0) {
		if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
			PRINT_DEBUG("inserting call: hdr=%p", hdr);
			md->calls[hdr->call_index].serial_num = serial_num;
			md->calls[hdr->call_index].sent = sent;
		} else {
			PRINT_ERROR("Insert fail: hdr=%p", hdr);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	} else {
		PRINT_ERROR("Exited: failed to send ff");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		metadata_destroy(meta);
	}
}

void poll_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t events) {
	PRINT_DEBUG("Entered: hdr=%p, events=0x%x", hdr, events);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t mask = 0;

	if (events) { //initial
		PRINT_DEBUG("POLLIN=%x, POLLPRI=%x, POLLOUT=%x, POLLERR=%x, POLLHUP=%x, POLLNVAL=%x, POLLRDNORM=%x, POLLRDBAND=%x, POLLWRNORM=%x, POLLWRBAND=%x",
				(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

		if (events & (POLLERR)) {
			PRINT_WARN("todo: POLLERR");
		}

		if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
			if (md->sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM | POLLPRI; //TODO check man page says should be set in revents even if data_buf==0
			}
		}

		if (events & (POLLHUP)) {
			//mask |= POLLHUP; //TODO implement
		}

		if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
			//TODO update for AF_INET6 //######################################################################################

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

			uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
			uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);

			if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
				PRINT_DEBUG("poll address: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
			} else {
				PRINT_DEBUG("poll address: host=%u:%u", host_ip, host_port);
			}

			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t initial = 1;
			secure_metadata_writeToElement(meta, "initial", &initial, META_TYPE_INT32);
			uint32_t family = AF_INET;
			secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
			uint32_t state = md->sockets[hdr->sock_index].state;
			secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "flags", &events, META_TYPE_INT32);

			secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
			if (state > SS_UNCONNECTED) {
				secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
			}

			uint32_t serial_num = gen_control_serial_num();
			uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, DAEMON_EXEC_TCP_POLL);
			if (sent > 0) {
				if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
					PRINT_DEBUG("inserting call: hdr=%p", hdr);
					md->calls[hdr->call_index].serial_num = serial_num;
					md->calls[hdr->call_index].buf = events;
					md->calls[hdr->call_index].flags = initial; //is initial
					md->calls[hdr->call_index].ret = mask;
					md->calls[hdr->call_index].sent = sent;

					struct linked_list *call_list = md->sockets[hdr->sock_index].call_list;
					if (list_has_space(call_list)) {
						list_append(call_list, &md->calls[hdr->call_index]);
						PRINT_DEBUG("");
					} else {
						PRINT_ERROR("call_list full");
						nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
					}
				} else {
					PRINT_ERROR("Insert fail: hdr=%p", hdr);
					nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
				}
			} else {
				PRINT_ERROR("Exited: failed to send ff");
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
				metadata_destroy(meta);
			}
			return;
		}

		uint32_t ret_mask = events & mask;
		PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
		if (ret_mask) {
			ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
		} else {
			struct daemon_call *call = daemon_call_create(hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index);
			call->buf = events;
			call->ret = 0;

			struct linked_list *call_list = md->sockets[hdr->sock_index].call_list;
			if (list_has_space(call_list)) {
				list_append(call_list, call);

				PRINT_DEBUG("");
				ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				PRINT_ERROR("call_list full");
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		}
	} else { //final
		struct daemon_call *call =
				(struct daemon_call *) list_find2(md->sockets[hdr->sock_index].call_list, daemon_call_pid_test, &hdr->call_pid, &hdr->call_type);
		if (call) {
			events = call->buf;
			mask = call->ret;

			list_remove(md->sockets[hdr->sock_index].call_list, call);
			if (call->alloc) {
				daemon_call_free(call);
			} else {
				PRINT_WARN("todo error");
			}

			uint32_t ret_mask = events & mask;
			PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
			if (ret_mask) {
				ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
			} else {
				PRINT_DEBUG(
						"POLLIN=%x, POLLPRI=%x, POLLOUT=%x, POLLERR=%x, POLLHUP=%x, POLLNVAL=%x, POLLRDNORM=%x, POLLRDBAND=%x, POLLWRNORM=%x, POLLWRBAND=%x",
						(events & POLLIN) > 0, (events & POLLPRI) > 0, (events & POLLOUT) > 0, (events & POLLERR) > 0, (events & POLLHUP) > 0, (events & POLLNVAL) > 0, (events & POLLRDNORM) > 0, (events & POLLRDBAND) > 0, (events & POLLWRNORM) > 0, (events & POLLWRBAND) > 0);

				if (events & (POLLERR)) {
					PRINT_WARN("todo: POLLERR");
				}

				if (events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
					if (md->sockets[hdr->sock_index].data_buf > 0) {
						mask |= POLLIN | POLLRDNORM | POLLPRI; //TODO check man page says should be set in revents even if data_buf==0
					}
				}

				if (events & (POLLHUP)) {
					//mask |= POLLHUP; //TODO implement
				}

				if (events & (POLLOUT | POLLWRNORM | POLLWRBAND)) { //same as second one
					PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
							md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

					uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
					uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
					uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
					uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);

					if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
						PRINT_DEBUG("poll address: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
					} else {
						PRINT_DEBUG("poll address: host=%u:%u", host_ip, host_port);
					}

					metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
					metadata_create(meta);

					uint32_t initial = 0;
					secure_metadata_writeToElement(meta, "initial", &initial, META_TYPE_INT32);
					uint32_t family = AF_INET;
					secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
					uint32_t state = md->sockets[hdr->sock_index].state;
					secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
					secure_metadata_writeToElement(meta, "flags", &events, META_TYPE_INT32);

					secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
					secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
					if (state > SS_UNCONNECTED) {
						secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
						secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
					}

					uint32_t serial_num = gen_control_serial_num();
					uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, DAEMON_EXEC_TCP_POLL);
					if (sent > 0) {
						if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
							PRINT_DEBUG("inserting call: hdr=%p", hdr);
							md->calls[hdr->call_index].serial_num = serial_num;
							md->calls[hdr->call_index].buf = events;
							md->calls[hdr->call_index].flags = initial; //is final
							md->calls[hdr->call_index].ret = mask;
							md->calls[hdr->call_index].sent = sent;

							struct linked_list *call_list = md->sockets[hdr->sock_index].call_list;
							if (list_has_space(call_list)) {
								list_append(call_list, &md->calls[hdr->call_index]);
								PRINT_DEBUG("");
							} else {
								PRINT_ERROR("call_list full");
								nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
							}
						} else {
							PRINT_ERROR("Insert fail: hdr=%p", hdr);
							nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
						}
					} else {
						PRINT_ERROR("Exited: failed to send ff");
						nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
						metadata_destroy(meta);
					}
					return;
				}
				ret_mask = events & mask;
				PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
				ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, ret_mask);
			}
		} else {
			PRINT_WARN("final: no corresponding call: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
					hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);

			//if (md->daemon_sockets[hdr->sock_index].error_buf > 0) {mask |= POLLERR;}

			if (md->sockets[hdr->sock_index].data_buf > 0) {
				mask |= POLLIN | POLLRDNORM | POLLPRI; //TODO check man page says should be set in revents even if data_buf==0
			}

			//mask |= POLLOUT | POLLWRNORM | POLLWRBAND;

			//mask |= POLLHUP; //TODO implement

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

			uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
			uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
			uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);

			if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
				PRINT_DEBUG("poll address: host=%u:%u, rem=%u:%u", host_ip, host_port, rem_ip, rem_port);
			} else {
				PRINT_DEBUG("poll address: host=%u:%u", host_ip, host_port);
			}

			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t initial = 0;
			secure_metadata_writeToElement(meta, "initial", &initial, META_TYPE_INT32);
			uint32_t family = AF_INET;
			secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
			uint32_t state = md->sockets[hdr->sock_index].state;
			secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "flags", &events, META_TYPE_INT32);

			secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
			secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
			if (state > SS_UNCONNECTED) {
				secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
				secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
			}

			uint32_t serial_num = gen_control_serial_num();
			uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_EXEC, DAEMON_EXEC_TCP_POLL);
			if (sent > 0) {
				if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
					PRINT_DEBUG("inserting call: hdr=%p", hdr);
					md->calls[hdr->call_index].serial_num = serial_num;
					md->calls[hdr->call_index].buf = events;
					md->calls[hdr->call_index].flags = initial; //is final
					md->calls[hdr->call_index].ret = mask;
					md->calls[hdr->call_index].sent = sent;

					struct linked_list *call_list = md->sockets[hdr->sock_index].call_list;
					if (list_has_space(call_list)) {
						list_append(call_list, &md->calls[hdr->call_index]);
						PRINT_DEBUG("");
					} else {
						PRINT_ERROR("call_list full");
						nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
					}
				} else {
					PRINT_ERROR("Insert fail: hdr=%p", hdr);
					nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
				}
			} else {
				PRINT_ERROR("Exited: failed to send ff");
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
				metadata_destroy(meta);
			}
			return;
		}
	}
}

void mmap_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	PRINT_WARN("todo");
}
void socketpair_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	PRINT_WARN("todo");
}

void shutdown_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int how) {
	PRINT_DEBUG("Entered: hdr=%p, how=%d", hdr, how);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t how_daemon;
	if (how == SHUT_RD) {
		how_daemon = DAEMON_STATUS_RD;
	} else if (how == SHUT_WR) {
		how_daemon = DAEMON_STATUS_WR;
	} else if (how == SHUT_RDWR) {
		how_daemon = DAEMON_STATUS_RDWR;
	} else {
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EINVAL);
		return;
	}

	if (md->sockets[hdr->sock_index].state == SS_CONNECTED) {
		uint32_t and_test = md->sockets[hdr->sock_index].status & how_daemon;
		PRINT_DEBUG("before: status=0x%x, how=0x%x, and=0x%x", md->sockets[hdr->sock_index].status, how_daemon, and_test);
		if (and_test) {
			md->sockets[hdr->sock_index].status &= ~and_test;
			PRINT_DEBUG("after: status=0x%x, how=0x%x, and=0x%x", md->sockets[hdr->sock_index].status, how_daemon, and_test);

			metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
			metadata_create(meta);

			uint32_t family = AF_INET;
			secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
			uint32_t state = md->sockets[hdr->sock_index].state;
			secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

			uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
			secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
			uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
			secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
			if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
				uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
				secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
				uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
				secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
			}

			secure_metadata_writeToElement(meta, "value", &and_test, META_TYPE_INT32);

			if (daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, gen_control_serial_num(), CTRL_ALERT, DAEMON_ALERT_SHUTDOWN)) {
				ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
			} else {
				PRINT_ERROR("Exited: failed to send ff");
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
				metadata_destroy(meta);
			}
		} else {
			ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
		}
	} else {
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, ENOTCONN);
	}
}

void close_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	PRINT_WARN("todo");
}

void sendpage_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr) {
	PRINT_DEBUG("Entered: hdr=%p", hdr);
	PRINT_WARN("todo");
}

void getsockopt_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval) {
	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

	uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
	secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
	uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
	secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
		uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
		secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
		uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
		secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
	}

	int send_dst = -1;
	int len = 0;
	uint8_t *val = NULL;

	uint32_t param_id = optname;

	switch (optname) {
	case SO_DEBUG:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_DEBUG; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_REUSEADDR:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_REUSEADDR; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_TYPE:
#ifndef BUILD_FOR_ANDROID
	case SO_PROTOCOL:
	case SO_DOMAIN:
#endif
	case SO_ERROR:
	case SO_DONTROUTE:
	case SO_BROADCAST:
		break;
	case SO_SNDBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_SNDBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_SNDBUFFORCE:
		break;
	case SO_RCVBUF:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_RCVBUF; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_RCVBUFFORCE:
		break;
	case SO_KEEPALIVE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_OOBINLINE:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_OOBINLINE; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_NO_CHECK:
		break;
	case SO_PRIORITY:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_PRIORITY; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_LINGER:
	case SO_BSDCOMPAT:
	case SO_TIMESTAMP:
#ifndef BUILD_FOR_ANDROID
	case SO_TIMESTAMPNS:
	case SO_TIMESTAMPING:
#endif
	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
	case SO_RCVLOWAT:
	case SO_SNDLOWAT:
		break;
	case SO_PASSCRED:
		if (optlen >= sizeof(int)) {
			len = sizeof(int);
			val = (uint8_t *) &md->sockets[hdr->sock_index].sockopts.FSO_PASSCRED; //TODO move into sem's
			send_dst = 0;
		}
		break;
	case SO_PEERCRED:
		//TODO trickier
	case SO_PEERNAME:
	case SO_ACCEPTCONN:
	case SO_PASSSEC:
	case SO_PEERSEC:
#ifndef BUILD_FOR_ANDROID
	case SO_MARK:
	case SO_RXQ_OVFL:
#endif
	case SO_ATTACH_FILTER:
	case SO_DETACH_FILTER:
		break;
	default:
		//nack?
		PRINT_ERROR("default=%d", optname);
		break;
	}

	if (send_dst == -1) {
		PRINT_ERROR("send_dst == -1");
		metadata_destroy(meta);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else if (send_dst == 0) {
		metadata_destroy(meta);

		//send msg to wedge
		int msg_len = sizeof(struct daemon_to_wedge_hdr) + sizeof(int) + (len > 0 ? len : 0);
		uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

		struct daemon_to_wedge_hdr *hdr_ret = (struct daemon_to_wedge_hdr *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		uint8_t *pt = msg + sizeof(struct daemon_to_wedge_hdr);

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
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
		if (send_wedge(module, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		} else {
			PRINT_DEBUG("Exited: normal: hdr=%p", hdr);
		}
		free(msg);
	} else {
		uint32_t serial_num = gen_control_serial_num();
		uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_READ_PARAM, param_id);
		if (sent > 0) {
			if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				PRINT_DEBUG("inserting call: hdr=%p", hdr);
				md->calls[hdr->call_index].serial_num = serial_num;
				md->calls[hdr->call_index].buf = optname;
				md->calls[hdr->call_index].sent = sent;
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("Exited: failed to send ff");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			metadata_destroy(meta);
		}
	}
}

void setsockopt_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval) {
	PRINT_DEBUG("Entered: hdr=%p, level=%d, optname=%d, optlen=%d", hdr, level, optname, optlen);
	struct daemon_data *md = (struct daemon_data *) module->data;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[hdr->sock_index].sock_id, hdr->sock_index, md->sockets[hdr->sock_index].state, addr4_get_ip(&md->sockets[hdr->sock_index].host_addr), addr4_get_port(&md->sockets[hdr->sock_index].host_addr), addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr), addr4_get_port(&md->sockets[hdr->sock_index].rem_addr));

	metadata *meta = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[hdr->sock_index].state;
	secure_metadata_writeToElement(meta, "state", &state, META_TYPE_INT32);

	uint32_t host_ip = addr4_get_ip(&md->sockets[hdr->sock_index].host_addr);
	secure_metadata_writeToElement(meta, "host_ip", &host_ip, META_TYPE_INT32);
	uint32_t host_port = addr4_get_port(&md->sockets[hdr->sock_index].host_addr);
	secure_metadata_writeToElement(meta, "host_port", &host_port, META_TYPE_INT32);
	if (md->sockets[hdr->sock_index].state > SS_UNCONNECTED) {
		uint32_t rem_ip = addr4_get_ip(&md->sockets[hdr->sock_index].rem_addr);
		secure_metadata_writeToElement(meta, "rem_ip", &rem_ip, META_TYPE_INT32);
		uint32_t rem_port = addr4_get_port(&md->sockets[hdr->sock_index].rem_addr);
		secure_metadata_writeToElement(meta, "rem_port", &rem_port, META_TYPE_INT32);
	}

	int send_dst = -1;
	//int len = 0;
	//uint8_t *val = NULL;

	uint32_t param_id = optname;

	switch (level) {
	case SOL_IP:
		PRINT_WARN("todo error");
		break;
	case SOL_RAW:
		PRINT_WARN("todo error");
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
				md->sockets[hdr->sock_index].sockopts.FSO_DEBUG = *(int *) optval;

				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_DEBUG, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_REUSEADDR:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_REUSEADDR = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_REUSEADDR, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_TYPE:
#ifndef BUILD_FOR_ANDROID
		case SO_PROTOCOL:
		case SO_DOMAIN:
#endif
		case SO_ERROR:
		case SO_DONTROUTE:
		case SO_BROADCAST:
			break;
		case SO_SNDBUF:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_SNDBUF = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_SNDBUF, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_SNDBUFFORCE:
			break;
		case SO_RCVBUF:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_RCVBUF = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_RCVBUF, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_RCVBUFFORCE:
			break;
		case SO_KEEPALIVE:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_KEEPALIVE, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_OOBINLINE:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_OOBINLINE = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_OOBINLINE, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_NO_CHECK:
			break;
		case SO_PRIORITY:
			if (optlen >= sizeof(int)) {
				md->sockets[hdr->sock_index].sockopts.FSO_PRIORITY = *(int *) optval;
				secure_metadata_writeToElement(meta, "value", &md->sockets[hdr->sock_index].sockopts.FSO_PRIORITY, META_TYPE_INT32);
				send_dst = 1;
			}
			break;
		case SO_LINGER:
		case SO_BSDCOMPAT:
		case SO_TIMESTAMP:
#ifndef BUILD_FOR_ANDROID
		case SO_TIMESTAMPNS:
		case SO_TIMESTAMPING:
#endif
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
#ifndef BUILD_FOR_ANDROID
		case SO_MARK:
		case SO_RXQ_OVFL:
#endif
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
		PRINT_ERROR("Error");

		metadata_destroy(meta);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	} else if (send_dst == 0) {
		metadata_destroy(meta);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		uint32_t serial_num = gen_control_serial_num();

		uint32_t sent = daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta, serial_num, CTRL_SET_PARAM, param_id);
		if (sent > 0) {
			if (daemon_calls_insert(module, hdr->call_id, hdr->call_index, hdr->call_pid, hdr->call_type, hdr->sock_id, hdr->sock_index)) {
				PRINT_DEBUG("inserting call: hdr=%p", hdr);
				md->calls[hdr->call_index].serial_num = serial_num;
				md->calls[hdr->call_index].sent = sent;
			} else {
				PRINT_ERROR("Insert fail: hdr=%p", hdr);
				nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			}
		} else {
			PRINT_ERROR("Exited: failed to send ff");
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			metadata_destroy(meta);
		}
	}
}

void connect_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index, call->flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_CONNECT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);

	if (ff->ctrlFrame.ret_val == FCF_TRUE) {
		md->sockets[call->sock_index].state = SS_CONNECTED;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

		ack_send(module, call->id, call->index, call->type, 0);
	} else {
		md->sockets[call->sock_index].state = SS_UNCONNECTED;
		md->sockets[call->sock_index].error_call = call->type;
		md->sockets[call->sock_index].error_msg = ret_msg;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

		nack_send(module, call->id, call->index, call->type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void accept_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, sock_id_new=%llu, sock_index_new=%d, flags=%u",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index, call->sock_id_new, call->sock_index_new, call->flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_ACCEPT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);
	uint32_t rem_ip;
	secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
	uint32_t rem_port;
	secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);

	if (ff->ctrlFrame.ret_val == FCF_TRUE) {
		if (daemon_sockets_insert(module, call->sock_id_new, call->sock_index_new, md->sockets[call->sock_index].type, md->sockets[call->sock_index].protocol,
				&tcp_out_ops, &tcp_in_ops, &tcp_other_ops)) {
			md->sockets[call->sock_index_new].family = md->sockets[call->sock_index].family;
			md->sockets[call->sock_index_new].state = SS_CONNECTED;
			memcpy(&md->sockets[call->sock_index_new].host_addr, &md->sockets[call->sock_index].host_addr, sizeof(struct sockaddr_storage));
			addr4_set_ip(&md->sockets[call->sock_index_new].rem_addr, rem_ip);
			addr4_set_port(&md->sockets[call->sock_index_new].rem_addr, (uint16_t) rem_port);

			PRINT_DEBUG("Accept socket created: sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index_new].sock_id, call->sock_index_new, md->sockets[call->sock_index_new].state, addr4_get_ip(&md->sockets[call->sock_index_new].host_addr), addr4_get_port(&md->sockets[call->sock_index_new].host_addr), addr4_get_ip(&md->sockets[call->sock_index_new].rem_addr), addr4_get_port(&md->sockets[call->sock_index_new].rem_addr));

			md->sockets[call->sock_index].state = SS_UNCONNECTED;
			md->sockets[call->sock_index].sock_id_new = -1;
			md->sockets[call->sock_index].sock_index_new = -1;

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

			ack_send(module, call->id, call->index, call->type, 0);
		} else {
			PRINT_ERROR("Exited: insert failed: ff=%p", ff);

			md->sockets[call->sock_index].state = SS_UNCONNECTED;
			md->sockets[call->sock_index].error_call = call->type;
			md->sockets[call->sock_index].error_msg = 0; //TODO fill in special value?

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

			nack_send(module, call->id, call->index, call->type, 1);
		}
	} else {
		md->sockets[call->sock_index].state = SS_UNCONNECTED;
		md->sockets[call->sock_index].error_call = call->type;
		md->sockets[call->sock_index].error_msg = ret_msg;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

		nack_send(module, call->id, call->index, call->type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void sendmsg_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, flags=%u",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index, call->flags);

	if (ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_SEND) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);

	if (ff->ctrlFrame.ret_val == FCF_TRUE) {
		ack_send(module, call->id, call->index, call->type, ret_msg);
	} else {
		nack_send(module, call->id, call->index, call->type, ret_msg);
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void getsockopt_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index, call->buf);

	if ((int) ff->ctrlFrame.param_id != (int) call->buf || ff->ctrlFrame.ret_val == FCF_FALSE) { //TODO remove (int)'s?
		PRINT_DEBUG("Exiting, meta errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
	} else {

		//################ //TODO switch by param_id, convert into val/len
		int len = 0;
		uint8_t *val = NULL;
		//################

		//send msg to wedge
		int msg_len = sizeof(struct daemon_to_wedge_hdr) + sizeof(int) + (len > 0 ? len : 0);
		uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

		struct daemon_to_wedge_hdr *hdr_ret = (struct daemon_to_wedge_hdr *) msg;
		hdr_ret->call_type = call->type;
		hdr_ret->call_id = call->id;
		hdr_ret->call_index = call->index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		uint8_t *pt = msg + sizeof(struct daemon_to_wedge_hdr);

		*(int *) pt = len;
		pt += sizeof(int);

		if (len > 0) {
			memcpy(pt, val, len);
			pt += len;
		}

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);

			nack_send(module, call->id, call->index, call->type, 1);
			daemon_call_free(call);
			freeFinsFrame(ff);
			return;
		}

		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
		if (send_wedge(module, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: fail send_wedge: ff=%p", ff);
			nack_send(module, call->id, call->index, call->type, 1);
		} else {
			PRINT_DEBUG("Exited: normal: ff=%p", ff);
		}
		free(msg);
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void setsockopt_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index, call->buf);

	if ((int) ff->ctrlFrame.param_id != (int) call->buf || ff->ctrlFrame.ret_val == FCF_FALSE) { //TODO remove (int)'s?
		PRINT_DEBUG("Exited: meta errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
	} else {
		PRINT_DEBUG("Exited: normal: ff=%p", ff);
		ack_send(module, call->id, call->index, call->type, 0);
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void release_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_type=%u, sock_id=%llu, sock_index=%d",
			ff, call->id, call->index, call->type, call->sock_id, call->sock_index);

	if ((ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_CLOSE && ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_CLOSE_STUB) || ff->ctrlFrame.ret_val == FCF_FALSE) {
		PRINT_DEBUG("Exiting, NACK: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
	} else {
		PRINT_DEBUG("");
		daemon_sockets_remove(module, call->sock_index);
		PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
		ack_send(module, call->id, call->index, call->type, 0);
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void poll_in_tcp_fcf(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call) {
	PRINT_DEBUG("Entered: ff=%p, call_id=%u, call_index=%d, call_pid=%d, call_type=%u, sock_id=%llu, sock_index=%d, data=%u, flags=%u",
			ff, call->id, call->index, call->pid, call->type, call->sock_id, call->sock_index, call->buf, call->flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t ret_msg = 0;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);
	//secure_metadata_readFromElement(ff->metaData, "mask", &mask);

	if ((ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_POLL) || ff->ctrlFrame.ret_val == FCF_FALSE) {
		PRINT_ERROR("Exiting, NACK: ff=%p, param_id=%d, ret_val=%u", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		nack_send(module, call->id, call->index, call->type, 1);
	} else {
		if (ret_msg) {
			ack_send(module, call->id, call->index, call->type, ret_msg);
		} else {
			if (call->flags) { //flags == initial
				//struct daemon_call *call_store = daemon_call_create(call->id, call->index, call->pid, call->type, call->sock_id, call->sock_index);
				//call_store->buf = call->buf;
				//call_store->ret = 0;
				call->ret = 0;

				struct linked_list *call_list = md->sockets[call->sock_index].call_list;
				if (list_has_space(call_list)) {
					//list_append(call_list, call_store);
					list_append(call_list, call);
					PRINT_DEBUG("");
					ack_send(module, call->id, call->index, call->type, 0);
				} else {
					PRINT_ERROR("call_list full");
					nack_send(module, call->id, call->index, call->type, 1);
				}
			} else {
				ack_send(module, call->id, call->index, call->type, 0);
			}
		}
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void poll_in_tcp_fdf(struct daemon_call *call, struct fins_module *module, uint32_t *flags) {
	if (call->type == POLL_CALL) {
		return;
	}

	PRINT_DEBUG("Entered: call=%p, flags=%u", call, *flags);
	uint32_t events = call->buf;

	PRINT_DEBUG(
			"POLLIN=0x%x, POLLPRI=0x%x, POLLOUT=0x%x, POLLERR=0x%x, POLLHUP=0x%x, POLLNVAL=0x%x, POLLRDNORM=0x%x, POLLRDBAND=0x%x, POLLWRNORM=0x%x, POLLWRBAND=0x%x",
			events & POLLIN, events & POLLPRI, events & POLLOUT, events & POLLERR, events & POLLHUP, events & POLLNVAL, events & POLLRDNORM, events & POLLRDBAND, events & POLLWRNORM, events & POLLWRBAND);

	uint32_t mask = 0;

	if (*flags & POLLERR) {
		mask |= POLLERR;
	}

	if (*flags & POLLHUP) {
		mask |= POLLHUP;
	}

	if (*flags & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) {
		mask |= POLLIN | POLLRDNORM | POLLPRI; //TODO check man page says should be set in revents even if data_buf==0
	}

	if (*flags & (POLLOUT | POLLWRNORM | POLLWRBAND)) {
		mask |= POLLOUT | POLLWRNORM | POLLWRBAND;
	}

	uint32_t ret_mask = events & mask;
	PRINT_DEBUG("events=0x%x, mask=0x%x, ret_mask=0x%x", events, mask, ret_mask);
	if (ret_mask) {
		//send msg to wedge
		int msg_len = sizeof(struct daemon_to_wedge_hdr);
		uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

		struct daemon_to_wedge_hdr *hdr_ret = (struct daemon_to_wedge_hdr *) msg;
		hdr_ret->call_type = POLL_EVENT_CALL;
		hdr_ret->sock_id = call->sock_id;
		hdr_ret->sock_index = call->sock_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = ret_mask;
		uint8_t *pt = msg + sizeof(struct daemon_to_wedge_hdr);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			return;
		}

		PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
		if (send_wedge(module, msg, msg_len, 0)) {
			PRINT_ERROR("Exited: send_wedge error: call=%p", call);
		} else {

		}
		free(msg);

		call->ret |= ret_mask;
	}
}

uint32_t recvmsg_in_tcp_fdf(struct daemon_call *call, struct fins_module *module, metadata *meta, uint32_t data_len, uint8_t *data,
		struct sockaddr_storage *addr, uint32_t flags) {
	PRINT_DEBUG("Entered: call=%p, meta=%p, len=%u, data=%p, addr=%p, flags=0x%x", call, meta, data_len, data, addr, flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t call_len = call->buf; //buffer size
	uint32_t msg_controllen = call->ret;

	secure_metadata_readFromElement(meta, "recv_stamp", &md->sockets[call->sock_index].stamp);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)md->sockets[call->sock_index].stamp.tv_sec, (uint32_t)md->sockets[call->sock_index].stamp.tv_usec);

	uint32_t msg_flags = 0;

	if (call_len < data_len) {
		data_len = call_len;
	}

	uint32_t addr_len;
	if (addr->ss_family == AF_INET) {
		addr_len = sizeof(struct sockaddr_in);
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		addr4->sin_addr.s_addr = htonl(addr4->sin_addr.s_addr);
		addr4->sin_port = htons(addr4->sin_port);
		PRINT_DEBUG("address: '%s':%d (%u)", inet_ntoa(addr4->sin_addr), ntohs(addr4->sin_port), addr4->sin_addr.s_addr);
	} else { //AF_INET6
		PRINT_WARN("todo");
		nack_send(module, call->id, call->index, call->type, 1);
		daemon_calls_remove(module, call->index);
		return data_len;
	}

	//#######
#ifdef DEBUG
	uint8_t *temp = (uint8_t *) secure_malloc(data_len + 1);
	memcpy(temp, data, data_len);
	temp[data_len] = '\0';
	PRINT_DEBUG("data_len=%d, data='%s'", data_len, temp);
	free(temp);

	if (0) { //TODO change to func, print_hex
		print_hex(data_len, data);
	}
#endif
	//#######

	int32_t control_len;
	uint8_t *control;
	int ret_val = recvmsg_control(module, (struct wedge_to_daemon_hdr *) call, &msg_flags, meta, msg_controllen, flags, &control_len, &control);

	int ret = send_wedge_recvmsg(module, (struct wedge_to_daemon_hdr *) call, msg_flags, addr_len, addr, data_len, data, control_len, control);
	if (!ret) {
		nack_send(module, call->id, call->index, call->type, 1);
	}
	daemon_calls_remove(module, call->index);

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

	if (ret_val != 0) {
		free(control);
	}

	metadata *meta_reply = (metadata *) secure_malloc(sizeof(metadata));
	metadata_create(meta_reply);

	uint32_t value = data_len;
	secure_metadata_writeToElement(meta_reply, "value", &value, META_TYPE_INT32);

	uint32_t family = AF_INET;
	secure_metadata_writeToElement(meta_reply, "family", &family, META_TYPE_INT32);
	uint32_t state = md->sockets[call->sock_index].state;
	secure_metadata_writeToElement(meta_reply, "state", &state, META_TYPE_INT32);

	uint32_t host_ip = addr4_get_ip(&md->sockets[call->sock_index].host_addr);
	secure_metadata_writeToElement(meta_reply, "host_ip", &host_ip, META_TYPE_INT32);
	uint32_t host_port = addr4_get_port(&md->sockets[call->sock_index].host_addr);
	secure_metadata_writeToElement(meta_reply, "host_port", &host_port, META_TYPE_INT32);
	if (md->sockets[call->sock_index].state > SS_UNCONNECTED) {
		uint32_t rem_ip = addr4_get_ip(&md->sockets[call->sock_index].rem_addr);
		secure_metadata_writeToElement(meta_reply, "rem_ip", &rem_ip, META_TYPE_INT32);
		uint32_t rem_port = addr4_get_port(&md->sockets[call->sock_index].rem_addr);
		secure_metadata_writeToElement(meta_reply, "rem_port", &rem_port, META_TYPE_INT32);
	}

	if (daemon_fcf_to_switch(module, DAEMON_FLOW_TCP, meta_reply, gen_control_serial_num(), CTRL_SET_PARAM, SET_PARAM_TCP_HOST_WINDOW)) {
		PRINT_DEBUG("Exited, normal: call=%p", call);
	} else {
		PRINT_ERROR("Exited, fail sending flow msgs: call=%p", call);
		metadata_destroy(meta);
	}

	return data_len;
}

void daemon_in_fdf_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr) {
	PRINT_DEBUG("Entered: ff=%p, family=%u, src_addr=%p, dst_addr=%p", ff, family, src_addr, dst_addr);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t src_port;
	secure_metadata_readFromElement(ff->metaData, "recv_src_port", &src_port);
	uint32_t dst_port;
	secure_metadata_readFromElement(ff->metaData, "recv_dst_port", &dst_port);

	int sock_index;
	if (family == AF_INET) {
		uint32_t src_ip = addr4_get_ip(src_addr);
		uint32_t dst_ip = addr4_get_ip(dst_addr);

		sock_index = match_conn_addr4_tcp(module, src_ip, (uint16_t) src_port, dst_ip, (uint16_t) dst_port);
		if (sock_index == -1) {
			sock_index = match_conn_addr4_tcp(module, src_ip, (uint16_t) src_port, 0, 0);
		}
		if (sock_index == -1) {
			PRINT_WARN("No matching socket, freeing TCP data: ff=%p, src='%u.%u.%u.%u':%u, dst='%u.%u.%u.%u':%u, data_len=%u",
					ff, (src_ip&0xFF000000)>>24, (src_ip&0x00FF0000)>>16, (src_ip&0x0000FF00)>>8, (src_ip&0x000000FF), (uint16_t) src_port, (dst_ip&0xFF000000)>>24, (dst_ip&0x00FF0000)>>16, (dst_ip&0x0000FF00)>>8, (dst_ip&0x000000FF), (uint16_t)dst_port, ff->dataFrame.pduLength);
			freeFinsFrame(ff);
			return;
		}
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[sock_index].sock_id, sock_index, md->sockets[sock_index].state, addr4_get_ip(&md->sockets[sock_index].host_addr), addr4_get_port(&md->sockets[sock_index].host_addr), addr4_get_ip(&md->sockets[sock_index].rem_addr), addr4_get_port(&md->sockets[sock_index].rem_addr));
	} else { //AF_INET
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		return;
	}

	//md->sockets[sock_index].count++; //TODO remove, only for testing
	//PRINT_INFO("count=%d", md->sockets[sock_index].count);

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	secure_metadata_writeToElement(ff->metaData, "recv_stamp", &current, META_TYPE_INT64);

	//TODO check if this datagram comes from the address this socket has been previously connected to it (Only if the socket is already connected to certain address)
	uint32_t flags = POLLIN;
	list_for_each2(md->sockets[sock_index].call_list, poll_in_tcp_fdf, module, &flags);

	uint32_t data_len = ff->dataFrame.pduLength;
	uint8_t *data = ff->dataFrame.pdu;
	uint32_t data_pos = 0;
	flags = 0;
	struct daemon_call *call;

	while (1) {
		call = (struct daemon_call *) list_find1(md->sockets[sock_index].call_list, daemon_call_recvmsg_test, &flags);
		if (call != NULL) {
			data_pos += recvmsg_in_tcp_fdf(call, module, ff->metaData, data_len - data_pos, data + data_pos, dst_addr, 0);
			list_remove(md->sockets[sock_index].call_list, call);

			if (data_pos == ff->dataFrame.pduLength) {
				freeFinsFrame(ff);
				return;
			}
		} else {
			break;
		}
	}

	struct daemon_store *store = (struct daemon_store *) secure_malloc(sizeof(struct daemon_store));
	store->addr = (struct sockaddr_storage *) secure_malloc(sizeof(struct sockaddr_storage));
	memcpy(store->addr, src_addr, sizeof(struct sockaddr_storage));
	store->ff = ff;
	store->pos = data_pos;

	if (list_has_space(md->sockets[sock_index].data_list)) {
		PRINT_DEBUG("appending store: store=%p, ff=%p, data_len=%u, data=%p, pos=%u", store, store->ff, data_len, data, store->pos);
		list_append(md->sockets[sock_index].data_list, store);
		md->sockets[sock_index].data_buf += data_len - store->pos;
		PRINT_DEBUG("stored, sock_index=%d, ff=%p, meta=%p, data_buf=%d", sock_index, ff, ff->metaData, md->sockets[sock_index].data_buf);
	} else {
		PRINT_ERROR("data_list full: sock_index=%d, ff=%p", sock_index, ff);
		daemon_store_free(store);
	}
}

void daemon_in_error_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr,
		struct sockaddr_storage *dst_addr) {
	PRINT_DEBUG("Entered: ff=%p, family=%u, src_addr=%p, dst_addr=%p", ff, family, src_addr, dst_addr);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t src_port;
	secure_metadata_readFromElement(ff->metaData, "recv_src_port", &src_port);
	uint32_t dst_port;
	secure_metadata_readFromElement(ff->metaData, "recv_dst_port", &dst_port);

	int sock_index;
	if (family == AF_INET) {
		uint32_t src_ip = addr4_get_ip(src_addr);
		uint32_t dst_ip = addr4_get_ip(dst_addr);

		//src == host & dst == rem
		sock_index = match_conn_addr4_tcp(module, src_ip, (uint16_t) src_port, dst_ip, (uint16_t) dst_port);
		if (sock_index == -1) {
			sock_index = match_conn_addr4_tcp(module, src_ip, (uint16_t) src_port, 0, 0);
		}
		if (sock_index == -1) {
			PRINT_WARN("No matching socket, freeing TCP error msg: ff=%p, src='%u.%u.%u.%u':%u, dst='%u.%u.%u.%u':%u, data_len=%u",
					ff, (src_ip&0xFF000000)>>24, (src_ip&0x00FF0000)>>16, (src_ip&0x0000FF00)>>8, (src_ip&0x000000FF), (uint16_t) src_port, (dst_ip&0xFF000000)>>24, (dst_ip&0x00FF0000)>>16, (dst_ip&0x0000FF00)>>8, (dst_ip&0x000000FF), (uint16_t)dst_port, ff->ctrlFrame.data_len);
			//TODO change back  to PRINT_ERROR
			freeFinsFrame(ff);
			return;
		}
		PRINT_DEBUG("Matched: sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[sock_index].sock_id, sock_index, md->sockets[sock_index].state, addr4_get_ip(&md->sockets[sock_index].host_addr), addr4_get_port(&md->sockets[sock_index].host_addr), addr4_get_ip(&md->sockets[sock_index].rem_addr), addr4_get_port(&md->sockets[sock_index].rem_addr));
	} else { //AF_INET
		PRINT_WARN("todo");
		freeFinsFrame(ff);
		return;
	}

	struct timeval current;
	gettimeofday(&current, 0);
	PRINT_DEBUG("stamp=%u.%u", (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);
	secure_metadata_writeToElement(ff->metaData, "recv_stamp", &current, META_TYPE_INT64);

	if (md->sockets[sock_index].sockopts.FIP_RECVERR) {
		uint32_t flags = POLLERR;
		list_for_each2(md->sockets[sock_index].call_list, poll_in_tcp_fdf, module, &flags);

		freeFinsFrame(ff);
	} else {
		PRINT_WARN("todo");
		freeFinsFrame(ff);
	}
}

void daemon_in_poll_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: ff=%p, ret_msg=%u", ff, ret_msg);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "family", &family);
	uint32_t state;
	secure_metadata_readFromElement(ff->metaData, "state", &state);

	uint32_t host_ip;
	secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
	uint32_t host_port;
	secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);

	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;
	if (state > SS_UNCONNECTED) {
		secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);
	}

	int sock_index = match_conn_addr4_tcp(module, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
	if (sock_index == -1) {
		sock_index = match_conn_addr4_tcp(module, host_ip, (uint16_t) host_port, 0, 0);
	}
	if (sock_index == -1) {
		PRINT_WARN("No matching socket, freeing poll FCF: ff=%p, src='%u.%u.%u.%u':%u, dst='%u.%u.%u.%u':%u",
				ff, (host_ip&0xFF000000)>>24, (host_ip&0x00FF0000)>>16, (host_ip&0x0000FF00)>>8, (host_ip&0x000000FF), (uint16_t) host_port, (rem_ip&0xFF000000)>>24, (rem_ip&0x00FF0000)>>16, (rem_ip&0x0000FF00)>>8, (rem_ip&0x000000FF), (uint16_t)rem_port);
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[sock_index].sock_id, sock_index, md->sockets[sock_index].state, addr4_get_ip(&md->sockets[sock_index].host_addr), addr4_get_port(&md->sockets[sock_index].host_addr), addr4_get_ip(&md->sockets[sock_index].rem_addr), addr4_get_port(&md->sockets[sock_index].rem_addr));
	list_for_each2(md->sockets[sock_index].call_list, poll_in_tcp_fdf, module, &ret_msg);

	freeFinsFrame(ff);
}

void daemon_in_shutdown_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t ret_msg) {
	PRINT_DEBUG("Entered: ff=%p, ret_msg=%u", ff, ret_msg);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t family;
	secure_metadata_readFromElement(ff->metaData, "family", &family);
	uint32_t state;
	secure_metadata_readFromElement(ff->metaData, "state", &state);

	uint32_t host_ip;
	secure_metadata_readFromElement(ff->metaData, "host_ip", &host_ip);
	uint32_t host_port;
	secure_metadata_readFromElement(ff->metaData, "host_port", &host_port);

	uint32_t rem_ip = 0;
	uint32_t rem_port = 0;
	if (state > SS_UNCONNECTED) {
		secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
		secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);
	}

	int sock_index = match_conn_addr4_tcp(module, host_ip, (uint16_t) host_port, rem_ip, (uint16_t) rem_port);
	if (sock_index == -1) {
		sock_index = match_conn_addr4_tcp(module, host_ip, (uint16_t) host_port, 0, 0);
	}
	if (sock_index == -1) {
		PRINT_WARN("No matching socket, freeing shutdown FCF: ff=%p, src='%u.%u.%u.%u':%u, dst='%u.%u.%u.%u':%u",
				ff, (host_ip&0xFF000000)>>24, (host_ip&0x00FF0000)>>16, (host_ip&0x0000FF00)>>8, (host_ip&0x000000FF), (uint16_t) host_port, (rem_ip&0xFF000000)>>24, (rem_ip&0x00FF0000)>>16, (rem_ip&0x0000FF00)>>8, (rem_ip&0x000000FF), (uint16_t)rem_port);
		freeFinsFrame(ff);
		return;
	}

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
			md->sockets[sock_index].sock_id, sock_index, md->sockets[sock_index].state, addr4_get_ip(&md->sockets[sock_index].host_addr), addr4_get_port(&md->sockets[sock_index].host_addr), addr4_get_ip(&md->sockets[sock_index].rem_addr), addr4_get_port(&md->sockets[sock_index].rem_addr));

	md->sockets[sock_index].status &= ~ret_msg;

	uint32_t flags;

	if (ret_msg & DAEMON_STATUS_WR) {
		//TODO check saved poll calls & return POLLHUP?
		flags = POLLHUP;
		list_for_each2(md->sockets[sock_index].call_list, poll_in_tcp_fdf, module, &flags);
	}

	if (ret_msg & DAEMON_STATUS_RD) {
		flags = 0;
		struct daemon_call *call;
		uint32_t addr_len = sizeof(struct sockaddr_in);
		struct sockaddr_storage addr;
		addr.ss_family = md->sockets[sock_index].family;

		while (1) {
			call = (struct daemon_call *) list_find1(md->sockets[sock_index].call_list, daemon_call_recvmsg_test, &flags);
			if (call != NULL) {
				int ret = send_wedge_recvmsg(module, (struct wedge_to_daemon_hdr *) call, 0, addr_len, &addr, 0, NULL, 0, NULL);
				if (!ret) {
					nack_send(module, call->id, call->index, call->type, 1);
				}
				list_remove(md->sockets[sock_index].call_list, call);
			} else {
				break;
			}
		}
	}

	freeFinsFrame(ff);
}

void connect_timeout_tcp(struct fins_module *module, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);
	struct daemon_data *md = (struct daemon_data *) module->data;

	switch (md->sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check md->daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		if (md->sockets[call->sock_index].error_call == call->type) {
			nack_send(module, call->id, call->index, call->type, md->sockets[call->sock_index].error_msg);

			md->sockets[call->sock_index].error_call = 0; //TODO remove?
			md->sockets[call->sock_index].error_msg = 0;
		}
		break;
	case SS_CONNECTING:
		nack_send(module, call->id, call->index, call->type, EAGAIN); //nack EAGAIN or EWOULDBLOCK, or should it be EINPROGRESS?

		if (call->serial_num != 0) { //was sent outside of module
			struct daemon_call *call_clone = daemon_call_clone(call);
			list_append(md->expired_call_list, call_clone);
		}
		break;
	case SS_CONNECTED:
		ack_send(module, call->id, call->index, call->type, 0);
		break;
	default:
		PRINT_WARN("todo error");
		nack_send(module, call->id, call->index, call->type, 1);
		break;
	}

	daemon_calls_remove(module, call->index);
}

void accept_timeout_tcp(struct fins_module *module, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);
	struct daemon_data *md = (struct daemon_data *) module->data;

	switch (md->sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		//TODO check md->daemon_sockets[hdr->sock_index].error_msg / error_call, such that if nonblocking & expired connect refused
		//TODO check md->daemon_sockets[hdr->sock_index].sock_id_new / sock_index_new, such that if nonblocking & expired accept accomplished
		if (md->sockets[call->sock_index].error_call == call->type) {
			nack_send(module, call->id, call->index, call->type, md->sockets[call->sock_index].error_msg);

			md->sockets[call->sock_index].error_call = 0; //TODO remove?
			md->sockets[call->sock_index].error_msg = 0;
		} else if (md->sockets[call->sock_index].sock_id_new != -1 && md->sockets[call->sock_index].sock_index_new != -1) {
			ack_send(module, call->id, call->index, call->type, 0);

			md->sockets[call->sock_index].sock_id_new = 0; //TODO remove?
			md->sockets[call->sock_index].sock_index_new = 0;
		} else {
			nack_send(module, call->id, call->index, call->type, EAGAIN); //TODO fix; this is a patch such that if 2 accepts are called at the same time in different threads
		}
		break;
	case SS_CONNECTING:
		nack_send(module, call->id, call->index, call->type, EAGAIN); //nack EAGAIN or EWOULDBLOCK, or should it be EINPROGRESS?

		if (call->serial_num != 0) { //was sent outside of module
			struct daemon_call *call_clone = daemon_call_clone(call);
			list_append(md->expired_call_list, call_clone);
		}
		break;
	default:
		PRINT_WARN("todo error");
		nack_send(module, call->id, call->index, call->type, 1);
		break;
	}

	daemon_calls_remove(module, call->index);
}

void recvmsg_timeout_tcp(struct fins_module *module, struct daemon_call *call) {
	PRINT_DEBUG("Entered: call=%p", call);
	struct daemon_data *md = (struct daemon_data *) module->data;

	list_remove(md->sockets[call->sock_index].call_list, call);

	switch (md->sockets[call->sock_index].state) {
	case SS_UNCONNECTED:
		PRINT_WARN("todo error");
		nack_send(module, call->id, call->index, call->type, 1);
		break;
	case SS_CONNECTING:
		PRINT_WARN("todo error");
		nack_send(module, call->id, call->index, call->type, 1);
		break;
	case SS_CONNECTED:
		nack_send(module, call->id, call->index, call->type, EAGAIN); //nack EAGAIN or EWOULDBLOCK
		break;
	default:
		PRINT_WARN("todo error");
		nack_send(module, call->id, call->index, call->type, 1);
		break;
	}

	daemon_calls_remove(module, call->index);
}

//##############################################################################
void connect_expired_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply) { //almost equiv to connect_in_tcp //TODO combine the two?
	PRINT_DEBUG("Entered: ff=%p, call=%p, reply=%d", ff, call, reply);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_CONNECT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		if (reply)
			nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);

	if (ff->ctrlFrame.ret_val == FCF_TRUE) {
		md->sockets[call->sock_index].state = SS_CONNECTED;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));
		if (reply)
			ack_send(module, call->id, call->index, call->type, 0);
	} else {
		md->sockets[call->sock_index].state = SS_UNCONNECTED;
		md->sockets[call->sock_index].error_call = call->type;
		md->sockets[call->sock_index].error_msg = ret_msg;

		addr4_set_ip(&md->sockets[call->sock_index].host_addr, 0); //TODO don't clear? so that will detect error
		addr4_set_port(&md->sockets[call->sock_index].host_addr, 0);
		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

		if (reply)
			nack_send(module, call->id, call->index, call->type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}

void accept_expired_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply) { //change accept_in_tcp to call, add ack/nack flag?
	PRINT_DEBUG("Entered: ff=%p, call=%p, reply=%d", ff, call, reply);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (ff->ctrlFrame.param_id != DAEMON_EXEC_TCP_ACCEPT) {
		PRINT_ERROR("Exiting, param_id errors: ff=%p, param_id=%d, ret_val=%d", ff, ff->ctrlFrame.param_id, ff->ctrlFrame.ret_val);
		if (reply)
			nack_send(module, call->id, call->index, call->type, 1);
		daemon_call_free(call);
		freeFinsFrame(ff);
		return;
	}

	uint32_t ret_msg;
	secure_metadata_readFromElement(ff->metaData, "ret_msg", &ret_msg);
	uint32_t rem_ip;
	secure_metadata_readFromElement(ff->metaData, "rem_ip", &rem_ip);
	uint32_t rem_port;
	secure_metadata_readFromElement(ff->metaData, "rem_port", &rem_port);

	if (ff->ctrlFrame.ret_val == FCF_TRUE) {
		if (daemon_sockets_insert(module, call->sock_id_new, call->sock_index_new, md->sockets[call->sock_index].type, md->sockets[call->sock_index].protocol,
				&tcp_out_ops, &tcp_in_ops, &tcp_other_ops)) {
			md->sockets[call->sock_index_new].family = md->sockets[call->sock_index].family;
			md->sockets[call->sock_index_new].state = SS_CONNECTED;
			memcpy(&md->sockets[call->sock_index_new].host_addr, &md->sockets[call->sock_index].host_addr, sizeof(struct sockaddr_storage));
			addr4_set_ip(&md->sockets[call->sock_index_new].rem_addr, rem_ip);
			addr4_set_port(&md->sockets[call->sock_index_new].rem_addr, (uint16_t) rem_port);

			PRINT_DEBUG("Accept socket created: sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

			md->sockets[call->sock_index].state = SS_UNCONNECTED;
			if (reply) {
				md->sockets[call->sock_index].sock_id_new = -1;
				md->sockets[call->sock_index].sock_index_new = -1;
			} else {
				md->sockets[call->sock_index].sock_id_new = call->sock_id_new;
				md->sockets[call->sock_index].sock_index_new = call->sock_index_new;
			}

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

			PRINT_DEBUG("Exiting, ACK: ff=%p", ff);
			if (reply)
				ack_send(module, call->id, call->index, call->type, 0);
		} else {
			PRINT_ERROR("Exited: insert failed: ff=%p", ff);

			md->sockets[call->sock_index].state = SS_UNCONNECTED;
			md->sockets[call->sock_index].error_call = call->type;
			md->sockets[call->sock_index].error_msg = 0; //TODO fill in special value?

			PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
					md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

			if (reply)
				nack_send(module, call->id, call->index, call->type, 1);
		}
	} else {
		md->sockets[call->sock_index].state = SS_UNCONNECTED;
		md->sockets[call->sock_index].error_call = call->type;
		md->sockets[call->sock_index].error_msg = ret_msg;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, state=%u, host=%u:%u, rem=%u:%u",
				md->sockets[call->sock_index].sock_id, call->sock_index, md->sockets[call->sock_index].state, addr4_get_ip(&md->sockets[call->sock_index].host_addr), addr4_get_port(&md->sockets[call->sock_index].host_addr), addr4_get_ip(&md->sockets[call->sock_index].rem_addr), addr4_get_port(&md->sockets[call->sock_index].rem_addr));

		if (reply)
			nack_send(module, call->id, call->index, call->type, ECONNREFUSED); //TODO change based off of timeout, refused etc
	}

	daemon_call_free(call);
	freeFinsFrame(ff);
}
