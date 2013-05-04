/*
 * handlers.c
 *
 *  Created on: May 3, 2013
 *      Author: Jonathan Reed
 */
#include "daemon_internal.h"

static call_out_type call_outs[] = { socket_out, bind_out, listen_out, connect_out, accept_out, getname_out, ioctl_out, sendmsg_out, recvmsg_out,
		getsockopt_out, setsockopt_out, release_out, poll_out, mmap_out, socketpair_out, shutdown_out, close_out, sendpage_out };

void daemon_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *msg_pt, int msg_len) {
	PRINT_DEBUG("Entered: hdr=%p, sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d, len=%d",
			hdr, hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index, msg_len);
	//struct daemon_data *md = (struct daemon_data *) module->data;

	//############################### Debug
#ifdef DEBUG
	uint8_t *temp;
	temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg_pt, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);

	if (0) {
		print_hex(msg_len, msg_pt);
	}
#endif
	//###############################

	if (hdr->call_index < 0 || hdr->call_index > MAX_CALLS) {
		PRINT_ERROR("call_index out of range: call_index=%d", hdr->call_index);
	} else {
		if (hdr->call_type >= MAX_CALL_TYPES) {
			PRINT_ERROR("call_index out of range: call_type=%u", hdr->call_type);
			//TODO nack?
		} else if (hdr->call_type == SOCKET_CALL) {
			socket_out(module, hdr, msg_pt, msg_len);
		} else {
			if (hdr->sock_index < 0 || hdr->sock_index > MAX_SOCKETS) {
				PRINT_ERROR("sock_index out of range: sock_index=%d", hdr->sock_index);
			} else {
				//TODO update to system where use ops in daemon_socket struct
				/*
				PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
				secure_sem_wait(&md->daemon_sockets_sem);
				if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
					PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
							hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
					PRINT_DEBUG("post$$$$$$$$$$$$$$$");
					sem_post(&md->daemon_sockets_sem);

					nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
					return;
				}

				//(md->daemon_sockets[hdr->sock_index].ops[hdr->call_type])(module, hdr, msg_pt, msg_len);

				int type = md->daemon_sockets[hdr->sock_index].type;
				int protocol = md->daemon_sockets[hdr->sock_index].protocol;

				PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d",
						md->daemon_calls[hdr->call_index].sock_id, md->daemon_calls[hdr->call_index].sock_index, type, protocol);
				PRINT_DEBUG("post$$$$$$$$$$$$$$$");
				sem_post(&md->daemon_sockets_sem);
				*/

				(call_outs[hdr->call_type])(module, hdr, msg_pt, msg_len);
			}
		}
	}
}

void socket_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	uint8_t *pt = buf;

	int domain = *(int *) pt;
	pt += sizeof(int);

	int type = *(int *) pt;
	pt += sizeof(int);

	int protocol = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("domain=%d, type=%u, protocol=%d", domain, type, protocol);
	if (domain != AF_INET) {
		PRINT_ERROR("Wrong domain, only AF_INET us supported");
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	if (type == SOCK_RAW && (protocol == IPPROTO_ICMP || protocol == IPPROTO_IP)) {
		socket_out_icmp(module, hdr, domain, SOCK_RAW, IPPROTO_ICMP);
	} else if (type == SOCK_STREAM && (protocol == IPPROTO_TCP || protocol == IPPROTO_IP)) {
		socket_out_tcp(module, hdr, domain, SOCK_STREAM, IPPROTO_TCP);
	} else if (type == SOCK_DGRAM && (protocol == IPPROTO_UDP || protocol == IPPROTO_IP)) {
		socket_out_udp(module, hdr, domain, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void bind_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;
	uint8_t *pt = buf;

	socklen_t addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len <= 0) {
		PRINT_ERROR("READING ERROR! CRASH, addrlen=%d", addr_len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	} else {
		PRINT_DEBUG("addr_len=%d", addr_len);
	}

	struct sockaddr_in *addr = (struct sockaddr_in *) secure_malloc(addr_len);
	memcpy(addr, pt, addr_len);
	pt += addr_len;

	int reuseaddr = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("addr=%u/%d, family=%d, reuseaddr=%d", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, reuseaddr);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(addr);
		return;
	}

	md->daemon_sockets[hdr->sock_index].sockopts.FSO_REUSEADDR |= reuseaddr; //TODO: when sockopts fully impelmented just set to '='

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d",
			md->daemon_calls[hdr->call_index].sock_id, md->daemon_calls[hdr->call_index].sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) { //is proto==icmp needed?
		bind_out_icmp(module, hdr, addr);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		bind_out_tcp(module, hdr, addr);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		bind_out_udp(module, hdr, addr);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(addr);
	}
}

void listen_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int backlog;
	uint8_t *pt;

	pt = buf;

	backlog = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("backlog=%d", backlog);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		listen_out_icmp(module, hdr, backlog);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		listen_out_tcp(module, hdr, backlog);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		listen_out_udp(module, hdr, backlog);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void connect_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	socklen_t addrlen;
	struct sockaddr_in *addr;
	int flags;
	uint8_t *pt;

	pt = buf;

	addrlen = *(int *) pt;
	pt += sizeof(int);

	if (addrlen <= 0) {
		PRINT_ERROR("READING ERROR! CRASH, addrlen=%d", addrlen);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	addr = (struct sockaddr_in *) secure_malloc(addrlen);
	memcpy(addr, pt, addrlen);
	pt += addrlen;

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(addr);
		return;
	}

	PRINT_DEBUG("addr=%u/%d, family=%d, flags=0x%x", (addr->sin_addr).s_addr, ntohs(addr->sin_port), addr->sin_family, flags);

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(addr);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		connect_out_icmp(module, hdr, addr, flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		connect_out_tcp(module, hdr, addr, flags);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		connect_out_udp(module, hdr, addr, flags);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		free(addr);
	}
}

void accept_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint64_t sock_id_new;
	int sock_index_new;
	int flags;
	uint8_t *pt;

	pt = buf;

	sock_id_new = *(uint64_t *) pt;
	pt += sizeof(uint64_t);

	sock_index_new = *(int *) pt;
	pt += sizeof(int);

	flags = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("");
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		accept_out_icmp(module, hdr, sock_id_new, sock_index_new, flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		accept_out_tcp(module, hdr, sock_id_new, sock_index_new, flags); //TODO finish
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		accept_out_udp(module, hdr, sock_id_new, sock_index_new, flags);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void getname_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int peer;
	uint8_t *pt;

	pt = buf;

	peer = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("");
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getname_out_icmp(module, hdr, peer);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		getname_out_tcp(module, hdr, peer);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		getname_out_udp(module, hdr, peer);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void ioctl_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int buf_len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, buf_len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	//TODO fix here!!!!!!!!!!!!!!!!!! handle if_list stuff & addr_list

	uint32_t cmd;
	uint8_t *pt;
	uint8_t *temp;
	int len;
	int msg_len = 0;
	uint8_t *msg = NULL;
	struct nl_daemon_to_wedge *hdr_ret;
	struct sockaddr_in addr;
	struct ifreq ifr;
	int total = 0;

	pt = buf;

	cmd = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	switch (cmd) {
	case SIOCGIFCONF:
		PRINT_DEBUG("SIOCGIFCONF=%d", cmd);
		//TODO implement: http://lxr.linux.no/linux+v2.6.39.4/net/core/dev.c#L3919, http://lxr.linux.no/linux+v2.6.39.4/net/ipv4/devinet.c#L926
		len = *(int *) pt;
		pt += sizeof(int);

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFCONF), len=%d", cmd, len);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int) + 2 * sizeof(struct ifreq);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		temp = pt; //store ptr to where total should be stored
		pt += sizeof(int);

		//TODO implement a looped version of this that's taken from where interface/device info will be stored
		total = 0;
		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, "lo");
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(loopback_ip_addr);
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		if (total + sizeof(struct ifreq) <= len) {
			strcpy(ifr.ifr_name, (char *) my_host_if_name);
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_family = AF_INET;
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr = htonl(my_host_ip_addr);
			((struct sockaddr_in *) &ifr.ifr_addr)->sin_port = 0;

			memcpy(pt, &ifr, sizeof(struct ifreq));
			pt += sizeof(struct ifreq);
			total += sizeof(struct ifreq);
		} else {
			msg_len -= sizeof(struct ifreq);
		}

		*(int *) temp = total;
		PRINT_DEBUG("total=%d (%d)", total, total/32);

		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGIFADDR:
		PRINT_DEBUG("SIOCGIFADDR=%d", cmd);

		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			return;
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGIFDSTADDR:
		PRINT_DEBUG("SIOCGIFDSTADDR=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFDSTADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_ip_addr);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			return;
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGIFBRDADDR:
		PRINT_DEBUG("SIOCGIFBRDADDR=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFBRDADDR), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl((my_host_ip_addr & my_host_mask) | (~my_host_mask));
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(any_ip_addr);
			addr.sin_port = 0;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			//nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			//return;
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGIFNETMASK:
		PRINT_DEBUG("SIOCGIFNETMASK=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFNETMASK), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP?
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(my_host_mask);
			addr.sin_port = 0;
		} else if (strcmp((char *) temp, "lo") == 0) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(loopback_mask);
			addr.sin_port = 0;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			//nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			//return;
		}

		PRINT_DEBUG("temp='%s', addr=%s/%d", temp, inet_ntoa(addr.sin_addr), addr.sin_port);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(struct sockaddr_in);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, &addr, sizeof(struct sockaddr_in));
		pt += sizeof(struct sockaddr_in);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case FIONREAD:
		PRINT_DEBUG("FIONREAD=%d", cmd);
		msg_len = 0; //handle per socket/protocol

		PRINT_ERROR("todo");
		break;
	case TIOCOUTQ:
		PRINT_DEBUG("TIOCOUTQ=%d", cmd);
		PRINT_ERROR("todo");
		break;
		//case TIOCINQ: //equiv to FIONREAD??
	case SIOCGIFNAME:
		PRINT_DEBUG("SIOCGIFNAME=%d", cmd);
		len = *(int *) pt; //IFNAMSIZ
		pt += sizeof(int);

		total = *(int *) pt; //ifr_ifindex
		pt += sizeof(int);

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFNAME), index=%d", cmd, total);

		temp = (uint8_t *) secure_malloc(len);

		//TODO get correct values from IP?
		if (total == my_host_if_num) {
			strcpy((char *) temp, (char *) my_host_if_name);
		} else {
			PRINT_ERROR("index=%d", total);
		}

		PRINT_DEBUG("index=%d, temp='%s'", total, temp);

		msg_len = sizeof(struct nl_daemon_to_wedge) + len;
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		memcpy(pt, temp, len);
		pt += len;

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCGIFFLAGS:
		PRINT_DEBUG("SIOCGIFFLAGS=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFFLAGS), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP? ifr_flags
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			total = IFF_UP | IFF_BROADCAST | IFF_RUNNING | IFF_MULTICAST; //TODO remove running if is interface but not connected
		} else if (strcmp((char *) temp, "lo") == 0) {
			total = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			total = IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
			//nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			//return;
		}

		PRINT_DEBUG("temp='%s', ifr_flags=0x%x", temp, total);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = total;
		pt += sizeof(int);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCSIFFLAGS:
		PRINT_DEBUG("SIOCSIFFLAGS=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCGIFMTU:
		PRINT_DEBUG("SIOCGIFMTU=%d", cmd);
		len = *(int *) pt;
		pt += sizeof(int);

		temp = (uint8_t *) secure_malloc(len);
		memcpy(temp, pt, len);
		pt += len;

		if (pt - buf != buf_len) {
			PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, buf_len);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		PRINT_DEBUG("cmd=%d (SIOCGIFMTU), len=%d, temp='%s'", cmd, len, temp);

		//TODO get correct values from IP? ifr_mtu
		if (strcmp((char *) temp, (char *) my_host_if_name) == 0) {
			total = 1500;
		} else if (strcmp((char *) temp, "lo") == 0) {
			total = 16436;
		} else {
			PRINT_ERROR("temp='%s'", temp);
			//nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, EADDRNOTAVAIL);
			//return;
		}

		PRINT_DEBUG("temp='%s', ifr_mtu=%d", temp, total);

		msg_len = sizeof(struct nl_daemon_to_wedge) + sizeof(int);
		msg = (uint8_t *) secure_malloc(msg_len);

		hdr_ret = (struct nl_daemon_to_wedge *) msg;
		hdr_ret->call_type = hdr->call_type;
		hdr_ret->call_id = hdr->call_id;
		hdr_ret->call_index = hdr->call_index;
		hdr_ret->ret = ACK;
		hdr_ret->msg = 0;
		pt = msg + sizeof(struct nl_daemon_to_wedge);

		*(int *) pt = total;
		pt += sizeof(int);

		free(temp);
		if (pt - msg != msg_len) {
			PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
			free(msg);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}
		break;
	case SIOCADDRT:
		PRINT_DEBUG("SIOCADDRT=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCDELRT:
		PRINT_DEBUG("SIOCDELRT=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCSIFADDR:
		PRINT_DEBUG("SIOCSIFADDR=%d", cmd);
		PRINT_ERROR("todo");
		break;
		//case SIOCAIPXITFCRT:
		//case SIOCAIPXPRISLT:
		//case SIOCIPXCFGDATA:
		//case SIOCIPXNCPCONN:
	case SIOCGSTAMP:
		PRINT_DEBUG("SIOCGSTAMP=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCSIFDSTADDR:
		PRINT_DEBUG("SIOCSIFDSTADDR=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCSIFBRDADDR:
		PRINT_DEBUG("SIOCSIFBRDADDR=%d", cmd);
		PRINT_ERROR("todo");
		break;
	case SIOCSIFNETMASK:
		PRINT_DEBUG("SIOCSIFNETMASK=%d", cmd);
		PRINT_ERROR("todo");
		break;
	default:
		PRINT_ERROR("default: cmd=%d", cmd);
		break;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	if (msg_len) {
		if (send_wedge(module, msg, msg_len, 0)) {
			PRINT_ERROR("Exiting, fail send_wedge: sock_id=%llu", hdr->sock_id);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
		free(msg);
	} else {
		PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
		secure_sem_wait(&md->daemon_sockets_sem);
		if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
			PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
					hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
			PRINT_DEBUG("post$$$$$$$$$$$$$$$");
			sem_post(&md->daemon_sockets_sem);

			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
			return;
		}

		int type = md->daemon_sockets[hdr->sock_index].type;
		int protocol = md->daemon_sockets[hdr->sock_index].protocol;

		PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
			ioctl_out_icmp(module, hdr, cmd, buf, buf_len);
		} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
			ioctl_out_tcp(module, hdr, cmd, buf, buf_len);
		} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
			ioctl_out_udp(module, hdr, cmd, buf, buf_len);
		} else {
			PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
			nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		}
	}
}

void sendmsg_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t sk_flags;
	int timestamp;
	int addr_len;
	struct sockaddr_in *addr = NULL;
	uint32_t msg_flags;
	uint32_t msg_controllen;
	void *msg_control = NULL;
	uint32_t msg_len;
	uint8_t *msg = NULL;
	uint8_t *pt;

	pt = buf;

	sk_flags = *(uint32_t *) pt;
	pt += sizeof(uint32_t);
	timestamp = sk_flags & ((1 << SOCK_TIMESTAMP) | (1 << SOCK_RCVTSTAMP));

	addr_len = *(int *) pt;
	pt += sizeof(int);

	if (addr_len > 0) {
		if (addr_len >= sizeof(struct sockaddr_in)) {
			addr = (struct sockaddr_in *) secure_malloc(addr_len);
			memcpy(addr, pt, addr_len);
			pt += addr_len;

			PRINT_DEBUG("addr_len=%d, addr=%s/%d", addr_len, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
		} else {
			//TODO error?
			PRINT_ERROR("todo error: addr_len=%d", addr_len);
		}
	} else {
		PRINT_DEBUG("addr_len=%d", addr_len);
	}

	msg_flags = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	if (msg_controllen) {
		msg_control = secure_malloc(msg_controllen);
		memcpy(msg_control, pt, msg_controllen);
		pt += msg_controllen;
	}

	msg_len = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	if (msg_len) {
		msg = (uint8_t *) secure_malloc(msg_len);
		memcpy(msg, pt, msg_len);
		pt += msg_len;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (msg_controllen)
			free(msg_control);
		if (msg_len)
			free(msg);
		return;
	}

	PRINT_DEBUG("");
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (msg_controllen)
			free(msg_control);
		if (msg_len)
			free(msg);

		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	md->daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP |= timestamp;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	//#########################
#ifdef DEBUG
	uint8_t *temp = (uint8_t *) secure_malloc(msg_len + 1);
	memcpy(temp, msg, msg_len);
	temp[msg_len] = '\0';
	PRINT_DEBUG("msg='%s'", temp);
	free(temp);
	//#########################
	uint8_t *temp2 = (uint8_t *) secure_malloc(msg_controllen + 1);
	memcpy(temp2, msg_control, msg_controllen);
	temp2[msg_controllen] = '\0';
	PRINT_DEBUG("msg_control='%s'", temp2);
	free(temp2);
#endif
	//#########################

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		sendmsg_out_icmp(module, hdr, msg, msg_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		sendmsg_out_tcp(module, hdr, msg, msg_len, msg_flags, addr, addr_len);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		sendmsg_out_udp(module, hdr, msg, msg_len, msg_flags, addr, addr_len);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (msg_len)
			free(msg);
	}

	if (msg_controllen)
		free(msg_control);
}

void recvmsg_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint32_t sk_flags;
	int timestamp;
	int msg_len;
	uint32_t msg_controllen;
	int flags;
	uint8_t *pt;

	pt = buf;

	sk_flags = *(uint32_t *) pt;
	pt += sizeof(uint32_t);
	timestamp = sk_flags & ((1 << SOCK_TIMESTAMP) | (1 << SOCK_RCVTSTAMP)); //TODO remove rcvtstamp? or figure out/expand

	msg_len = *(int *) pt; //check on not in original socket_interceptor: recvmsg
	pt += sizeof(int);

	msg_controllen = *(uint32_t *) pt;
	pt += sizeof(uint32_t);

	flags = *(int *) pt;
	pt += sizeof(int);

	/*
	 msg_flags = *(uint32_t *) pt; //TODO remove, set when returning
	 pt += sizeof(uint32_t);

	 if (msg_controllen) {	//TODO send msg_controllen?
	 msg_control = (uint8_t *) secure_malloc(msg_controllen);
	 memcpy(msg_control, pt, msg_controllen);
	 pt += msg_controllen;
	 }
	 */

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		//if (msg_controllen) {
		//	free(msg_control);
		//}

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("flags=0x%x", flags);

	/** Notice that send is only used with tcp connections since
	 * the receiver is already known
	 */

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);
		//if (msg_controllen) {
		//	free(msg_control);
		//}

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	md->daemon_sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP |= timestamp;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		recvmsg_out_icmp(module, hdr, msg_len, msg_controllen, flags);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		recvmsg_out_tcp(module, hdr, msg_len, msg_controllen, flags);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		recvmsg_out_udp(module, hdr, msg_len, msg_controllen, flags);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}

	//if (msg_controllen) {
	//	free(msg_control);
	//}
}

void getsockopt_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int level;
	int optname;
	int optlen;
	uint8_t *optval = NULL;
	uint8_t *pt;

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = *(int *) pt;
	pt += sizeof(int);

	if (optlen > 0) { //TODO remove?
		optval = (uint8_t *) secure_malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
		return;
	}

	PRINT_DEBUG("");
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		getsockopt_out_icmp(module, hdr, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		getsockopt_out_tcp(module, hdr, level, optname, optlen, optval);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		getsockopt_out_udp(module, hdr, level, optname, optlen, optval);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
	}
}

void setsockopt_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int level;
	int optname;
	int optlen;
	uint8_t *optval = NULL;
	uint8_t *pt;

	pt = buf;

	level = *(int *) pt;
	pt += sizeof(int);

	optname = *(int *) pt;
	pt += sizeof(int);

	optlen = (int) (*(uint32_t *) pt);
	pt += sizeof(uint32_t);

	if (optlen > 0) {
		optval = (uint8_t *) secure_malloc(optlen);
		memcpy(optval, pt, optlen);
		pt += optlen;
	}

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
		return;
	}

	PRINT_DEBUG("");
	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
		return;
	}

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		setsockopt_out_icmp(module, hdr, level, optname, optlen, optval);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		setsockopt_out_tcp(module, hdr, level, optname, optlen, optval);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		setsockopt_out_udp(module, hdr, level, optname, optlen, optval);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		if (optlen > 0)
			free(optval);
	}
}

void release_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint8_t *pt;

	pt = buf;

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		release_out_icmp(module, hdr);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		release_out_tcp(module, hdr);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		release_out_udp(module, hdr);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void poll_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint8_t *pt;
	int events;

	pt = buf;

	events = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, POLLERR);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, POLLNVAL); //TODO check value?
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		poll_out_icmp(module, hdr, events);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		poll_out_tcp(module, hdr, events);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		poll_out_udp(module, hdr, events);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, POLLERR);
	}
}

void mmap_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	uint8_t *pt;
	pt = buf;

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		//mmap_tcp_icmp(hdr);
		PRINT_DEBUG("implement mmap_icmp");
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		//mmap_tcp_out(hdr);
		PRINT_DEBUG("implement mmap_tcp");
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		//mmap_out_udp(module, hdr);
		PRINT_DEBUG("implement mmap_udp");
		ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void socketpair_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

}

void shutdown_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int how;
	uint8_t *pt;

	pt = buf;

	how = *(int *) pt;
	pt += sizeof(int);

	if (pt - buf != len) {
		PRINT_ERROR("READING ERROR! CRASH, diff=%d, len=%d", pt - buf, len);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	PRINT_DEBUG("wait$$$$$$$$$$$$$$$");
	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		PRINT_DEBUG("post$$$$$$$$$$$$$$$");
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}
	//daemonSockets[hdr->sock_index].threads = threads;

	int type = md->daemon_sockets[hdr->sock_index].type;
	int protocol = md->daemon_sockets[hdr->sock_index].protocol;

	PRINT_DEBUG("sock_id=%llu, sock_index=%d, type=%d, proto=%d", hdr->sock_id, hdr->sock_index, type, protocol);
	PRINT_DEBUG("post$$$$$$$$$$$$$$$");
	sem_post(&md->daemon_sockets_sem);

	if (type == SOCK_RAW && protocol == IPPROTO_ICMP) {
		shutdown_out_icmp(module, hdr, how);
	} else if (type == SOCK_STREAM && protocol == IPPROTO_TCP) {
		shutdown_out_tcp(module, hdr, how);
	} else if (type == SOCK_DGRAM && protocol == IPPROTO_UDP) {
		shutdown_out_udp(module, hdr, how);
	} else {
		PRINT_ERROR("non supported socket: type=%d, protocol=%d", type, protocol);
		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
	}
}

void close_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {
	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);
	struct daemon_data *md = (struct daemon_data *) module->data;

	secure_sem_wait(&md->daemon_sockets_sem);
	if (md->daemon_sockets[hdr->sock_index].sock_id != hdr->sock_id) {
		PRINT_DEBUG("invalid socket: sock_id=%llu, sock_index=%d, call_pid=%d,  call_type=%u, call_id=%u, call_index=%d",
				hdr->sock_id, hdr->sock_index, hdr->call_pid, hdr->call_type, hdr->call_id, hdr->call_index);
		sem_post(&md->daemon_sockets_sem);

		nack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 1);
		return;
	}

	daemon_sockets_remove(module, hdr->sock_index);

	PRINT_DEBUG("");
	sem_post(&md->daemon_sockets_sem);

	ack_send(module, hdr->call_id, hdr->call_index, hdr->call_type, 0);

	/**
	 * TODO Fix the problem with terminate queue which goes into infinite loop
	 * when close is called
	 */
}

void sendpage_out(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *buf, int len) {

	PRINT_DEBUG("Entered: hdr=%p, len=%d", hdr, len);

}
