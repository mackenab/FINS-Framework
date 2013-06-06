/*
 * daemon_netlink.c
 *
 *  Created on: May 28, 2013
 *      Author: Jonathan Reed
 */

#include "daemon_internal.h"

int init_fins_nl(struct fins_module *module) {
	PRINT_DEBUG("Entered: module=%p", module);
	struct daemon_data *md = (struct daemon_data *) module->data;

	sem_init(&md->nl_sem, 0, 1);

	// Get a netlink socket descriptor
	md->nl_sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FINS);
	if (md->nl_sockfd == -1) {
		return 0;
	}

	// Populate daemon_addr
	memset(&md->daemon_addr, 0, sizeof(struct sockaddr_nl));
	md->daemon_addr.nl_family = AF_NETLINK;
	md->daemon_addr.nl_pad = 0;
	md->daemon_addr.nl_pid = getpid(); //pthread_self() << 16 | getpid(),	// use second option for multi-threaded process
	md->daemon_addr.nl_groups = 0; // unicast

	// Bind the local netlink socket
	int ret = bind(md->nl_sockfd, (struct sockaddr*) &md->daemon_addr, sizeof(struct sockaddr_nl));
	if (ret == -1) {
		return 0;
	}

	// Populate wedge_addr
	memset(&md->wedge_addr, 0, sizeof(struct sockaddr_nl));
	md->wedge_addr.nl_family = AF_NETLINK;
	md->wedge_addr.nl_pad = 0;
	md->wedge_addr.nl_pid = 0; // to kernel
	md->wedge_addr.nl_groups = 0; // unicast

	//prime the kernel to establish daemon's PID
	int daemoncode = DAEMON_START_CALL;
	ret = send_wedge(module, (uint8_t *) &daemoncode, sizeof(int), 0);
	if (ret != 0) {
		PRINT_ERROR("unable to connect to wedge");
		return 0;
	}
	PRINT_IMPORTANT("Connected to wedge at fd=%d", md->nl_sockfd);

	return 1;
}

/*
 * Sends len bytes from buf on the sockfd.  Returns 0 if successful.  Returns -1 if an error occurred, errno set appropriately.
 */
int send_wedge(struct fins_module *module, uint8_t *buf, size_t len, int flags) {
	PRINT_DEBUG("Entered: buf=%p, len=%d, flags=0x%x", buf, len, flags);
	struct daemon_data *md = (struct daemon_data *) module->data;

	int ret; // Holds system call return values for error checking

	// Begin send message section
	// Build a message to send to the kernel
	int nlmsg_len = NLMSG_LENGTH(len);
	struct nlmsghdr *nlh = (struct nlmsghdr *) secure_malloc(nlmsg_len);
	nlh->nlmsg_len = nlmsg_len;
	// following can be used by application to track message, opaque to netlink core
	nlh->nlmsg_type = 0; // arbitrary value
	nlh->nlmsg_seq = 0; // sequence number
	nlh->nlmsg_pid = getpid(); // pthread_self() << 16 | getpid();	// use the second one for multiple threads
	nlh->nlmsg_flags = flags;

	// Insert payload (memcpy)
	memcpy(NLMSG_DATA(nlh), buf, len);

	// finish message packing
	struct iovec iov;
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base = (void *) nlh;
	iov.iov_len = nlh->nlmsg_len;

	struct msghdr msg;
	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *) &md->wedge_addr;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Send the message
	PRINT_DEBUG("Sending message to kernel");

	secure_sem_wait(&md->nl_sem);
	ret = sendmsg(md->nl_sockfd, &msg, 0);
	sem_post(&md->nl_sem);

	free(nlh);

	if (ret == -1) {
		return -1;
	} else {
		return 0;
	}
}

int nack_send(struct fins_module *module, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra meta
	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, nack=%d", call_id, call_index, call_type, msg, NACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = NACK;
	hdr->msg = msg;

	int ret = send_wedge(module, buf, buf_len, 0);
	free(buf);

	return ret == 0; //TODO change to ret_val ?
}

int ack_send(struct fins_module *module, uint32_t call_id, int call_index, uint32_t call_type, uint32_t msg) { //TODO remove extra meta
	PRINT_DEBUG("Entered: call_id=%u, call_index=%u, call_type=%u, msg=%u, ack=%d", call_id, call_index, call_type, msg, ACK);

	int buf_len = sizeof(struct nl_daemon_to_wedge);
	uint8_t *buf = (uint8_t *) secure_malloc(buf_len);

	struct nl_daemon_to_wedge *hdr = (struct nl_daemon_to_wedge *) buf;
	hdr->call_type = call_type;
	hdr->call_id = call_id;
	hdr->call_index = call_index;
	hdr->ret = ACK;
	hdr->msg = msg;

	int ret = send_wedge(module, buf, buf_len, 0);
	free(buf);

	return ret == 0; //TODO change to ret_val ?
}

int recvmsg_control(struct fins_module *module, struct nl_wedge_to_daemon *hdr, metadata *meta, uint32_t msg_controllen, int flags, int32_t *control_len,
		uint8_t **control) {
	PRINT_DEBUG("Entered: module=%p, hdr=%p, meta=%p, msg_controllen=%u, flags=0x%x, control_len=%p, control=%p", module, hdr, meta, msg_controllen, flags, control_len, control);
	struct daemon_data *md = (struct daemon_data *) module->data;

	if (msg_controllen > CONTROL_LEN_MAX) {
		PRINT_WARN("todo error");
		//TODO send some error
		*control_len = 0;
		*control = NULL;
		PRINT_DEBUG("Exited: module=%p, hdr=%p, meta=%p, control_len=%d, control=%p", module, hdr, meta, *control_len, *control);
		return 0;
	}

	if (msg_controllen == 0) {
		msg_controllen = CONTROL_LEN_DEFAULT;
	}

	*control_len = 0;
	*control = (uint8_t *) secure_malloc(msg_controllen);
	uint8_t *control_pt = *control;

	uint32_t cmsg_data_len;
	uint32_t cmsg_space;
	struct cmsghdr *cmsg;
	uint8_t *cmsg_data;

	if (md->sockets[hdr->sock_index].sockopts.FSO_TIMESTAMP) {
		cmsg_data_len = sizeof(struct timeval);
		cmsg_space = CMSG_SPACE(cmsg_data_len);

		if (*control_len + cmsg_space <= msg_controllen) {
			cmsg = (struct cmsghdr *) control_pt;
			cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SO_TIMESTAMP;
			PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

			cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
			memcpy(cmsg_data, &md->sockets[hdr->sock_index].stamp, cmsg_data_len);

			*control_len += cmsg_space;
			control_pt += cmsg_space;
		} else {
			PRINT_WARN("todo error");
		}
	}

	if (md->sockets[hdr->sock_index].sockopts.FIP_RECVTTL) {
		int32_t recv_ttl = 255;
		if (metadata_readFromElement(meta, "recv_ttl", &recv_ttl) == META_TRUE) {
			cmsg_data_len = sizeof(int32_t);
			cmsg_space = CMSG_SPACE(cmsg_data_len);

			if (*control_len + cmsg_space <= msg_controllen) {
				cmsg = (struct cmsghdr *) control_pt;
				cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
				cmsg->cmsg_level = IPPROTO_IP;
				cmsg->cmsg_type = IP_TTL;
				PRINT_DEBUG("cmsg_space=%u, cmsg_len=%u, cmsg_level=%d, cmsg_type=0x%x", cmsg_space, cmsg->cmsg_len, cmsg->cmsg_level, cmsg->cmsg_type);

				cmsg_data = (uint8_t *) CMSG_DATA(cmsg);
				*(int32_t *) cmsg_data = recv_ttl;

				*control_len += cmsg_space;
				control_pt += cmsg_space;
			} else {
				PRINT_WARN("todo error");
			}
		} else {
			PRINT_ERROR("no recv_ttl, meta=%p", meta);
		}
	}

	if (md->sockets[hdr->sock_index].sockopts.FIP_RECVERR && (flags & MSG_ERRQUEUE)) {
		uint32_t err_src_ip;
		secure_metadata_readFromElement(meta, "recv_src_ipv4", &err_src_ip);
		uint32_t icmp_type;
		secure_metadata_readFromElement(meta, "recv_icmp_type", &icmp_type);
		//add port?

		cmsg_data_len = sizeof(struct errhdr);
		cmsg_space = CMSG_SPACE(cmsg_data_len);

		if (*control_len + cmsg_space <= msg_controllen) {
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

			err->offender.sin_family = AF_INET;
			err->offender.sin_addr.s_addr = htonl(err_src_ip);
			err->offender.sin_port = htons(0);

			*control_len += cmsg_space;
			control_pt += cmsg_space;
		} else {
			PRINT_WARN("todo error");
		}
	}

	if (control_pt - *control != *control_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", control_pt - *control, *control_len);
		exit(-1);
	}

	PRINT_DEBUG("Exited: module=%p, hdr=%p, meta=%p, control_len=%d, control=%p", module, hdr, meta, *control_len, *control);
	return 1;
}

int send_wedge_recvmsg(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint32_t addr_len, struct sockaddr_storage *addr, uint32_t data_len,
		uint8_t *data, uint32_t control_len, uint8_t *control) {
	PRINT_DEBUG("Entered: module=%p, hdr=%p, addr_len=%u, addr=%p, data_len=%u, data=%p, control_len=%u, control=%p", module, hdr, addr_len, addr, data_len, data, control_len, control);

	int msg_len = sizeof(struct nl_daemon_to_wedge) + 3 * sizeof(uint32_t) + addr_len + data_len + control_len;
	uint8_t *msg = (uint8_t *) secure_malloc(msg_len);

	struct nl_daemon_to_wedge *hdr_ret = (struct nl_daemon_to_wedge *) msg;
	hdr_ret->call_type = hdr->call_type;
	hdr_ret->call_id = hdr->call_id;
	hdr_ret->call_index = hdr->call_index;
	hdr_ret->ret = ACK;
	hdr_ret->msg = 0; //TODO change to set msg_flags
	uint8_t *pt = msg + sizeof(struct nl_daemon_to_wedge);

	*(uint32_t *) pt = addr_len;
	pt += sizeof(uint32_t);

	if (addr_len != 0) {
		memcpy(pt, addr, addr_len);
		pt += addr_len;
	}

	*(uint32_t *) pt = data_len;
	pt += sizeof(uint32_t);

	if (data_len != 0) {
		memcpy(pt, data, data_len);
		pt += data_len;
	}

	*(uint32_t *) pt = control_len;
	pt += sizeof(uint32_t);

	if (control_len != 0) {
		memcpy(pt, control, control_len);
		pt += control_len;
	}

	if (pt - msg != msg_len) {
		PRINT_ERROR("write error: diff=%d, len=%d", pt - msg, msg_len);
		free(msg);
		return 0;
	}

	PRINT_DEBUG("msg_len=%d, msg='%s'", msg_len, msg);
	int ret = send_wedge(module, msg, msg_len, 0);
	free(msg);
	if (ret) {
		PRINT_ERROR("Exited: fail send_wedge: hdr=%p", hdr);
		return 0;
	} else {
		//PRINT_DEBUG("Exiting, normal: id=%d, index=%d, uniqueSockID=%llu", id, index, uniqueSockID);
		return 1;
	}
}
