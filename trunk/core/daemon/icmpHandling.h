/*
 * icmphandling.h
 *
 *  Created on: Jun 29, 2011
 *      Author: dell
 */

#ifndef ICMPHANDLING_H_
#define ICMPHANDLING_H_

#include "daemon.h"

int daemon_fdf_to_icmp(u_char *data, u_int data_len, metadata *params);

void socket_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol);
void bind_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr);
void listen_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog);
void connect_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags);
void accept_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags);
void getname_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer);
void ioctl_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len);
void sendmsg_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags,
		struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags); //TODO need symbol?
void getsockopt_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void setsockopt_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void release_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void poll_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int events);
void mmap_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void socketpair_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void shutdown_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how);
void close_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void sendpage_icmp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);

struct daemon_icmp_thread_data {
	int id;
	unsigned long long uniqueSockID;
	int index;
	u_int call_id;
	int call_index;

	int data_len;
	int flags;
//int socketCallType; //TODO remove?
//int symbol; //TODO remove?
};

#endif /* ICMPHANDLING_H_ */
