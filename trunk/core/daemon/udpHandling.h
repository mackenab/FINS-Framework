/**
 * @file udpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#ifndef UDPHANDLING_H_
#define UDPHANDLING_H_

#define MAX_DATA_PER_UDP 4096

#include "daemon.h"

int daemon_fdf_to_udp(u_char *data, u_int data_len, metadata *params);

void socket_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol);
void bind_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr);
void listen_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog);
void connect_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags);
void accept_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags);
void getname_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer);
void ioctl_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len);
void sendmsg_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags,
		struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags); //TODO need symbol?
void getsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void setsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void release_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void poll_udp_out(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int events);
//void poll_udp_in(unsigned long long uniqueSockID, int index /* results? */);
void mmap_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void socketpair_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void shutdown_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how);
void close_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void sendpage_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);

struct daemon_udp_thread_data {
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

#endif /* UDPHANDLING_H_ */
