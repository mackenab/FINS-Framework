/**
 * @file tcpHandling.h
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#ifndef TCPHANDLING_H_
#define TCPHANDLING_H_

#define MAX_DATA_PER_TCP 4096

#include "handlers.h"

#define EXEC_TCP_CONNECT 0
#define EXEC_TCP_LISTEN 1
#define EXEC_TCP_ACCEPT 2
#define EXEC_TCP_SEND 3
#define EXEC_TCP_RECV 4
#define EXEC_TCP_CLOSE 5
#define EXEC_TCP_CLOSE_STUB 6
#define EXEC_TCP_OPT 7
#define EXEC_TCP_POLL 8

struct daemon_tcp_thread_data {
	int id;
	unsigned long long uniqueSockID;
	int index;
	u_int call_id;
	int call_index;

	int data_len;
	int flags;
	unsigned long long uniqueSockID_new;
	int index_new;
	//int socketCallType; //TODO remove?
	//int symbol; //TODO remove?
};

int daemon_fdf_to_tcp(u_char *data, u_int data_len, metadata *params);
int daemon_fcf_to_tcp(uint16_t opcode, metadata *params);

void socket_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol);
void bind_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr);
void listen_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog);
void connect_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags);
void accept_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags);
void getname_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer);
void ioctl_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len);
void sendmsg_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags,
		struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags); //TODO need symbol?
void getsockopt_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void setsockopt_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void release_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void poll_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int events);
void mmap_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void socketpair_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void shutdown_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how);
void close_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void sendpage_tcp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);

#endif /* TCPHANDLING_H_ */
