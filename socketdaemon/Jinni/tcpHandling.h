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

struct jinni_tcp_thread_data {
	int index;
	unsigned long long uniqueSockID;
	int blocking_flag;
	unsigned long long uniqueSockID_new;
};

int jinni_TCP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat, int block_flag);
int TCPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag);

void socket_tcp(int domain, int type, int protocol, unsigned long long uniqueSockID);
void bind_tcp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr);
void listen_tcp(int index, unsigned long long uniqueSockID, int len);
void connect_tcp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr);
void accept_tcp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags);
void write_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen);
void send_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags);
void sendto_tcp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *dest_addr, socklen_t addrlen);
void recv_tcp(int index, unsigned long long uniqueSockID, int datalen, int flags);
void recvfrom_tcp(int index, unsigned long long uniqueSockID, int datalen, int flags, int symbol);

void socketpair_tcp();
void getsockname_tcp();
void getpeername_tcp(int index, unsigned long long uniqueSockID, int addrlen);
void recvmsg_tcp();
void getsockopt_tcp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void setsockopt_tcp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void accept4_tcp();
void shutdown_tcp(int index, unsigned long long uniqueSockID, int how);
void release_tcp(int index, unsigned long long uniqueSockID);

#endif /* TCPHANDLING_H_ */
