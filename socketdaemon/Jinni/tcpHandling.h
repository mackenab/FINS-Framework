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


int jinni_TCP_to_fins(u_char *dataLocal, int len, uint16_t dstport,
		uint32_t dst_IP_netformat, uint16_t hostport,
		uint32_t host_IP_netformat);
int TCPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag);



void socket_tcp(int domain, int type, int protocol, unsigned long long uniqueSockID);
void socketpair_tcp();
void bind_tcp(unsigned long long uniqueSockID, struct sockaddr_in *addr);
void getsockname_tcp();
void connect_tcp(unsigned long long uniqueSockID, struct sockaddr_in *addr);
void getpeername_tcp(unsigned long long uniqueSockID, int addrlen);
void send_tcp(unsigned long long uniqueSockID, int socketCallType, int datalen, u_char *data, int flags);
void write_tcp(unsigned long long uniqueSockID, int socketCallType, int datalen, u_char *data);


void recv_tcp(unsigned long long uniqueSockID, int datalen, int flags);
void sendto_tcp(unsigned long long uniqueSockID, int socketCallType, int datalen, u_char *data, int flags,
		struct sockaddr_in *dest_addr, socklen_t addrlen);
void recvfrom_tcp(void *threadData);
void sendmsg_tcp();
void recvmsg_tcp();
void getsockopt_tcp(unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void setsockopt_tcp(unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void listen_tcp(unsigned long long uniqueSockID, int len);
void accept_tcp();
void accept4_tcp();
void shutdown_tcp(unsigned long long uniqueSockID, int  how);



#endif /* TCPHANDLING_H_ */
