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
int TCPreadFrom_fins(int senderid, int sockfd, u_char **buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag);



void socket_tcp(int domain, int type, int protocol, int sockfd, int fakeID,pid_t processid);
void socketpair_tcp();
void bind_tcp(int sender, int sockfd, struct sockaddr *addr);
void getsockname_tcp();
void connect_tcp(int sender, int sockfd, struct sockaddr_in *addr);
void getpeername_tcp(int senderid, int sockfd, int addrlen);
void send_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags);
void write_tcp(int senderid, int sockfd, int datalen, u_char *data);


void recv_tcp(int senderid, int sockfd, int datalen, int flags);
void sendto_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *dest_addr, socklen_t addrlen);
void recvfrom_tcp(int senderid, int sockfd, int datalen, int flags, int symbol);
void sendmsg_tcp();
void recvmsg_tcp();
void getsockopt_tcp(int senderid, int sockfd, int level, int optname, int optlen, void *optval);
void setsockopt_tcp(int senderid, int sockfd, int level, int optname, int optlen, void *optval);
void listen_tcp();
void accept_tcp();
void accept4_tcp();
void shutdown_tcp(int senderid,int sockfd,int  how);



#endif /* TCPHANDLING_H_ */
