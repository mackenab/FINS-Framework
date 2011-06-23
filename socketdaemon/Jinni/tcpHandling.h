/**
 * @file tcpHandling.h
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#ifndef TCPHANDLING_H_
#define TCPHANDLING_H_

#include "handlers.h"

void socket_tcp(int domain, int type, int protocol, int sockfd, int processid);
void socketpair_tcp();
void bind_tcp(int sender, int sockfd, struct sockaddr *addr);
void getsockname_tcp();
void connect_tcp(int sender, int sockfd, struct sockaddr_in *addr);
void getpeername_tcp(int senderid, int sockfd, int addrlen);
void send_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags);
void recv_tcp(int senderid, int sockfd, int datalen, int flags);
void sendto_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *dest_addr, socklen_t addrlen);
void recvfrom_tcp(int senderid, int sockfd, int datalen, int flags);
void sendmsg_tcp();
void recvmsg_tcp();
void getsockopt_tcp();
void setsockopt_tcp();
void listen_tcp();
void accept_tcp();
void accept4_tcp();
void shutdown_tcp();

#endif /* TCPHANDLING_H_ */
