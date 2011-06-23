/**
 * @file tcpHandling.c
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#include "tcpHandling.h"

void socket_tcp(int domain, int type, int protocol, int sockfd, int processid) {

	return;

}

void bind_tcp(int sender, int sockfd, struct sockaddr *addr) {

	return;
}

void send_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags) {

	sendto_tcp(senderid, sockfd, datalen, data, flags, NULL, 0);

	return;

}

void connect_tcp(int sender, int sockfd, struct sockaddr_in *addr) {

	return;

}

void sendto_tcp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *dest_addr, socklen_t addrlen) {

	return;
}

void recvfrom_tcp(int senderid, int sockfd, int datalen, int flags) {

	return;
}

void recv_tcp(int senderid, int sockfd, int datalen, int flags) {

	recvfrom_tcp(senderid, sockfd, datalen, flags);
	return;

}

void getpeername_tcp(int senderid, int sockfd, int addrlen) {

	return;

}

