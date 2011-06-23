/**
 * @file udpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#ifndef UDPHANDLING_H_
#define UDPHANDLING_H_

#define MAX_DATA_PER_UDP 4096
#define IP4_ADR_P2N(a,b,c,d) 	(16777216ul*(a) + (65536ul*(b)) + (256ul*(c)) + (d))

#include "handlers.h"

int jinni_UDP_to_fins(u_char *dataLocal, int len, uint16_t dstport,
		uint32_t dst_IP_netformat, uint16_t hostport,
		uint32_t host_IP_netformat);
int readFrom_fins(int senderid, int sockfd, u_char **buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag);

void socket_udp(int domain, int type, int protocol, int sockfd, int fakeID,
		int processid);
void socketpair_udp();
void bind_udp(int sender, int sockfd, struct sockaddr *addr);
void getsockname_udp();
void connect_udp(int senderid, int sockfd, struct sockaddr_in *addr);
void getpeername_udp(int senderid, int sockfd, int addrlen);
void send_udp(); /** UDP DOESN NOT IMPLEMENT SEND without recipient */
void recv_udp(int senderid, int sockfd, int datalen, int flags); /** UDP DOESN NOT IMPLEMENT recv without sender */
void write_udp(int senderid, int sockfd, int datalen, u_char *data);
void send_udp(int senderid, int sockfd, int datalen, u_char *data, int flags);
void sendto_udp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *addr, socklen_t addrlen);

void recvfrom_udp(int senderid, int sockfd, int datalen, int flags, int symbol);
void sendmsg_udp();
void recvmsg_udp();
void getsockopt_udp();
void setsockopt_udp();
void listen_udp();
void accept_udp();
void accept4_udp();
void shutdown_udp();

#endif /* UDPHANDLING_H_ */
