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

int jinni_UDP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat);
int UDPreadFrom_fins(int index, unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag,
		int multi_flag);

void socket_udp(int domain, int type, int protocol, unsigned long long uniqueSockID);
void bind_udp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr);
void listen_udp(int index, unsigned long long uniqueSockID, int backlog);
void connect_udp(int index, unsigned long long uniqueSockID, struct sockaddr_in *addr);
void accept_udp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags);
void getname_udp(int index, unsigned long long uniqueSockID, int peer);
void write_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen);
void send_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags);
void sendto_udp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *addr, socklen_t addrlen);
void recvfrom_udp(int index, unsigned long long uniqueSockID, int datalen, int flags, int msgFlags);
void release_udp(int index, unsigned long long uniqueSockID);

void recv_udp(unsigned long long uniqueSockID, int datalen, int flags); /** UDP DOESN NOT IMPLEMENT recv without sender */
void socketpair_udp();
void getsockname_udp();
void getpeername_udp(unsigned long long uniqueSockID, int addrlen);
//void send_udp(); /** UDP DOESN NOT IMPLEMENT SEND without recipient */

void getsockopt_udp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, u_char *optval);
void setsockopt_udp(int index, unsigned long long uniqueSockID, int level, int optname, int optlen, u_char *optval);
void accept4_udp();
void shutdown_udp(unsigned long long uniqueSockID, int how);

struct jinni_udp_thread_data {
	int id;
	int index;
	unsigned long long uniqueSockID;
	int data_len;
	int flags;
	//int socketCallType; //TODO remove?
	//int symbol; //TODO remove?
};
#define MAX_recv_threads 100

#endif /* UDPHANDLING_H_ */
