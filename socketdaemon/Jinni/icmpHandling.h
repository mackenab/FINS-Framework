/*
 * icmphandling.h
 *
 *  Created on: Jun 29, 2011
 *      Author: dell
 */

#ifndef ICMPHANDLING_H_
#define ICMPHANDLING_H_

#include "handlers.h"

int jinni_ICMP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat);
int ICMPreadFrom_fins(unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag);

void socket_icmp(int domain, int type, int protocol, unsigned long long uniqueSockID);

void write_icmp(unsigned long long uniqueSockID, int datalen, u_char *data);

void listen_icmp(int index, unsigned long long uniqueSockID, int backlog);
void accept_icmp(int index, unsigned long long uniqueSockID, unsigned long long uniqueSockID_new, int flags);
void sendto_icmp(int index, unsigned long long uniqueSockID, u_char *data, int datalen, int flags, struct sockaddr_in *dest_addr, socklen_t addrlen);
void recv_icmp(unsigned long long uniqueSockID, int datalen, int flags);
void recvfrom_icmp(void *threadData);
void sendmsg_icmp();
void recvmsg_icmp();
void getsockopt_icmp(unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void setsockopt_icmp(unsigned long long uniqueSockID, int level, int optname, int optlen, void *optval);
void shutdown_icmp(unsigned long long uniqueSockID, int how);
void release_udp(unsigned long long uniqueSockID);

#endif /* ICMPHANDLING_H_ */
