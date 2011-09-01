/*
 * icmphandling.h
 *
 *  Created on: Jun 29, 2011
 *      Author: dell
 */

#ifndef ICMPHANDLING_H_
#define ICMPHANDLING_H_




#include "handlers.h"


int jinni_ICMP_to_fins(u_char *dataLocal, int len, uint16_t dstport,
		uint32_t dst_IP_netformat, uint16_t hostport,
		uint32_t host_IP_netformat);
int ICMPreadFrom_fins(int senderid, int sockfd, u_char **buf, int *buflen,
		int symbol, struct sockaddr_in *address, int block_flag);



void socket_icmp(int domain, int type, int protocol, int sockfd, int fakeID,pid_t processid);

void write_icmp(int senderid, int sockfd, int datalen, u_char *data);


void recv_icmp(int senderid, int sockfd, int datalen, int flags);
void sendto_icmp(int senderid, int sockfd, int datalen, u_char *data, int flags,
		struct sockaddr *dest_addr, socklen_t addrlen);
void recvfrom_icmp(int senderid, int sockfd, int datalen, int flags, int symbol);
void sendmsg_icmp();
void recvmsg_icmp();
void getsockopt_icmp(int senderid, int sockfd, int level, int optname, int optlen, void *optval);
void setsockopt_icmp(int senderid, int sockfd, int level, int optname, int optlen, void *optval);

void shutdown_icmp(int senderid,int sockfd,int  how);






#endif /* ICMPHANDLING_H_ */
