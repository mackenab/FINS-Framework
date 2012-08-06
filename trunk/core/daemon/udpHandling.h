/**
 * @file udpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#ifndef UDPHANDLING_H_
#define UDPHANDLING_H_

#define MAX_DATA_PER_UDP 4096

#include "handlers.h"

int daemon_UDP_to_fins(u_char *dataLocal, int len, uint16_t dstport, uint32_t dst_IP_netformat, uint16_t hostport, uint32_t host_IP_netformat);
int UDPreadFrom_fins(int index, unsigned long long uniqueSockID, u_char *buf, int *buflen, int symbol, struct sockaddr_in *address, int block_flag,
		int multi_flag);

void socket_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int domain, int type, int protocol);
void bind_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr);
void listen_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int backlog);
void connect_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, struct sockaddr_in *addr, int flags);
void accept_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, unsigned long long uniqueSockID_new, int index_new, int flags);
void getname_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int peer);
void ioctl_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_int cmd, u_char *buf, ssize_t buf_len);
void send_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags);
void sendto_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, u_char *data, u_int data_len, u_int flags,
		struct sockaddr_in *dest_addr, socklen_t addrlen);
void recvfrom_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int data_len, int flags, u_int msg_flags); //TODO need symbol?
void getsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void setsockopt_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int level, int optname, int optlen, u_char *optval);
void release_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void poll_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void mmap_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void socketpair_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void shutdown_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index, int how);
void close_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);
void sendpage_udp(unsigned long long uniqueSockID, int index, u_int call_id, int call_index);

struct daemon_udp_thread_data {
	int id;
	unsigned long long uniqueSockID;
	int index;
	u_int call_id;
	int call_index;

	int data_len;
	int flags;
	//int socketCallType; //TODO remove?
	//int symbol; //TODO remove?
};
#define MAX_recv_threads 100

#endif /* UDPHANDLING_H_ */
