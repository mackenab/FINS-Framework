/**
 * @file udpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Jonathan Reed
 */

#ifndef UDPHANDLING_H_
#define UDPHANDLING_H_

#define MAX_DATA_PER_UDP 4096

#include "daemon.h"

void socket_out_udp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol);
void bind_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr);
void listen_out_udp(struct nl_wedge_to_daemon *hdr, int backlog);
void connect_out_udp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags);
void accept_out_udp(struct nl_wedge_to_daemon *hdr, uint64_t uniqueSockID_new, int index_new, int flags);
void getname_out_udp(struct nl_wedge_to_daemon *hdr, int peer);
void ioctl_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, uint8_t *buf, int buf_len);
void sendmsg_out_udp(struct nl_wedge_to_daemon *hdr, uint8_t *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_out_udp(struct nl_wedge_to_daemon *hdr, int data_len, uint32_t msg_controllen, int flags);
void getsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void setsockopt_out_udp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void release_out_udp(struct nl_wedge_to_daemon *hdr);
void poll_out_udp(struct nl_wedge_to_daemon *hdr, uint32_t events);
void mmap_out_udp(struct nl_wedge_to_daemon *hdr);
void socketpair_out_udp(struct nl_wedge_to_daemon *hdr);
void shutdown_out_udp(struct nl_wedge_to_daemon *hdr, int how);
void close_out_udp(struct nl_wedge_to_daemon *hdr);
void sendpage_out_udp(struct nl_wedge_to_daemon *hdr);

void daemon_udp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);
void daemon_udp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);

void poll_in_udp(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags);
void recvmsg_in_udp(struct daemon_call_list *call_list, struct daemon_call *call, metadata *params, uint8_t *data, uint32_t data_len, uint32_t addr_ip,
		uint16_t addr_port, uint32_t flags);

void recvmsg_timeout_udp(struct daemon_call *call);

#define EXEC_UDP_CLEAR_SENT 0

#endif /* UDPHANDLING_H_ */
