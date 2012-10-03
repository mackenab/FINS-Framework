/**
 * @file icmpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Jonathan Reed
 */

#ifndef ICMPHANDLING_H_
#define ICMPHANDLING_H_

#define MAX_DATA_PER_ICMP 4096

#include "daemon.h"

int daemon_fdf_to_icmp(u_char *data, uint32_t data_len, metadata *params);

void socket_out_icmp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol);
void bind_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr);
void listen_out_icmp(struct nl_wedge_to_daemon *hdr, int backlog);
void connect_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags);
void accept_out_icmp(struct nl_wedge_to_daemon *hdr, unsigned long long uniqueSockID_new, int index_new, int flags);
void getname_out_icmp(struct nl_wedge_to_daemon *hdr, int peer);
void ioctl_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, u_char *buf, ssize_t buf_len);
void sendmsg_out_icmp(struct nl_wedge_to_daemon *hdr, u_char *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_out_icmp(struct nl_wedge_to_daemon *hdr, int data_len, int flags, uint32_t msg_flags); //TODO need symbol?
void getsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval);
void setsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval);
void release_out_icmp(struct nl_wedge_to_daemon *hdr);
void poll_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t events);
void mmap_out_icmp(struct nl_wedge_to_daemon *hdr);
void socketpair_out_icmp(struct nl_wedge_to_daemon *hdr);
void shutdown_out_icmp(struct nl_wedge_to_daemon *hdr, int how);
void close_out_icmp(struct nl_wedge_to_daemon *hdr);
void sendpage_out_icmp(struct nl_wedge_to_daemon *hdr);

void daemon_icmp_in_fdf(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t dst_ip, uint16_t dst_port);

void recvmsg_in_icmp(struct daemon_call_list *call_list, struct daemon_call *call, struct finsFrame *ff, uint32_t src_ip, uint16_t src_port);
void poll_icmp_in(struct daemon_call_list *call_list, struct daemon_call *call);

#endif /* ICMPHANDLING_H_ */
