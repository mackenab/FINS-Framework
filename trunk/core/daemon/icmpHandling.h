/**
 * @file icmpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Jonathan Reed
 */

#ifndef ICMPHANDLING_H_
#define ICMPHANDLING_H_

#define MAX_DATA_PER_ICMP 4096

#include <linux/icmp.h>
#include "daemon.h"

int daemon_fdf_to_icmp(uint8_t *data, uint32_t data_len, metadata *params);

void socket_out_icmp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol);
void bind_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr);
void listen_out_icmp(struct nl_wedge_to_daemon *hdr, int backlog);
void connect_out_icmp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags);
void accept_out_icmp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags);
void getname_out_icmp(struct nl_wedge_to_daemon *hdr, int peer);
void ioctl_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, uint8_t *buf, ssize_t buf_len);
void sendmsg_out_icmp(struct nl_wedge_to_daemon *hdr, uint8_t *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_out_icmp(struct nl_wedge_to_daemon *hdr, int data_len, uint32_t msg_controllen, int flags);
void getsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void setsockopt_out_icmp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void release_out_icmp(struct nl_wedge_to_daemon *hdr);
void poll_out_icmp(struct nl_wedge_to_daemon *hdr, uint32_t events);
void mmap_out_icmp(struct nl_wedge_to_daemon *hdr);
void socketpair_out_icmp(struct nl_wedge_to_daemon *hdr);
void shutdown_out_icmp(struct nl_wedge_to_daemon *hdr, int how);
void close_out_icmp(struct nl_wedge_to_daemon *hdr);
void sendpage_out_icmp(struct nl_wedge_to_daemon *hdr);

void daemon_icmp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);
void daemon_icmp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);

void poll_in_icmp(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags);
void recvmsg_in_icmp(struct daemon_call_list *call_list, struct daemon_call *call, metadata *params, uint8_t *data, uint32_t data_len, uint32_t addr_ip,
		uint32_t flags);

#endif /* ICMPHANDLING_H_ */
