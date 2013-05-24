/**
 * @file udpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#ifndef UDPHANDLING_H_
#define UDPHANDLING_H_

#include "daemon_internal.h"

#define MAX_DATA_PER_UDP 4096

int match_host_addr4_udp(struct fins_module *module, uint32_t host_ip, uint16_t host_port);

int socket_udp_test(int domain, int type, int protocol);
void socket_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int domain);
void daemon_in_fdf_udp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr);
void daemon_in_error_udp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr,
		struct sockaddr_storage *dst_addr);

void bind_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, struct sockaddr_storage *addr);
void listen_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int backlog);
void connect_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, struct sockaddr_storage *addr, int flags);
void accept_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint64_t uniqueSockID_new, int index_new, int flags);
void getname_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int peer);
void ioctl_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint32_t cmd, uint8_t *buf, int buf_len);
void sendmsg_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint8_t *data, uint32_t data_len, uint32_t flags,
		struct sockaddr_storage *dest_addr, int addr_len);
void recvmsg_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int buf_len, uint32_t msg_controllen, int flags);
void getsockopt_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void setsockopt_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, uint8_t *optval);
void release_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr);
void poll_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, uint32_t events);
void mmap_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr);
void socketpair_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr);
void shutdown_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr, int how);
void close_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr);
void sendpage_out_udp(struct fins_module *module, struct nl_wedge_to_daemon *hdr);

void poll_in_udp(struct daemon_call *call, struct fins_module *module, uint32_t *flags);
uint32_t recvmsg_in_udp(struct daemon_call *call, struct fins_module *module, metadata *meta, uint32_t data_len, uint8_t *data, struct sockaddr_storage *addr,
		uint32_t flags);

void recvmsg_timeout_udp(struct fins_module *module, struct daemon_call *call);

#define EXEC_UDP_CLEAR_SENT 0

#endif /* UDPHANDLING_H_ */
