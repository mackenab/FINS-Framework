/**
 * @file tcpHandling.h
 *
 *  @date Nov 28, 2010
 *  @author Abdallah Abdallah
 */

#ifndef TCPHANDLING_H_
#define TCPHANDLING_H_

#include "daemon_internal.h"

#define MAX_DATA_PER_TCP 4096

int match_host_addr4_tcp(struct fins_module *module, uint32_t host_ip, uint16_t host_port);
int match_conn_addr4_tcp(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
int match_packet_addr4_tcp(struct fins_module *module, uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port);

int socket_tcp_test(int domain, int type, int protocol);
void socket_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int domain);
void daemon_in_fdf_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr, struct sockaddr_storage *dst_addr);
void daemon_in_error_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t family, struct sockaddr_storage *src_addr,
		struct sockaddr_storage *dst_addr);
void daemon_in_poll_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t ret_msg);
void daemon_in_shutdown_tcp(struct fins_module *module, struct finsFrame *ff, uint32_t ret_msg);

void bind_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr);
void listen_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int backlog);
void connect_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, struct sockaddr_storage *addr, int flags);
void accept_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint64_t sock_id_new, int sock_index_new, int flags);
void getname_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int peer);
void ioctl_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t cmd, int buf_len, uint8_t *buf);
void sendmsg_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t data_len, uint8_t *data, uint32_t flags, int addr_len,
		struct sockaddr_storage *dest_addr);
void recvmsg_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int buf_len, uint32_t msg_controllen, int flags);
void getsockopt_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval);
void setsockopt_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int level, int optname, int optlen, uint8_t *optval);
void release_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
void poll_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, uint32_t events);
void mmap_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
void socketpair_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
void shutdown_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr, int how);
void close_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);
void sendpage_out_tcp(struct fins_module *module, struct wedge_to_daemon_hdr *hdr);

void connect_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void accept_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void sendmsg_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void getsockopt_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void setsockopt_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void release_in_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);
void poll_in_tcp_fcf(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call);

void poll_in_tcp_fdf(struct daemon_call *call, struct fins_module *module, uint32_t *flags);
uint32_t recvmsg_in_tcp_fdf(struct daemon_call *call, struct fins_module *module, metadata *meta, uint32_t data_len, uint8_t *data,
		struct sockaddr_storage *addr, uint32_t flags);

void connect_timeout_tcp(struct fins_module *module, struct daemon_call *call);
void accept_timeout_tcp(struct fins_module *module, struct daemon_call *call);
void recvmsg_timeout_tcp(struct fins_module *module, struct daemon_call *call);

void connect_expired_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply);
void accept_expired_tcp(struct fins_module *module, struct finsFrame *ff, struct daemon_call *call, uint8_t reply);

#define DAEMON_EXEC_TCP_CONNECT 0
#define DAEMON_EXEC_TCP_LISTEN 1
#define DAEMON_EXEC_TCP_ACCEPT 2
#define DAEMON_EXEC_TCP_SEND 3
#define DAEMON_EXEC_TCP_RECV 4
#define DAEMON_EXEC_TCP_CLOSE 5
#define DAEMON_EXEC_TCP_CLOSE_STUB 6
#define DAEMON_EXEC_TCP_OPT 7
#define DAEMON_EXEC_TCP_POLL 8

#define DAEMON_SET_PARAM_TCP_HOST_WINDOW 3
#define DAEMON_SET_PARAM_TCP_SOCK_OPT 4

#define DAEMON_READ_PARAM_TCP_HOST_WINDOW 3
#define DAEMON_READ_PARAM_TCP_SOCK_OPT 4

//sockopts trying to support
//TCP_NODELAY
//SO_DEBUG
//SO_REUSEADDR
//SO_SNDBUF
//SO_RCVBUF
//SO_KEEPALIVE
//SO_OOBINLINE
//SO_PRIORITY

#endif /* TCPHANDLING_H_ */
