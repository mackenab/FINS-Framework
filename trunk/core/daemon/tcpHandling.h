/**
 * @file tcpHandling.h
 *
 *  @date Nov 28, 2010
 *      @author Abdallah Abdallah
 */

#ifndef TCPHANDLING_H_
#define TCPHANDLING_H_

#define MAX_DATA_PER_TCP 4096

#include "daemon.h"

int daemon_fdf_to_tcp(u_char *data, uint32_t data_len, metadata *params);
int daemon_fcf_to_tcp(metadata *params, uint32_t serial_num, uint16_t opcode, uint32_t param_id);

void socket_out_tcp(struct nl_wedge_to_daemon *hdr, int domain, int type, int protocol);
void bind_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr);
void listen_out_tcp(struct nl_wedge_to_daemon *hdr, int backlog);
void connect_out_tcp(struct nl_wedge_to_daemon *hdr, struct sockaddr_in *addr, int flags);
void accept_out_tcp(struct nl_wedge_to_daemon *hdr, uint64_t sock_id_new, int sock_index_new, int flags);
void getname_out_tcp(struct nl_wedge_to_daemon *hdr, int peer);
void ioctl_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t cmd, u_char *buf, ssize_t buf_len);
void sendmsg_out_tcp(struct nl_wedge_to_daemon *hdr, u_char *data, uint32_t data_len, uint32_t flags, struct sockaddr_in *dest_addr, int addr_len);
void recvmsg_out_tcp(struct nl_wedge_to_daemon *hdr, int data_len, int flags);
void getsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval);
void setsockopt_out_tcp(struct nl_wedge_to_daemon *hdr, int level, int optname, int optlen, u_char *optval);
void release_out_tcp(struct nl_wedge_to_daemon *hdr);
void poll_out_tcp(struct nl_wedge_to_daemon *hdr, uint32_t events);
void mmap_out_tcp(struct nl_wedge_to_daemon *hdr);
void socketpair_out_tcp(struct nl_wedge_to_daemon *hdr);
void shutdown_out_tcp(struct nl_wedge_to_daemon *hdr, int how);
void close_out_tcp(struct nl_wedge_to_daemon *hdr);
void sendpage_out_tcp(struct nl_wedge_to_daemon *hdr);

void connect_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags);
void accept_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint64_t sock_id_new,
		int sock_index_new, uint32_t flags);
void sendmsg_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t flags);
void getsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data);
void setsockopt_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data);
void release_in_tcp(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index);
void poll_in_tcp_fcf(struct finsFrame *ff, uint32_t call_id, int call_index, uint32_t call_type, uint64_t sock_id, int sock_index, uint32_t data);

void daemon_tcp_in_fdf(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);
void daemon_tcp_in_error(struct finsFrame *ff, uint32_t src_ip, uint32_t dst_ip);

void poll_in_tcp_fdf(struct daemon_call_list *call_list, struct daemon_call *call, uint32_t flags);
void recvmsg_in_tcp_fdf(struct daemon_call_list *call_list, struct daemon_call *call, struct finsFrame *ff, uint32_t src_ip, uint16_t src_port, uint32_t flags);

#define SET_PARAM_TCP_HOST_WINDOW 0
#define SET_PARAM_TCP_SOCK_OPT 1

#define READ_PARAM_TCP_HOST_WINDOW 0
#define READ_PARAM_TCP_SOCK_OPT 1

#endif /* TCPHANDLING_H_ */
