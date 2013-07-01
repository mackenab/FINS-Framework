/*
 * tcp_internal.h
 *
 *  Created on: May 4, 2013
 *      Author: Jonathan Reed
 */

#ifndef TCP_INTERNAL_H_
#define TCP_INTERNAL_H_

#include <errno.h>
#include <linux/net.h>
#include <math.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifdef BUILD_FOR_ANDROID
#include <linux/time.h>
#include <sys/endian.h>
//#include <sys/linux-unistd.h>
#endif

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <finsthreads.h>
#include <metadata.h>
#include <finsqueue.h>

#include "tcp.h"

//Macros for the TCP header

//These can be ANDed (bitwise, of course) with the 'flags' field of the tcp_segment structure to get the appropriate flags.
#define FLAG_FIN		0x01	//No more data from sender
#define FLAG_SYN		0x02	//Synchronize sequence numbers
#define FLAG_RST		0x04	//Reset the connection
#define FLAG_PSH		0x08	//Push the buffered data to the receiving application
#define FLAG_ACK		0x10	//The acknowledgment field is significant
#define FLAG_URG		0x20	//Urgent pointer field is significant
#define FLAG_ECE		0x40	//ECN-Echo flag
#define FLAG_CWR		0x80	//Congestion Reduced Window
#define FLAG_NS			0x100	//ECN-nonce concealment protection.
//bytes 4-6 in this field are reserved for future use and should be set = 0
#define FLAG_DATAOFFSET	0xF000	//For easily grabbing the data offset from the flags field
#define FLAG_RESERVED	0x0E00
#define FLAG_ECN		0x01C0
#define FLAG_CONTROL	0x003F

//flags defined for this implementation
#define FLAG_ACK_PLUS	0x1000

//header & option sizes in words
#define MAX_TCP_OPTIONS_WORDS		(10)
#define MIN_TCP_HEADER_WORDS		(5)
#define MAX_TCP_HEADER_WORDS		(MIN_TCP_HEADER_WORDS + MAX_TCP_OPTIONS_WORDS)
#define TCP_HEADER_WORDS(flags)		((flags & FLAG_DATAOFFSET) >> 12)
#define TCP_OPTIONS_WORDS(flags)	(TCP_HEADER_WORDS(flags) - MIN_TCP_HEADER_WORDS)

//Byte equivalent
#define WORDS_TO_BYTES(words)		(words*4)
#define MAX_TCP_OPTIONS_BYTES		WORDS_TO_BYTES(MAX_TCP_OPTIONS_WORDS)
#define MIN_TCP_HEADER_BYTES		WORDS_TO_BYTES(MIN_TCP_HEADER_WORDS)
#define MAX_TCP_HEADER_BYTES		WORDS_TO_BYTES(MAX_TCP_HEADER_WORDS)
#define TCP_HEADER_BYTES(flags)		WORDS_TO_BYTES(TCP_HEADER_WORDS(flags))	//For easily grabbing the size of the header in bytes from the flags field
#define TCP_OPTIONS_BYTES(flags)	WORDS_TO_BYTES(TCP_OPTIONS_WORDS(flags))

//#define TCP_PROTOCOL 		IPPROTO_TCP //6
#define IP_HEADER_WORDS 	3
#define IP_HEADER_BYTES 	(IP_HEADER_WORDS*4)

//#define MAX_OPTIONS_LEN			320						//Maximum number of bits in the options field of the TCP header is 320 bits, says RFC
//#define MIN_DATA_OFFSET			5						//As per RFC spec, if the TCP header has no options set, the length will be 5 32-bit segments
//#define MIN_TCP_HEADER_LEN		MIN_DATA_OFFSET * 4	//Therefore, the minimum TCP header length is 4*5=20 bytes
//#define MAX_TCP_HEADER_LEN		MAX_OPTIONS_LEN + MIN_TCP_HEADER_LEN	//Maximum TCP header size, as defined by the maximum options size
//typedef unsigned long IP4addr; /*  internet address			*/

struct tcp_request {
	uint8_t *data;
	uint32_t len;
	uint32_t flags;
	uint32_t serial_num;
	//TO?

	struct intsem_to_timer_data *to_data;
	uint8_t to_flag;
};

//structure for a record of a tcp_queue
struct tcp_node {
	struct tcp_node *next; //Next item in the list
	uint8_t *data; //Actual data
	uint32_t len;
	uint32_t seq_num;
	uint32_t seq_end;
};

struct tcp_node *tcp_node_create(uint8_t *data, uint32_t len, uint32_t seq_num, uint32_t seq_end);
int tcp_node_compare(struct tcp_node *node, struct tcp_node *cmp, uint32_t win_seq_num, uint32_t win_seq_end);
void tcp_node_free(struct tcp_node *node);

//Structure for the ordered queue of outgoing/incoming packets for a TCP connection
struct tcp_queue {
	uint32_t max;
	uint32_t len;
	struct tcp_node *front;
	struct tcp_node *end;
};

//TODO convert to struct linked_list from common
struct tcp_queue *tcp_queue_create(uint32_t max); //TODO change to struct common_list in common
void tcp_queue_append(struct tcp_queue *queue, struct tcp_node *node);
void tcp_queue_prepend(struct tcp_queue *queue, struct tcp_node *node);
void tcp_queue_add(struct tcp_queue *queue, struct tcp_node *node, struct tcp_node *prev);

//specific funcs, rest are general
int tcp_queue_insert(struct tcp_queue *queue, struct tcp_node *node, uint32_t win_seq_num, uint32_t win_seq_end); //TCP specific
struct tcp_node *tcp_queue_find(struct tcp_queue *queue, uint32_t seq_num); //TCP specific

struct tcp_node *tcp_queue_remove_front(struct tcp_queue *queue);
void tcp_queue_remove(struct tcp_queue *queue, struct tcp_node *node);
int tcp_queue_check(struct tcp_queue *queue);
int tcp_queue_is_empty(struct tcp_queue *queue);
int tcp_queue_is_full(struct tcp_queue *queue);
//replace with: list_space(list) >= len
int tcp_queue_has_space(struct tcp_queue *queue, uint32_t len);
void tcp_queue_free(struct tcp_queue *queue);

struct tcp_conn_stub_stats { //Per connection & have one for totals for entire module
	uint16_t bad_checksum; /* total number of segments that have a bad checksum */
	uint16_t no_checksum; /* total number of segments with no checksum */
	uint16_t mismatching_lengths; /* total number of segments with mismatching segment lengths from the header and pseudoheader */
	uint32_t bad_segments; /* total number of segments that were thrown away */
	uint32_t received; /* total number of incoming TCP segments */
	uint32_t sent; /* total number of outgoing TCP segments */
//RSTs?
};

struct tcp_conn_stub {
	//## protected by conn_stub_list_sem
	//struct tcp_conn_stub *next;
	uint32_t threads;
	//##

	struct fins_module *module;
	sem_t sem;

	uint32_t family;
	struct sockaddr_storage *host_addr;
	uint32_t host_ip; //IP address of this machine
	uint16_t host_port; //Port on this machine that this connection is taking up

	struct tcp_queue *syn_queue; //buffer for recv tcp_seg SYN requests
	//struct thread_pool *pool;

	uint32_t poll_events;
	//int syn_threads;

	//int accept_threads;
	sem_t accept_wait_sem;

	uint8_t running_flag;
	//uint32_t backlog; //TODO ?

	struct tcp_conn_stub_stats stats;
};

struct tcp_conn_stub *tcp_conn_stub_create(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t backlog);
int tcp_conn_stub_addr_test(struct tcp_conn_stub *conn_stub, uint32_t *host_ip, uint16_t *host_port);
//int conn_stub_send_jinni(struct tcp_conn_stub *conn_stub, uint32_t param_id, uint32_t ret_val);
int tcp_conn_stub_send_daemon(struct tcp_conn_stub *conn_stub, uint32_t param_id, uint32_t ret_val, uint32_t ret_msg);
void tcp_conn_stub_shutdown(struct tcp_conn_stub *conn_stub);
void tcp_conn_stub_free(struct tcp_conn_stub *conn_stub);
//int conn_stub_add(uint32_t src_ip, uint16_t src_port);

typedef enum {
	TS_CLOSED = 0, TS_SYN_SENT, TS_LISTEN, TS_SYN_RECV, TS_ESTABLISHED, TS_FIN_WAIT_1, TS_FIN_WAIT_2, TS_CLOSING, TS_TIME_WAIT, TS_CLOSE_WAIT, TS_LAST_ACK
} tcp_state;

typedef enum {
	RENO_SLOWSTART = 0, RENO_AVOIDANCE, RENO_RECOVERY
} tcp_reno_state;

#define TCP_STATUS_NONE 0x0
#define TCP_STATUS_RD 	0x1
#define TCP_STATUS_WR 	0x2
#define TCP_STATUS_RDWR (TCP_STATUS_RD|TCP_STATUS_WR)

struct ipv4_header {
	uint32_t src_ip; //Source ip
	uint32_t dst_ip; //Destination ip
	uint8_t zeros; //Unused zeros
	uint8_t protocol; //protocol
	uint16_t tcp_len; //TCP length
};

struct tcpv4_header {
	uint16_t src_port; //Source port
	uint16_t dst_port; //Destination port
	uint32_t seq_num; //Sequence number
	uint32_t ack_num; //Acknowledgment number
	uint16_t flags; //Flags and data offset
	uint16_t win_size; //Window size
	uint16_t checksum; //TCP checksum
	uint16_t urg_pointer; //Urgent pointer (If URG flag set)
	uint8_t options[MAX_TCP_OPTIONS_BYTES]; //Options for the TCP segment (If Data Offset > 5) //TODO iron out full options mechanism
};

struct tcp_packet {
	struct ipv4_header ip_hdr;
	struct tcpv4_header tcp_hdr;
};

struct tcp_packet2 {
	uint32_t src_ip; //Source ip
	uint32_t dst_ip; //Destination ip
	uint8_t zeros; //Unused zeros
	uint8_t protocol; //protocol
	uint16_t tcp_len; //TCP length
	uint16_t src_port; //Source port
	uint16_t dst_port; //Destination port
	uint32_t seq_num; //Sequence number
	uint32_t ack_num; //Acknowledgment number
	uint16_t flags; //Flags and data offset
	uint16_t win_size; //Window size
	uint16_t checksum; //TCP checksum
	uint16_t urg_pointer; //Urgent pointer (If URG flag set)
	uint8_t options[MAX_TCP_OPTIONS_BYTES]; //Options for the TCP segment (If Data Offset > 5) //TODO iron out full options mechanism
};

struct tcp_conn_stats { //Per connection & have one for totals for entire module
	uint32_t sent_segs; /* total number of outgoing TCP segments */
	uint32_t fast; /* total number of fast retransmits */
	uint32_t gbn; /* total number of GBN */

	uint64_t sent_bytes; /* total number of byes sent */
	uint64_t sent_data; /* total number of data sent in bytes */

	uint32_t send_data_len_total; /* total send data_len */
	uint32_t send_data_len_count; /* count send data_len */

	double timeout_total; /* total timeout */
	uint32_t timeout_count; /* count timeout */

	double cong_window_total; /* total congestion window */
	uint32_t cong_window_count; /* count congestion window */

	double threshhold_total; /* total threshhold */
	uint32_t threshhold_count; /* count threshhold */

	uint16_t mismatching_lengths; /* total number of segments with mismatching segment lengths from the header and pseudoheader */
	uint32_t recv_segs; /* total number of received TCP segments */
	uint16_t no_checksum; /* total number of segments with no checksum */
	uint16_t bad_checksum; /* total number of segments that have a bad checksum */

	uint32_t drop_segs; /* total number of segments that were thrown away because of incorrect states, etc*/
	uint32_t in_order_segs; /* total number of in order TCP segments */
	uint32_t out_order_segs; /* total number of out of order TCP segments */
	uint32_t dup_segs; /* total number of duplicate segments */

	uint32_t recv_acks; /* total number of received ACKs */
	uint32_t bad_acks; /* total number of bad ACKs */
	uint32_t dup_acks; /* total number of duplicate ACKs */

	uint64_t recv_bytes; /* total number of byes received */
	uint64_t recv_data; /* total number of data received in bytes */

	uint32_t recv_data_len_total; /* total recv data_len */
	uint32_t recv_data_len_count; /* count recv data_len */

	double rtt_est_total; /* total RTT estimate */
	uint32_t rtt_est_count; /* count RTT estimate */

	double rtt_dev_total; /* total RTT deviation */
	uint32_t rtt_dev_count; /* count RTT deviation */

//Need to determine when to calculate this
//uint32_t send_win_total; /* total send window */
//uint32_t send_win_count; /* count send window */
//uint32_t recv_win_total; /* total recv window */
//uint32_t recv_win_count; /* count recv window */
};

//Structure for TCP connections that we have open at the moment
struct tcp_conn {
	uint32_t threads; //Number of threads accessing this obj

	struct fins_module *module;
	sem_t sem; //for next, state, write_threads
	uint8_t running_flag; //signifies if it is running, 0=when shutting down
	tcp_state state;
	uint8_t status;

	//struct thread_pool *pool; //removed as no longer doing highly multithreaded

	uint32_t family;
	struct sockaddr_storage *host_addr; //IP address/port of this machine //TODO transition to this
	struct sockaddr_storage *rem_addr; //IP address/port of remote machine //TODO transition to this

	uint32_t host_ip; //IP address of this machine
	uint16_t host_port; //Port on this machine that this connection is taking up
	uint32_t rem_ip; //IP address of remote machine
	uint16_t rem_port; //Port on remote machine

	struct tcp_queue *request_queue; //buffer for sendmsg requests to be added to write_queue - nonblocking requests may TO and be removed
	struct tcp_queue *write_queue; //buffer for raw data to be transfered - guaranteed to be transfered
	struct tcp_queue *send_queue; //buffer for sent tcp_seg that are unACKed
	struct tcp_queue *recv_queue; //buffer for recv tcp_seg that are unACKed - ordered out of order packets
	//struct tcp_queue *read_queue; //buffer for raw data that has been transfered //TODO push straight to daemon?

	pthread_t main_thread;
	uint8_t main_wait_flag;
	sem_t main_wait_sem;
	uint8_t main_waiting;

	uint8_t request_interrupt;
	int request_index;
	uint32_t write_index;
	uint32_t poll_events;

	uint8_t first_flag;
	uint32_t duplicate;
	uint8_t fast_flag;

	struct sem_to_timer_data *to_msl_data;
	uint8_t to_msl_flag; //1=MSL timeout occurred
	//uint8_t msl_flag; //1=performing MSL

	struct sem_to_timer_data *to_gbn_data;
	uint8_t to_gbn_flag; //1=GBN timeout occurred
	uint8_t gbn_flag; //1=performing GBN
	struct tcp_node *gbn_node;

	struct sem_to_timer_data *to_delayed_data;
	uint8_t to_delayed_flag; //1=delayed ack timeout occured
	uint8_t delayed_flag; //0=no delayed ack, 1=delayed ack
	uint16_t delayed_ack_flags;

	//host:send_win == rem:recv_win, host:recv_win == rem:send_win

	uint8_t fin_sent;
	uint8_t fin_sep; //TODO replace with fin_seq

	uint32_t issn; //initial send seq num
	uint32_t fsse; //final send seq end, so fsse == ACK of FIN
	uint32_t irsn; //initial recv seq num
	//uint32_t frsn; //final recv seq num, so frsn == figure out?

	uint32_t send_max_win; //max bytes in rem recv buffer, tied with host_seq_num/send_queue
	uint32_t send_win; //avail bytes in rem recv buffer
	uint32_t send_win_seq; //TODO shorten to send_last_seq & send_last_ack
	uint32_t send_win_ack;
	uint32_t send_seq_num; //seq of host sendbase, tied with send_queue, seq of unACKed data
	uint32_t send_seq_end; //1+seq of last sent byte by host, == send_next

	uint32_t recv_max_win; //max bytes in host recv buffer, tied with rem_seq_num/recv_queue
	uint32_t recv_win; //avail bytes in host recv buffer //actually 16 bits
	uint32_t recv_seq_num; //seq of rem sendbase, tied with recv_queue
	uint32_t recv_seq_end; //seq of last inside rem window
	uint8_t flow_stopped; //1=in ESTABLISEHD/FIN_WAIT_1 hit recv_win==0 & sent seg to stop flow

	uint16_t MSS; //max segment size
	tcp_reno_state cong_state;
	double cong_window;
	double threshhold;

	uint8_t rtt_flag;
	uint32_t rtt_first;
	uint32_t rtt_seq_end;
	struct timeval rtt_stamp;
	double rtt_est;
	double rtt_dev;
	double timeout;

	uint8_t active_open;
	struct finsFrame *ff;

	struct tcp_conn_stats stats;

	//some type of options state
	uint8_t tsopt_attempt; //attempt time stamp option
	uint8_t tsopt_enabled; //time stamp option enabled
	uint32_t ts_rem; //latest ts val from rem
	uint32_t ts_used;

	uint8_t sack_attempt; //attempt selective ACK option
	uint8_t sack_enabled; //selective ACK option enabled
	uint8_t sack_len;

	uint8_t wsopt_attempt; //attempt window scaling option
	uint8_t wsopt_enabled; //window scaling option enabled
	uint8_t ws_send; //window scaling applied on sending
	uint8_t ws_recv; //window scaling applied on recving

	//-------------------------------------------------------------alternate implementation for sending
	uint8_t *send_buf; //send buf, circular buffer that keeps data to send
	uint32_t send_len; //size of send buffer
	uint32_t send_start; //index in send_buf that corresponds to send_seq_num (SSN)
	uint32_t send_next; //index in send_buf that corresponds to send_seq_end (SSE)
	uint32_t send_end; //index in send_buf that corresponds to (1+end of data), so is where write to next
	struct tcp_packet *send_pkt; //the single tcpv4_packet used for sending

//if start == end, then no data written, next-start = len of data unACKed,
//for optimization malloc a single packet for sending since for info:
//doesn't change: src ip, dst ip, protocol, src port, dst port
//always latest: ack, win, options
//per seg: ip_tcp_len, seq_num, flags, checksum, urg pointer, data
//just reference data in send_buffer

//call:
//update_pkt_latest(conn, flag?): ack, win, opts, opt_len;
//update_pkt_seg(seq, flags, data, data_len, urg pt): ip_tcp_len, checksum;
//checksum(pkt, opt_len, data, data_len): checksum
};

//TODO raise any of these?
#define TCP_THREADS_MAX 50 //TODO set thread limits by call?
#define TCP_MAX_QUEUE_DEFAULT 131072//65535
#define TCP_CONN_MAX 512
#define TCP_GBN_TO_MIN 1000
#define TCP_GBN_TO_MAX 64000
#define TCP_GBN_TO_DEFAULT 5000
#define TCP_DELAYED_TO_DEFAULT 200
#define TCP_MAX_SEQ_NUM 4294967295.0
#define TCP_MAX_WINDOW_DEFAULT 65535//8191
#define TCP_MSS_DEFAULT_LARGE 1460 //also said to be, 536 //Headers + MSS ≤ MTU
#define TCP_MSS_DEFAULT_SMALL 536 //also said to be, 536
#define TCP_MSL_TO_DEFAULT 120000 //max seg lifetime TO
#define TCP_KA_TO_DEFAULT 7200000 //keep alive TO
#define TCP_SEND_MIN 4096
#define TCP_SEND_MAX 3444736
#define TCP_SEND_DEFAULT 16384
#define TCP_RECV_MIN 4096
#define TCP_RECV_MAX 3444736
#define TCP_RECV_DEFAULT 87380
#define TCP_SYN_RETRIES
#define TCP_SYNACK_RETRIES

//TCP Options
#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_MSS_BYTES 4
#define TCP_OPT_WS 3
#define TCP_OPT_WS_BYTES 3
#define TCP_OPT_WS_DEFAULT 2 //default value?
#define TCP_OPT_WS_MAX 14
#define TCP_OPT_SACK_PERM 4
#define TCP_OPT_SACK_PERM_BYTES 2
#define TCP_OPT_SACK 5
#define TCP_OPT_SACK_BYTES(x) (8*x+2)
#define TCP_OPT_SACK_MIN_BYTES TCP_OPT_SACK_BYTES(0)
#define TCP_OPT_SACK_MAX_BYTES TCP_OPT_SACK_BYTES(3)
#define TCP_OPT_SACK_LEN(x) ((x-2)/8)
#define TCP_OPT_TS 8
#define TCP_OPT_TS_BYTES 10

struct tcp_conn *tcp_conn_create(struct fins_module *module, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
int tcp_conn_addr_test(struct tcp_conn *conn, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port);
int tcp_conn_send_fcf(struct tcp_conn *conn, uint16_t opcode, uint32_t param_id, uint32_t ret_val, uint32_t ret_msg);
int tcp_conn_send_exec_reply(struct tcp_conn *conn, uint32_t serialNum, uint32_t param_id, uint32_t ret_val, uint32_t ret_msg);
int tcp_conn_reply_fcf(struct tcp_conn *conn, uint32_t ret_val, uint32_t ret_msg);
int tcp_conn_is_finished(struct tcp_conn *conn);
void tcp_conn_shutdown(struct tcp_conn *conn);
void tcp_conn_stop(struct tcp_conn *conn); //TODO remove, move above tcp_main_thread, makes private
void tcp_conn_free(struct tcp_conn *conn);

void tcp_handle_requests(struct tcp_conn *conn);

//Object for TCP segments all values are in host format
struct tcp_seg {
	uint16_t src_port; //Source port
	uint16_t dst_port; //Destination port
	uint32_t seq_num; //Sequence number
	uint32_t ack_num; //Acknowledgment number
	uint16_t flags; //Flags and data offset
	uint16_t win_size; //Window size
	uint16_t checksum; //TCP checksum
	uint16_t urg_pointer; //Urgent pointer (If URG flag set)
	uint8_t options[MAX_TCP_OPTIONS_BYTES]; //Options for the TCP segment (If Data Offset > 5) //TODO iron out full options mechanism

	int opt_len; //length of the options in bytes
	uint8_t *data; //Actual TCP segment data
	int data_len; //Length of the data. This, of course, is not in the original TCP header.

	uint32_t src_ip; //Source addr
	uint32_t dst_ip; //Destination addr
	uint32_t seq_end;

//uint32_t ts_val;
//uint32_t ts_secr;
//uint32_t sack_len;
};

void tcp_srand(void); //Seed the random number generator
int tcp_rand(void); //Get a random number
uint32_t tcp_gen_thread_id(struct fins_module *module);

struct finsFrame *tcp_to_fdf(struct tcp_seg *tcp);
struct tcp_seg *fdf_to_tcp(struct finsFrame *ff);

struct tcp_seg *tcp_seg_create(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port, uint32_t seq_num, uint32_t seq_end);
uint32_t tcp_seg_add_data(struct tcp_seg *seg, struct tcp_queue *queue, uint32_t index, int data_len);
uint16_t tcp_seg_checksum(struct tcp_seg *seg);
int tcp_seg_send(struct fins_module *module, struct tcp_seg *seg);
void tcp_seg_free(struct tcp_seg *seg);

void tcp_seg_update(struct tcp_seg *seg, struct tcp_conn *conn, uint16_t flags);
void tcp_seg_delayed_ack(struct tcp_seg *seg, struct tcp_conn *conn);

int tcp_in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end);
int tcp_in_window_overlaps(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end);

struct tcp_thread_data {
	uint32_t id;
	struct tcp_conn *conn; //TODO change conn/conn_stub to union?
	struct tcp_conn_stub *conn_stub;
	struct tcp_seg *seg; //TODO change seg/raw to union?
	uint8_t *data_raw;
	uint32_t data_len;
	uint32_t flags;
	uint32_t serial_num;
	struct finsFrame *ff;
};

//General functions for dealing with the incoming and outgoing frames
int tcp_fcf_to_daemon(struct fins_module *module, socket_state state, uint32_t param_id, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip,
		uint16_t rem_port, uint32_t ret_val);
int tcp_fdf_to_daemon(struct fins_module *module, uint8_t *data, int data_len, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void tcp_reply_fcf(struct fins_module *module, struct finsFrame *ff, uint32_t ret_val, uint32_t ret_msg);

#define TCP_REQUEST_LIST_MAX 30 //equal to DAEMON_CALL_LIST_MAX
#define TCP_BLOCK_DEFAULT 500 //default block time (ms) for sendmsg
void tcp_metadata_read_conn(metadata *meta, socket_state *state, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port);
void tcp_metadata_write_conn(metadata *meta, socket_state *state, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port);

void tcp_exec_close(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void tcp_exec_close_stub(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port);
void tcp_exec_listen(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t backlog);
void tcp_exec_accept(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t flags);
void tcp_exec_connect(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port,
		uint32_t flags);
void tcp_exec_poll(struct fins_module *module, struct finsFrame *ff, socket_state state, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip,
		uint16_t rem_port, uint32_t initial, uint32_t flags);

int tcp_process_options(struct tcp_conn *conn, struct tcp_seg *seg);

/*
 void tcp_read_param_host_window(struct finsFrame *ff);
 void tcp_read_param_sock_opt(struct finsFrame *ff);

 void tcp_set_param_host_window(struct finsFrame *ff);
 void tcp_set_param_sock_opt(struct finsFrame *ff);
 */

//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application
//--------------------------------------------------- //temp stuff to cross compile, remove/implement better eventual?
#ifndef POLLRDNORM
#define POLLRDNORM POLLIN
#endif

#ifndef POLLRDBAND
#define POLLRDBAND POLLIN
#endif

#ifndef POLLWRNORM
#define POLLWRNORM POLLOUT
#endif

#ifndef POLLWRBAND
#define POLLWRBAND POLLOUT
#endif
//---------------------------------------------------

#define TCP_LIB "tcp"
#define TCP_MAX_FLOWS 	3
#define TCP_FLOW_IPV4 	0
#define TCP_FLOW_ICMP 	1
#define TCP_FLOW_DAEMON	2

struct tcp_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[TCP_MAX_FLOWS];

	pthread_t switch_to_tcp_thread;

	sem_t conn_stub_list_sem;
	struct linked_list *conn_stub_list; //The list of current connections we have

	sem_t conn_list_sem;
	struct linked_list *conn_list; //The list of current connections we have

	uint32_t thread_id_num;
	sem_t thread_id_sem;

	//module values
	uint8_t fast_enabled;
	uint32_t fast_duplicates;

	uint32_t mss;

	struct tcp_conn_stub_stats total_conn_stub_stats;
	struct tcp_conn_stats total_conn_stats;
//struct linked_list *if_list;
};

int tcp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int tcp_run(struct fins_module *module, pthread_attr_t *attr);
int tcp_pause(struct fins_module *module);
int tcp_unpause(struct fins_module *module);
int tcp_shutdown(struct fins_module *module);
int tcp_release(struct fins_module *module);

void tcp_get_ff(struct fins_module *module);
void tcp_fcf(struct fins_module *module, struct finsFrame *ff);
void tcp_read_param(struct fins_module *module, struct finsFrame *ff);
void tcp_set_param(struct fins_module *module, struct finsFrame *ff);
void tcp_exec(struct fins_module *module, struct finsFrame *ff);
void tcp_error(struct fins_module *module, struct finsFrame *ff);

void tcp_in_fdf(struct fins_module *module, struct finsFrame *ff);
void tcp_out_fdf(struct fins_module *module, struct finsFrame *ff);

#define TCP_ALERT_POLL 0
#define TCP_ALERT_SHUTDOWN 1 //TODO change to alert?

//don't use 0
#define TCP_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define TCP_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define TCP_GET_PARAM_DUAL 	MOD_GET_PARAM_DUAL
#define TCP_GET_HOST_WINDOW 3
#define TCP_GET_SOCK_OPT 	4
#define TCP_GET_FAST_ENABLED__id 5
#define TCP_GET_FAST_ENABLED__str "fast_enabled"
#define TCP_GET_FAST_ENABLED__type META_TYPE_INT32
#define TCP_GET_FAST_DUPLICATES__id 6
#define TCP_GET_FAST_DUPLICATES__str "fast_duplicates"
#define TCP_GET_FAST_DUPLICATES__type META_TYPE_INT32
#define TCP_GET_FAST_RETRANSMITS__id 7
#define TCP_GET_FAST_RETRANSMITS__str "fast_retransmits"
#define TCP_GET_FAST_RETRANSMITS__type META_TYPE_INT32
#define TCP_GET_MSS__id 8
#define TCP_GET_MSS__str "mss"
#define TCP_GET_MSS__type META_TYPE_INT32

#define TCP_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define TCP_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define TCP_SET_PARAM_DUAL 	MOD_SET_PARAM_DUAL
#define TCP_SET_HOST_WINDOW 3
#define TCP_SET_SOCK_OPT 	4
#define TCP_SET_FAST_ENABLED__id 5
#define TCP_SET_FAST_ENABLED__str "fast_enabled"
#define TCP_SET_FAST_ENABLED__type META_TYPE_INT32
#define TCP_SET_FAST_DUPLICATES__id 6
#define TCP_SET_FAST_DUPLICATES__str "fast_duplicates"
#define TCP_SET_FAST_DUPLICATES__type META_TYPE_INT32
#define TCP_SET_FAST_RETRANSMITS__id 7
#define TCP_SET_FAST_RETRANSMITS__str "fast_retransmits"
#define TCP_SET_FAST_RETRANSMITS__type META_TYPE_INT32
#define TCP_SET_MSS__id 8
#define TCP_SET_MSS__str "mss"
#define TCP_SET_MSS__type META_TYPE_INT32
#define TCP_SET_PARAM_STATUS 9

#define TCP_EXEC_CONNECT 0
#define TCP_EXEC_LISTEN 1
#define TCP_EXEC_ACCEPT 2
#define TCP_EXEC_SEND 3
#define TCP_EXEC_RECV 4
#define TCP_EXEC_CLOSE 5
#define TCP_EXEC_CLOSE_STUB 6
#define TCP_EXEC_OPT 7
#define TCP_EXEC_POLL 8

#define ERROR_ICMP_TTL 0
#define ERROR_ICMP_DEST_UNREACH 1

#endif /* TCP_INTERNAL_H_ */
