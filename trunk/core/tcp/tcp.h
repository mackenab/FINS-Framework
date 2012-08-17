/*
 * @file tcp.h
 * @date Feb 22, 2012
 * @author Jonathan Reed
 */

#ifndef TCP_H_
#define TCP_H_

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <semaphore.h>
#include <math.h>
#include <time.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <queueModule.h>
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

#define TCP_PROTOCOL 		IPPROTO_TCP //6
#define IP_HEADER_WORDS 	3
#define IP_HEADER_BYTES 	(IP_HEADER_WORDS*4)

//#define MAX_OPTIONS_LEN			320						//Maximum number of bits in the options field of the TCP header is 320 bits, says RFC
//#define MIN_DATA_OFFSET			5						//As per RFC spec, if the TCP header has no options set, the length will be 5 32-bit segments
//#define MIN_TCP_HEADER_LEN		MIN_DATA_OFFSET * 4	//Therefore, the minimum TCP header length is 4*5=20 bytes
//#define MAX_TCP_HEADER_LEN		MAX_OPTIONS_LEN + MIN_TCP_HEADER_LEN	//Maximum TCP header size, as defined by the maximum options size
//typedef unsigned long IP4addr; /*  internet address			*/

//structure for a record of a tcp_queue
struct tcp_node {
	struct tcp_node *next; //Next item in the list
	uint8_t *data; //Actual data
	uint32_t len;
	uint32_t seq_num;
	uint32_t seq_end;
};

struct tcp_node *node_create(uint8_t *data, uint32_t len, uint32_t seq_num, uint32_t seq_end);
int node_compare(struct tcp_node *node, struct tcp_node *cmp, uint32_t win_seq_num, uint32_t win_seq_end);
void node_free(struct tcp_node *node);

//Structure for the ordered queue of outgoing/incoming packets for a TCP connection
struct tcp_queue {
	struct tcp_node *front;
	struct tcp_node *end;
	uint32_t max;
	uint32_t len;
	sem_t sem; //TODO remove, not used anymore
};

struct tcp_queue *queue_create(uint32_t max);
void queue_append(struct tcp_queue *queue, struct tcp_node *node);
void queue_prepend(struct tcp_queue *queue, struct tcp_node *node);
void queue_add(struct tcp_queue *queue, struct tcp_node *node, struct tcp_node *prev);
int queue_insert(struct tcp_queue *queue, struct tcp_node *node, uint32_t win_seq_num, uint32_t win_seq_end);
struct tcp_node *queue_find(struct tcp_queue *queue, uint32_t seq_num);
struct tcp_node *queue_remove_front(struct tcp_queue *queue);
int queue_is_empty(struct tcp_queue *queue);
int queue_has_space(struct tcp_queue *queue, uint32_t len);
void queue_free(struct tcp_queue *queue);

struct tcp_connection_stub {
	struct tcp_connection_stub *next;
	sem_t sem;

	uint32_t host_ip; //IP address of this machine  //should it be unsigned long?
	uint16_t host_port; //Port on this machine that this connection is taking up

	struct tcp_queue *syn_queue; //buffer for recv tcp_seg SYN requests

	uint32_t threads;

	//int syn_threads;

	//int accept_threads;
	sem_t accept_wait_sem;

	uint8_t running_flag;
//uint32_t backlog; //TODO ?
};

sem_t conn_stub_list_sem;
struct tcp_connection_stub *conn_stub_create(uint32_t host_ip, uint16_t host_port, uint32_t backlog);
int conn_stub_insert(struct tcp_connection_stub *conn_stub);
struct tcp_connection_stub *conn_stub_find(uint32_t host_ip, uint16_t host_port);
void conn_stub_remove(struct tcp_connection_stub *conn_stub);
int conn_stub_is_empty(void);
int conn_stub_has_space(uint32_t len);
//int conn_stub_send_jinni(struct tcp_connection_stub *conn_stub, uint32_t exec_call, uint32_t ret_val);
int conn_stub_send_daemon(struct tcp_connection_stub *conn_stub, uint32_t exec_call, uint32_t ret_val, uint32_t ret_msg);
void conn_stub_shutdown(struct tcp_connection_stub *conn_stub);
void conn_stub_free(struct tcp_connection_stub *conn_stub);
//int conn_stub_add(uint32_t src_ip, uint16_t src_port);

typedef enum {
	TCP_CLOSED = 0,
	TCP_SYN_SENT,
	TCP_LISTEN,
	TCP_SYN_RECV,
	TCP_ESTABLISHED,
	TCP_FIN_WAIT_1,
	TCP_FIN_WAIT_2,
	TCP_CLOSING,
	TCP_TIME_WAIT,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK
} tcp_state;

typedef enum {
	RENO_SLOWSTART = 0, RENO_AVOIDANCE, RENO_RECOVERY
} reno_state;

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

//Structure for TCP connections that we have open at the moment
struct tcp_connection {
	struct tcp_connection *next; //Next item in the list of TCP connections //TODO remove when change conn_list to circular array of ptrs
	sem_t sem; //for next, state, write_threads
	uint8_t running_flag; //signifies if it is running, 0 when shutting down
	uint32_t threads; //Number of threads accessing this obj
	tcp_state state;

	//some type of options state

	uint32_t host_ip; //IP address of this machine  //should it be unsigned long?
	uint16_t host_port; //Port on this machine that this connection is taking up
	uint32_t rem_ip; //IP address of remote machine
	uint16_t rem_port; //Port on remote machine

	struct tcp_queue *write_queue; //buffer for raw data to be transfered
	struct tcp_queue *send_queue; //buffer for sent tcp_seg that are unACKed
	struct tcp_queue *recv_queue; //buffer for recv tcp_seg that are unACKed
	//struct tcp_queue *read_queue; //buffer for raw data that have been transfered //TODO push straight to daemon?

	pthread_t main_thread;
	uint8_t main_wait_flag;
	sem_t main_wait_sem;

	//int write_threads; //number of write threads called (i.e. # processes calling write on same TCP socket)
	sem_t write_sem; //so that only 1 write thread can add to write_queue at a time
	sem_t write_wait_sem;
	int index;

	//int recv_threads;
	//sem_t read_sem; //TODO: prob don't need
	//int connect_threads;

	uint8_t first_flag;
	uint32_t duplicate;
	uint8_t fast_flag;

	int to_msl_fd; //MSL timeout occurred
	pthread_t to_msl_thread;
	uint8_t to_msl_flag; //MSL timeout occurred
	//uint8_t msl_flag; //MSL performing GBN

	int to_gbn_fd; //GBN timeout occurred
	pthread_t to_gbn_thread;
	uint8_t to_gbn_flag; //1 GBN timeout occurred
	uint8_t gbn_flag; //1 performing GBN
	struct tcp_node *gbn_node;

	int to_delayed_fd; //delayed ACK TO occurred
	pthread_t to_delayed_thread;
	uint8_t to_delayed_flag; //1 delayed ack timeout occured
	uint8_t delayed_flag; //0 no delayed ack, 1 delayed ack
	uint16_t delayed_ack_flags;

	//host:send_win == rem:recv_win, host:recv_win == rem:send_win

	uint8_t fin_sent;
	uint8_t fin_sep; //TODO replace with fin_seq
	uint32_t fin_ack;

	uint32_t issn; //initial send seq num
	uint32_t fssn; //final send seq num, seq of FIN
	//uint32_t fsse; //final send seq end, so fsse == final ACK
	uint32_t irsn; //initial recv seq num

	uint32_t send_max_win; //max bytes in rem recv buffer, tied with host_seq_num/send_queue
	uint32_t send_win; //avail bytes in rem recv buffer
	uint32_t send_win_seq; //TODO shorten to send_last_seq & send_last_ack
	uint32_t send_win_ack;
	uint32_t send_seq_num; //seq of host sendbase, tied with send_queue, seq of unACKed data
	uint32_t send_seq_end; //1+seq of last sent byte by host, == send_next

	uint32_t recv_max_win; //max bytes in host recv buffer, tied with rem_seq_num/recv_queue
	uint32_t recv_win; //avail bytes in host recv buffer
	uint32_t recv_seq_num; //seq of rem sendbase, tied with recv_queue
	uint32_t recv_seq_end; //seq of last inside rem window

	uint16_t MSS; //max segment size
	reno_state cong_state;
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
//#define MAX_RECV_THREADS 10
//#define MAX_WRITE_THREADS 10
//#define MAX_SYN_THREADS 10
//#define MAX_ACCEPT_THREADS 10
//#define MAX_CONNECT_THREADS 10
//#define MAX_SYS_THREADS 10
#define TCP_THREADS_MAX 50
#define TCP_MAX_QUEUE_DEFAULT 65535
#define TCP_CONN_MAX 512
#define TCP_GBN_TO_MIN 1000
#define TCP_GBN_TO_MAX 64000
#define TCP_GBN_TO_DEFAULT 5000
#define TCP_DELAYED_TO_DEFAULT 200
#define TCP_MAX_SEQ_NUM 4294967295.0
#define TCP_MAX_WINDOW_DEFAULT 8191
#define TCP_MSS_DEFAULT 1460 //also said to be, 536
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
#define TCP_EOL 0
#define TCP_NOP 1
#define TCP_MSS 2
#define TCP_MSS_BYTES 4
#define TCP_WS 3
#define TCP_WS_BYTES 3
#define TCP_WS_DEFAULT 2 //default value?
#define TCP_WS_MAX 14
#define TCP_SACK_PERM 4
#define TCP_SACK_PERM_BYTES 2
#define TCP_SACK 5
#define TCP_SACK_BYTES(x) (8*x+2)
#define TCP_SACK_MIN_BYTES TCP_SACK_BYTES(0)
#define TCP_SACK_MAX_BYTES TCP_SACK_BYTES(3)
#define TCP_SACK_LEN(x) ((x-2)/8)
#define TCP_TS 8
#define TCP_TS_BYTES 10

sem_t conn_list_sem;
struct tcp_connection *conn_create(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
int conn_insert(struct tcp_connection *conn);
struct tcp_connection *conn_find(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void conn_remove(struct tcp_connection *conn);
int conn_is_empty(void);
int conn_has_space(uint32_t len);
//int conn_send_jinni(struct tcp_connection *conn, uint32_t exec_call, uint32_t ret_val);
int conn_send_daemon(struct tcp_connection *conn, uint32_t exec_call, uint32_t ret_val, uint32_t ret_msg);
void conn_shutdown(struct tcp_connection *conn);
void conn_stop(struct tcp_connection *conn); //TODO remove, move above tcp_main_thread, makes private
void conn_free(struct tcp_connection *conn);

void startTimer(int fd, double millis);
void stopTimer(int fd);

//Object for TCP segments all values are in host format
struct tcp_segment {
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

void tcp_srand(); //Seed the random number generator
int tcp_rand(); //Get a random number

struct finsFrame *seg_to_fdf(struct tcp_segment *tcp);
struct tcp_segment *fdf_to_seg(struct finsFrame *ff);

struct tcp_segment *seg_create(struct tcp_connection *conn);
void seg_add_data(struct tcp_segment *seg, struct tcp_connection *conn, int data_len);
void seg_update(struct tcp_segment *seg, struct tcp_connection *conn, uint16_t flags);
uint16_t seg_checksum(struct tcp_segment *seg);
int seg_send(struct tcp_segment *seg);
void seg_free(struct tcp_segment *seg);
void seg_delayed_ack(struct tcp_segment *seg, struct tcp_connection *conn);

int in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end);
int in_window_overlaps(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num, uint32_t win_seq_end);

struct tcp_thread_data {
	int id;
	struct tcp_connection *conn; //TODO change conn/conn_stub to union?
	struct tcp_connection_stub *conn_stub;
	struct tcp_segment *seg; //TODO change seg/raw to union?
	uint8_t *data_raw;
	uint32_t data_len;
	uint32_t flags;
	struct finsFrame *ff;
};

struct tcp_to_thread_data {
	int id;
	int fd;
	uint8_t *running;
	uint8_t *flag;
	uint8_t *waiting;
	sem_t *sem;
};

//General functions for dealing with the incoming and outgoing frames
void tcp_init(pthread_attr_t *fins_pthread_attr);
void tcp_shutdown();
void tcp_free();
void tcp_get_FF();
int tcp_to_switch(struct finsFrame *ff); //Send a finsFrame to the switch's queue
int tcp_fcf_to_daemon(uint32_t status, uint32_t exec_call, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port, uint32_t ret_val);
int tcp_fdf_to_daemon(u_char *dataLocal, int len, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);

#define EXEC_TCP_CONNECT 0
#define EXEC_TCP_LISTEN 1
#define EXEC_TCP_ACCEPT 2
#define EXEC_TCP_SEND 3
#define EXEC_TCP_RECV 4
#define EXEC_TCP_CLOSE 5
#define EXEC_TCP_CLOSE_STUB 6
#define EXEC_TCP_OPT 7
#define EXEC_TCP_POLL 8

#define SET_PARAM_TCP_HOST_WINDOW 0
#define SET_PARAM_TCP_SOCK_OPT 1

#define READ_PARAM_TCP_HOST_WINDOW 0
#define READ_PARAM_TCP_SOCK_OPT 1

void tcp_out_fdf(struct finsFrame *ff);
void tcp_in_fdf(struct finsFrame *ff);
void tcp_fcf(struct finsFrame *ff);
void tcp_exec(struct finsFrame *ff);

int metadata_read_conn(metadata *params, uint32_t *status, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port);
void metadata_write_conn(metadata *params, uint32_t *status, uint32_t *host_ip, uint16_t *host_port, uint32_t *rem_ip, uint16_t *rem_port);

void tcp_exec_connect(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void tcp_exec_listen(uint32_t host_ip, uint16_t host_port, uint32_t backlog);
void tcp_exec_accept(uint32_t host_ip, uint16_t host_port, uint32_t flags);
void tcp_exec_close(uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void tcp_exec_close_stub(uint32_t host_ip, uint16_t host_port);
void tcp_exec_poll(socket_state state, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);

void tcp_set_param(struct finsFrame *ff);
void tcp_read_param(struct finsFrame *ff);

int process_options(struct tcp_connection *conn, struct tcp_segment *seg);

/*
 void tcp_read_param_host_window(struct finsFrame *ff);
 void tcp_read_param_sock_opt(struct finsFrame *ff);

 void tcp_set_param_host_window(struct finsFrame *ff);
 void tcp_set_param_sock_opt(struct finsFrame *ff);
 */

//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application
#endif /* TCP_H_ */

