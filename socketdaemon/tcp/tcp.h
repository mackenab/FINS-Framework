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
#define HEADERSIZE(x)	((x & FLAG_DATAOFFSET) * 4)	//For easily grabbing the size of the header in bytes from the flags field
#define MAX_OPTIONS_LEN			320						//Maximum number of bits in the options field of the TCP header is 320 bits, says RFC
#define MIN_DATA_OFFSET_LEN		5						//As per RFC spec, if the TCP header has no options set, the length will be 5 32-bit segments
#define MIN_TCP_HEADER_LEN		MIN_DATA_OFFSET_LEN * 4	//Therefore, the minimum TCP header length is 4*5=20 bytes
#define MAX_TCP_HEADER_LEN		MAX_OPTIONS_LEN + MIN_DATA_OFFSET_LEN	//Maximum TCP header size, as defined by the maximum options size
//typedef unsigned long IP4addr; /*  internet address			*/
#define TCP_PROTOCOL 6
#define IP_HEADERSIZE 12

//structure for a record of a tcp_queue
struct tcp_node {
	struct tcp_node *next; //Next item in the list
	uint8_t *data; //Actual data
	uint32_t len;
	uint32_t seq_num;
	uint32_t seq_end;
};

struct tcp_node *node_create(uint8_t *data, uint32_t len, uint32_t seq_num,
		uint32_t seq_end);
int node_compare(struct tcp_node *node, struct tcp_node *cmp,
		uint32_t win_seq_num, uint32_t win_seq_end);

//Structure for the ordered queue of outgoing/incoming packets for a TCP connection
struct tcp_queue {
	struct tcp_node *front;
	struct tcp_node *end;
	uint32_t max;
	uint32_t len;
	sem_t sem;
};

struct tcp_queue *queue_create(uint32_t max);
void queue_append(struct tcp_queue *queue, struct tcp_node *node);
void queue_prepend(struct tcp_queue *queue, struct tcp_node *node);
void queue_add(struct tcp_queue *queue, struct tcp_node *node,
		struct tcp_node *prev);
int queue_insert(struct tcp_queue *queue, struct tcp_node *node,
		uint32_t win_seq_num, uint32_t win_seq_end);
struct tcp_node *queue_find(struct tcp_queue *queue, uint32_t seq_num);
struct tcp_node *queue_remove_front(struct tcp_queue *queue);
int queue_is_empty(struct tcp_queue *queue);
int queue_has_space(struct tcp_queue *queue, uint32_t len);
//TODO might implement queue_find_seqnum/seqend, findNext, hasEnd if used more than once

enum CONN_STATE /* Defines an enumeration type    */
{
	CLOSED,
	LISTEN,
	SYN_SENT,
	SYN_RECV,
	ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
	CLOSING,
	TIME_WAIT,
	CLOSE_WAIT,
	LAST_ACK
};

enum CONG_STATE /* Defines an enumeration type    */
{
	INITIAL, SLOWSTART, AVOIDANCE, RECOVERY
};

//Structure for TCP connections that we have open at the moment
struct tcp_connection {
	struct tcp_connection *next; //Next item in the list of TCP connections (since we'll probably want more than one open at once)
	sem_t conn_sem; //for next, state, write_threads
	enum CONN_STATE conn_state;
	//some type of option state

	uint32_t host_addr; //IP address of this machine  //should it be unsigned long?
	uint16_t host_port; //Port on this machine that this connection is taking up
	uint32_t rem_addr; //IP address of remote machine
	uint16_t rem_port; //Port on remote machine

	struct tcp_queue *write_queue; //buffer for raw data to be transfered
	struct tcp_queue *send_queue; //buffer for sent tcp_seg that are unACKed
	struct tcp_queue *recv_queue; //buffer for recv tcp_seg that are unACKed
	struct tcp_queue *read_queue; //buffer for raw data that have been transfered //TODO push straight to daemon?

	pthread_t main_thread;
	uint8_t main_wait_flag;
	sem_t main_wait_sem;

	int write_threads; //number of write threads called (i.e. # processes calling write on same TCP socket)
	sem_t write_sem; //so that only 1 write thread can add to write_queue at a time
	sem_t write_wait_sem;

	int recv_threads;
	//sem_t read_sem; //TODO: prob don't need

	uint8_t running_flag;
	uint8_t first_flag;

	uint32_t duplicate;
	uint8_t fast_flag;

	int to_gbn_fd; //GBN timeout occurred
	pthread_t to_gbn_thread;
	uint8_t to_gbn_flag; //1 GBN timeout occurred
	uint8_t gbn_flag; //1 performing GBN

	int to_delayed_fd; //delayed ACK TO occurred
	pthread_t to_delayed_thread;
	uint8_t to_delayed_flag; //1 delayed ack timeout occured
	uint8_t delayed_flag; //0 no delayed ack, 1 delayed ack

	enum CONG_STATE cong_state;
	double cong_window;
	double threshhold;

	uint8_t rtt_flag;
	uint32_t rtt_first;
	uint32_t rtt_seq_end;
	struct timeval rtt_stamp;
	double rtt_est;
	double rtt_dev;

	double timeout;

	//-----values agreed upon during setup
	uint16_t MSS; //max segment size

	uint32_t host_seq_num; //seq of host sendbase, tied with send_queue
	uint32_t host_seq_end; //seq of host last sent
	uint16_t host_max_window; //max bytes in host recv buffer, tied with rem_seq_num/recv_queue
	uint16_t host_window; //avail bytes in host recv buffer

	uint32_t rem_seq_num; //seq of rem sendbase, tied with recv_queue
	uint32_t rem_seq_end; //seq of rem last sent
	uint16_t rem_max_window; //max bytes in rem recv buffer, tied with host_seq_num/send_queue
	uint16_t rem_window; //avail bytes in rem recv buffer
//-----
};

//TODO raise any of these?
#define DEFAULT_MAX_QUEUE 65535
#define MAX_RECV_THREADS 10
#define MAX_WRITE_THREADS 10
#define MAX_CONNECTIONS 512
#define MIN_GBN_TIMEOUT 1000
#define MAX_GBN_TIMEOUT 64000
#define DEFAULT_GBN_TIMEOUT 50
#define DELAYED_TIMEOUT 200
#define MAX_SEQ_NUM 4294967295.0
#define DEFAULT_MAX_WINDOW 65535

//connection states //TODO: figure out
#define CONN_SETUP 0
#define CONN_CONNECTED 1

sem_t conn_list_sem;
struct tcp_connection *conn_create(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port);
void conn_append(struct tcp_connection *conn);
struct tcp_connection *conn_find(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port);
void conn_remove(struct tcp_connection *conn);
int conn_is_empty(void);
int conn_has_space(uint32_t len);

void startTimer(int fd, double millis);
void stopTimer(int fd);

//Structure for TCP segments (Straight from the RFC, just in struct form)
struct tcp_segment {
	uint16_t src_port; //Source port
	uint16_t dst_port; //Destination port
	uint32_t seq_num; //Sequence number
	uint32_t ack_num; //Acknowledgment number
	uint16_t flags; //Flags and data offset
	uint16_t win_size; //Window size
	uint16_t checksum; //TCP checksum
	uint16_t urg_pointer; //Urgent pointer (If URG flag set)
	uint8_t *options; //Options for the TCP segment (If Data Offset > 5) //TODO iron out full options mechanism
	int opt_len; //length of the options in bytes
	uint8_t *data; //Actual TCP segment data
	int data_len; //Length of the data. This, of course, is not in the original TCP header.
//We don't need an optionslen variable because we can figure it out from the 'data offset' part of the flags.
};

void conn_send_ack(struct tcp_connection *conn);
void conn_update_seg(struct tcp_connection *conn, struct tcp_segment *tcp_seg);
void conn_send_seg(struct tcp_connection *conn, struct tcp_segment *tcp_seg);

struct finsFrame *tcp_to_fdf(struct tcp_segment *tcp);
struct tcp_segment *fdf_to_tcp(struct finsFrame *ff);
int tcp_in_window(uint32_t seq_num, uint32_t seq_end, uint32_t win_seq_num,
		uint32_t win_seq_end);

struct tcp_thread_data {
	struct tcp_connection *conn;
	struct tcp_segment *tcp_seg;
};

struct tcp_to_thread_data {
	uint8_t *running;
	uint32_t *fd;
	uint8_t *flag;
	uint8_t *waiting;
	sem_t *sem;
};

//General functions for dealing with the incoming and outgoing frames
void tcp_init();
void tcp_get_FF();
void tcp_to_switch(struct finsFrame *ff); //Send a finsFrame to the switch's queue

//More specific, internal functions for dealing with the data and all that
//uint16_t TCP_checksum(struct finsFrame *ff); //Calculate the checksum of this TCP segment
uint16_t tcp_checksum(uint32_t src_addr, uint32_t dst_addr,
		struct tcp_segment *tcp_seg);
void tcp_srand(); //Seed the random number generator
int tcp_rand(); //Get a random number

int tcp_getheadersize(uint16_t flags); //Get the size of the TCP header in bytes from the flags field
//int		tcp_get_datalen(uint16_t flags);					//Extract the datalen for a tcp_segment from the flags field

void tcp_out(struct finsFrame *ff);
void tcp_in(struct finsFrame *ff);

//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application

#endif /* TCP_H_ */
