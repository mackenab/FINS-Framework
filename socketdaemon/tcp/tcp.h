/*
 * tcp.h
 *
 *  Created on: Mar 12, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef TCP_H_
#define TCP_H_

#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <stdint.h>
#include <sys/time.h> //TODO might not need
#include <sys/timerfd.h>
#include <semaphore.h>

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
	uint8_t *options; //Options for the TCP segment (If Data Offset > 5)
	int optlen; //length of the options in bytes
	uint8_t *data; //Actual TCP segment data
	int datalen; //Length of the data. This, of course, is not in the original TCP header.
//We don't need an optionslen variable because we can figure it out from the 'data offset' part of the flags.
};

//structure for a record of a tcp_queue
struct tcp_node {
	struct tcp_node* next; //Next item in the list
	uint8_t *data; //Actual data
	uint32_t len;
	uint32_t seq_num;
	uint32_t seq_end;
};

//Structure for the ordered queue of outgoing/incoming packets for a TCP connection
struct tcp_queue {
	struct tcp_node *front;
	struct tcp_node *end;
	uint32_t max;
	uint32_t len;
	sem_t sem;
};

struct tcp_queue* queue_create(uint32_t max);
void queue_append(struct tcp_queue *queue, uint8_t* data, uint32_t len,
		uint32_t seq_num, uint32_t seq_end);
int queue_insert(struct tcp_queue *queue, uint8_t* data, uint32_t len,
		uint32_t seq_num, uint32_t seq_end);
void queue_remove_front(struct tcp_queue *queue);
int queue_is_empty(struct tcp_queue *queue);
int queue_has_space(struct tcp_queue *queue, uint32_t len);
//TODO might implement queue_find_seqnum/seqend, findNext, hasEnd if used more than once

//Structure for TCP connections that we have open at the moment
struct tcp_connection {
	struct tcp_connection * next; //Next item in the list of TCP connections (since we'll probably want more than one open at once)
	int state;
	sem_t conn_sem; //for next, state, write_threads
	//some type of option state

	int write_threads; //number of write threads called (i.e. # processes calling write on same TCP socket)
	int recv_threads;

	sem_t write_sem; //so that only 1 write thread can add to write_queue at a time
	//sem_t read_sem; //TODO: prob don't need

	uint32_t host_addr; //IP address of this machine  //should it be unsigned long?
	uint16_t host_port; //Port on this machine that this connection is taking up
	uint32_t rem_addr; //IP address of remote machine
	uint16_t rem_port; //Port on remote machine

	struct tcp_queue *write_queue; //buffer for raw FDF to be transfered
	struct tcp_queue *send_queue; //buffer for sent UDP FDF that are unACKed
	struct tcp_queue *recv_queue; //buffer for recv UDP FDF that are unACKed
	struct tcp_queue *read_queue; //buffer for raw FDF that have been transfered //TODO might not need

	pthread_t main_thread;
	uint8_t main_wait_flag;
	sem_t main_wait_sem;

	uint8_t running_flag;
	uint8_t first_flag;
	uint8_t delayed_flag;
	uint8_t fast_flag;
	uint8_t gbn_flag;

	int to_gbn_fd; //GBN timeout occurred
	pthread_t to_gbn_thread;
	uint8_t to_gbn_flag;

	int to_delayed_fd; //delayed ACK TO occurred
	pthread_t to_delayed_thread;
	uint8_t to_delayed_flag;

	//values agreed upon during setup
	uint16_t MSS; //max segment size
	uint32_t host_seq_num; //seq num rand gen by client expected by server
	uint16_t host_max_window; //
	uint16_t host_window;
	uint32_t rem_seq_num; //seq num rand gen by server expected by client
	uint16_t rem_max_window;
	uint16_t rem_window;

	unsigned int congState;
	double congWindow;
	unsigned int threshhold;

	unsigned int firstRTT;
	unsigned int seqEndRTT;
	struct timeval stampRTT;
	double estRTT;
	double devRTT;
	double timeout;
};

//TODO raise any of these?
#define DEFAULT_MAX_QUEUE 65535
#define MAX_RECV_THREADS 1
#define MAX_WRITE_THREADS 1
#define MAX_CONNECTIONS 512

//connection states //TODO: figure out
#define CONN_SETUP 0
#define CONN_CONNECTED 1

sem_t conn_list_sem;
struct tcp_connection* conn_create(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port);
void conn_append(struct tcp_connection *conn);
struct tcp_connection* conn_find(uint32_t host_addr, uint16_t host_port,
		uint32_t rem_addr, uint16_t rem_port);
void conn_remove(struct tcp_connection *conn);
int conn_is_empty(void);
int conn_has_space(uint32_t len);
void startTimer(int fd, double millis);
void stopTimer(int fd);

struct tcp_thread_data {
	struct tcp_connection* conn;
	struct tcp_segment* tcp_seg;
};

//General functions for dealing with the incoming and outgoing frames
void tcp_init();
void tcp_get_FF();
void tcp_to_switch(struct finsFrame * ff); //Send a finsFrame to the switch's queue

//More specific, internal functions for dealing with the data and all that
uint16_t TCP_checksum(struct finsFrame * ff); //Calculate the checksum of this TCP segment
void tcp_srand(); //Seed the random number generator
int tcp_rand(); //Get a random number

struct finsFrame* tcp_to_fins(struct tcp_segment* tcp);
struct tcp_segment* fins_to_tcp(struct finsFrame* ff);
int tcp_getheadersize(uint16_t flags); //Get the size of the TCP header in bytes from the flags field
//int		tcp_get_datalen(uint16_t flags);					//Extract the datalen for a tcp_segment from the flags field

void tcp_out(struct finsFrame *ff);
void tcp_in(struct finsFrame *ff);

//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application

#endif /* TCP_H_ */
