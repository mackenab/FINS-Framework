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
//#include <sys/time.h>
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

#define DEFAULT_MAX_QUEUE 65535

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
	uint8_t *data; //Actual TCP segment data
	int datalen; //Length of the data. This, of course, is not in the original TCP header.
//We don't need an optionslen variable because we can figure it out from the 'data offset' part of the flags.
};

//structure for a record of a tcp_queue
struct tcp_node {
	struct tcp_node* next; //Next item in the list

	uint32_t seq_num;
	uint32_t seq_end;
	struct finsFrame* ffsegment; //Actual data
};

//Structure for the ordered queue of outgoing/incoming packets for a TCP connection
struct tcp_queue {
	struct tcp_node *front;
	struct tcp_node *end;
	uint32_t max;
	uint32_t len;
	sem_t sem;
};

struct tcp_queue* create_queue(uint32_t max);
int insert_FF(struct tcp_queue *queue, struct finsFrame* ffsegment,
		uint32_t seq_num, uint32_t len);
struct finsFrame* remove_front(struct tcp_queue *queue);
int is_empty(struct tcp_queue *queue);
int has_space(struct tcp_queue *queue, uint32_t len);

//Structure for TCP connections that we have open at the moment
struct tcp_connection {
	struct tcp_connection * next; //Next item in the list of TCP connections (since we'll probably want more than one open at once)
	int state;

	uint32_t host_addr; //IP address of this machine  //should it be unsigned long?
	uint16_t host_port; //Port on this machine that this connection is taking up
	uint32_t rem_addr; //IP address of remote machine
	uint16_t rem_port; //Port on remote machine

	struct tcp_queue *write_queue; //buffer for raw FDF to be transfered
	struct tcp_queue *send_queue; //buffer for sent UDP FDF that are unACKed
	struct tcp_queue *recv_queue; //buffer for recv UDP FDF that are unACKed
	struct tcp_queue *read_queue; //buffer for raw FDF that have been transfered

	pthread_t write_thread;
	pthread_t send_thread;
	pthread_t recv_thread;
	pthread_t read_thread;

	sem_t wait_sem;
	sem_t send_wait_sem;
	sem_t recv_wait_sem;

	unsigned int MSS;
	unsigned short recvWindow;
	unsigned short window;
	unsigned int congState;
	double congWindow;
	unsigned int threshhold;

	unsigned int hostSeq; //seq num rand gen by client expected by server
	unsigned int remoteSeq; //seq num rand gen by server expected by client

	unsigned int firstRTT;
	unsigned int seqEndRTT;
	struct timeval stampRTT;
	double estRTT;
	double devRTT;
	double timeout;
//timer_t to_timer;
};

struct tcp_connection* create_tcp_connection(uint32_t host_addr,
		uint16_t host_port, uint32_t rem_addr, uint16_t rem_port);
struct tcp_connection* find_tcp_connection(uint32_t host_addr,
		uint16_t host_port, uint32_t rem_addr, uint16_t rem_port);

//General functions for dealing with the incoming and outgoing frames
void tcp_init();
void tcp_get_FF();
void tcp_out(struct finsFrame *ff);
void tcp_in(struct finsFrame *ff);
void tcp_to_switch(struct finsFrame * ff); //Send a finsFrame to the switch's queue

struct finsFrame* tcp_to_fins(struct tcp_segment* tcp);
struct tcp_segment* fins_to_tcp(struct finsFrame* ff);
int tcp_getheadersize(uint16_t flags); //Get the size of the TCP header in bytes from the flags field
//int		tcp_get_datalen(uint16_t flags);					//Extract the datalen for a tcp_segment from the flags field

//More specific, internal functions for dealing with the data and all that
uint16_t TCP_checksum(struct finsFrame * ff); //Calculate the checksum of this TCP segment
void tcp_srand(); //Seed the random number generator
int tcp_rand(); //Get a random number
//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application

#endif /* TCP_H_ */
