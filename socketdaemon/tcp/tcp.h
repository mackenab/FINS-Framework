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
struct tcp_segment
{
	uint16_t	src_port;		//Source port
	uint16_t	dst_port;		//Destination port
	uint32_t	seq_num;		//Sequence number
	uint32_t	ack_num;		//Acknowledgment number
	uint16_t	flags;			//Flags and data offset
	uint16_t	win_size;		//Window size
	uint16_t	checksum;		//TCP checksum
	uint16_t	urg_pointer;	//Urgent pointer (If URG flag set)
	uint8_t		*options;		//Options for the TCP segment (If Data Offset > 5)
	uint8_t		*data;			//Actual TCP segment data
	int			datalen;		//Length of the data. This, of course, is not in the original TCP header.
	//We don't need an optionslen variable because we can figure it out from the 'data offset' part of the flags.
};

//Structure for the queue of outgoing/incoming packets for a TCP connection
struct tcp_queue
{
	uint16_t			seq_num;
	struct finsFrame*	ffsegment;		//Actual data
	struct tcp_queue*	next;			//Next item in the list
};

//Structure for TCP connections that we have open at the moment
struct tcp_connection
{
	uint16_t	thisport;		//Port on this machine that this connection is taking up
	uint16_t	destport;		//TODO: Do I really need this? Port on destination machine
	uint32_t	cur_seq_num;	//Sequence number we're currently looking for
	unsigned long		dest_addr;		//IP address we're currently connected to
	struct tcp_connection * next;	//Next item in the list of TCP connections (since we'll probably want more than one open at once)
};

//General functions for dealing with the incoming and outgoing frames
void 	tcp_out(struct finsFrame *ff);
void 	tcp_in(struct finsFrame *ff);
void 	tcp_get_FF();
void 	tcp_init();
struct 	finsFrame* tcp_to_fins(struct tcp_segment* tcp);
struct 	tcp_segment* fins_to_tcp(struct finsFrame* ff);
//int		tcp_getheadersize(uint16_t flags);					//Get the size of the TCP header in bytes from the flags field
//int		tcp_get_datalen(uint16_t flags);					//Extract the datalen for a tcp_segment from the flags field


//More specific, internal functions for dealing with the data and all that
uint16_t TCP_checksum(struct finsFrame * ff);	//Calculate the checksum of this TCP segment
void tcp_srand();	//Seed the random number generator
int  tcp_rand();	//Get a random number
//void tcp_send_out();	//Send the data out that's currently in the queue (outgoing frames)
//void tcp_send_in();		//Send the incoming frames in to the application
void tcp_to_switch(struct finsFrame * ff);	//Send a finsFrame to the switch's queue





#endif /* TCP_H_ */
