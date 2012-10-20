/*
 * icmp.h
 *
 *  Created on: Mar 15, 2011
 *      Author: Abdallah Abdallah
 */

#ifndef ICMP_H_
#define ICMP_H_

#include <stdint.h>
#include <pthread.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsdebug.h>
#include <queueModule.h>
#include "icmp_types.h"

//typedef unsigned long IP4addr; /*  internet address			*/

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

//Define some common ICMP message types (Common values for the "Type" field of the ICMP header)
#define TYPE_ECHOREPLY		0	//Echo reply
#define TYPE_DESTUNREACH	3	//Destination unreachable
#define TYPE_SOURCEQUENCH	4	//Source quench
#define TYPE_REDIRECT		5	//Redirect message
#define TYPE_ECHOREQUEST	8	//Echo request
#define TYPE_ROUTERAD		9	//Router advertisement
#define TYPE_ROUTERSOLICIT	10	//Router solicitation
#define TYPE_TTLEXCEED		11	//Time Exceeded
#define TYPE_PARAMPROB		12	//Parameter problem
#define TYPE_TIMESTAMP		13	//Timestamp request
#define TYPE_TIMESTAMPREPLY	14	//Timestamp reply
#define TYPE_INFOREQUEST	15	//Information request
#define TYPE_INFOREPLY		16	//Information reply
#define TYPE_ADDMASKREQ		17	//Address mask request
#define TYPE_ADDMASKREPLY	18	//Address mask reply
//Define some common codes for the "Code" field of the ICMP header
//For echo requests and replies
#define CODE_ECHO				0
//For destination unreachable
#define CODE_NETUNREACH			0	//Destination network unreachable
#define CODE_HOSTUNREACH		1	//Destination host unreachable
#define CODE_PROTOUNREACH		2	//Destination protocol unreachable
#define CODE_PORTUNREACH		3	//Destination port unreachable
#define CODE_FRAGNEEDED			4	//Fragmentation required, and DF flag set
#define CODE_SRCROUTEFAIL		5	//Source route failed
#define CODE_DESTNETUNKOWN		6	//Destination network unknown
#define CODE_DESTHOSTUNKNOWN	7	//Destination host unknown
#define CODE_SRCHOSTISOLATED	8	//Source host isolated
#define CODE_NETADMINPROHIBIT	9	//Network administratively prohibited
#define CODE_HOSTADMINPROHIBIT	10	//Host administratively prohibited
#define CODE_NETTOSUNREACH		11	//Network unreachable for TOS
#define CODE_HOSTTOSUNREACH		12	//Host unreachable for TOS
#define CODE_PROHIBITED			13	//Communication administratively prohibited
//For Time Exceeded
#define CODE_TTLEXCEEDED		0
#define CODE_DEFRAGTIMEEXCEEDED	1

#define ICMP_FRAG_SIZE 8
#define TCP_FRAG_SIZE 8
#define UDP_FRAG_SIZE 8

//Generic use
#define ICMP_HEADER_SIZE	8
#define ICMP_PROTOCOL		1	//Protocol number for ICMP packets
#define TCP_PROTOCOL		6
#define UDP_PROTOCOL		17	//Protocol number for UDP packets
#define UNREACH_INCLUDE_DATA_SIZE	64	//How many bytes of data are included in destination unreachable and TTL exceeded ICMP messages.
// Defined here as a macro for simplicity. 512 bits seems reasonable in my opinion, but it can be tweaked.

#define ICMP_MSL_TO_DEFAULT 512000

#define ERROR_ICMP_TTL 0
#define ERROR_ICMP_DEST_UNREACH 1


struct icmp_packet {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t param_1;
	uint16_t param_2;
	uint8_t data[1];
};

struct tcp_header_frag {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint8_t data[1];
};

struct udp_header_frag {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t data[1];
};

struct icmp_sent {
	struct icmp_sent *next;

	uint32_t src_ip;
	uint32_t dst_ip;

	u_char *data;
	uint32_t data_len;

	struct timeval stamp;
};

struct icmp_sent *sent_create(uint32_t src_ip, uint32_t dst_ip, u_char *data, uint32_t data_len);
void sent_free(struct icmp_sent *sent);

struct icmp_sent_list {
	uint32_t max;
	uint32_t len;
	struct icmp_sent *front;
	struct icmp_sent *end;
};

#define ICMP_SENT_LIST_MAX 300

//TODO convert to hardcoded sent_list, so no create/free
struct icmp_sent_list *sent_list_create(uint32_t max);
void sent_list_append(struct icmp_sent_list *sent_list, struct icmp_sent *sent);
struct icmp_sent *sent_list_find(struct icmp_sent_list *sent_list, u_char *data, uint32_t data_len);
struct icmp_sent *sent_list_remove_front(struct icmp_sent_list *sent_list); //TODO remove?
void sent_list_remove(struct icmp_sent_list *sent_list, struct icmp_sent *sent);
int sent_list_is_empty(struct icmp_sent_list *sent_list);
int sent_list_has_space(struct icmp_sent_list *sent_list);
void sent_list_free(struct icmp_sent_list *sent_list);

void icmp_get_ff(void); //Gets a finsFrame from the queue and starts processing
void ICMP_send_FF(struct finsFrame *ff); //Put a finsFrame onto the queue to go out
int icmp_to_switch(struct finsFrame *ff);

void icmp_sent_gc(void);
void icmp_out(struct finsFrame *ff); //Processes an ICMP message that's headed out

void icmp_in(struct finsFrame *ff); //Processes an ICMP message that just came in
uint16_t icmp_checksum(uint8_t *pt, uint32_t len);
void icmp_ping_reply(struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len); //Create a ping reply from a ping request package
void icmp_create_unreach(struct finsFrame* ff); //Create a "destination unreachable" message from data we receive from the UDP //removed in vt_mark?

void icmp_fcf(struct finsFrame *ff);
void icmp_control_handler(struct finsFrame *ff); //Handle control frames sent from other modules, creating new messages as needed and sending them out.
void icmp_create_error(struct finsFrame *ff, uint8_t Type, uint8_t Code); //Create and send out an error from this type and code
void icmp_create_control_error(struct finsFrame* ff, uint8_t Type, uint8_t Code); //Create a control frame to TCP/UDP out of ICMP error that came in

void icmp_init(void);
void icmp_run(pthread_attr_t *fins_pthread_attr);
void icmp_shutdown(void);
void icmp_release(void);

#endif /* ICMP_H_ */
