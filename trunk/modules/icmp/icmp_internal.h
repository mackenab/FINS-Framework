/*
 * icmp_internal.h
 *
 *  Created on: May 3, 2013
 *      Author: Jonathan Reed
 */

#ifndef ICMP_INTERNAL_H_
#define ICMP_INTERNAL_H_

#include <stdint.h>
#include <pthread.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>
#include "icmp_types.h"

#include <icmp.h>

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
#define	IPV4_MIN_HLEN	20		/* minimum IP header length (in bytes)					*/
#define	IPV4_HLEN(pip)			((pip->ip_verlen & 0xf)<<2)
#define ICMP_HEADER_SIZE	8
#define ICMP_PROTOCOL		1	//Protocol number for ICMP packets
#define TCP_PROTOCOL		6
#define UDP_PROTOCOL		17	//Protocol number for UDP packets
#define UNREACH_INCLUDE_DATA_SIZE	64	//How many bytes of data are included in destination unreachable and TTL exceeded ICMP messages.
// Defined here as a macro for simplicity. 512 bits seems reasonable in my opinion, but it can be tweaked.

#define ICMP_MSL_TO_DEFAULT 512000
#define ICMP_SENT_LIST_MAX (2*65536)

#define ERROR_ICMP_TTL 0
#define ERROR_ICMP_DEST_UNREACH 1

struct ipv4_packet {
	uint8_t ip_verlen; /* IP version & header length (in longs)*/
	uint8_t ip_dif; /* differentiated service			*/
	uint16_t ip_len; /* total packet length (in octets)	*/
	uint16_t ip_id; /* datagram id				*/
	uint16_t ip_fragoff; /* fragment offset (in 8-octet's)	*/
	uint8_t ip_ttl; /* time to live, in gateway hops	*/
	uint8_t ip_proto; /* IP protocol */
	uint16_t ip_cksum; /* header checksum 			*/
	uint32_t ip_src; /* IP address of source			*/
	uint32_t ip_dst; /* IP address of destination		*/
	uint8_t ip_data[1]; /* variable length data			*/
};

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

struct icmp_sent {
	struct finsFrame *ff;
	struct timeval stamp;
};
int icmp_sent_match_test(struct icmp_sent *sent, uint32_t *data_len, uint8_t *data);
int icmp_sent_find(struct icmp_sent *sent);
void icmp_sent_free(struct icmp_sent *sent);

//TODO convert to hardcoded sent_list, so no create/free
void icmp_sent_list_gc(struct linked_list *sent_list, double timeout);

#define ICMP_LIB "icmp"
#define ICMP_MAX_FLOWS 		3
#define ICMP_FLOW_IPV4		0
#define ICMP_FLOW_UDP 		1
#define ICMP_FLOW_DAEMON	2

struct icmp_data {
	struct linked_list *link_list;
	uint32_t flows_num;
	uint32_t flows[ICMP_MAX_FLOWS];

	pthread_t switch_to_icmp_thread;

	struct linked_list *sent_list;
};

int icmp_init(struct fins_module *module, uint32_t flows_num, uint32_t *flows, metadata_element *params, struct envi_record *envi);
int icmp_run(struct fins_module *module, pthread_attr_t *attr);
int icmp_pause(struct fins_module *module);
int icmp_unpause(struct fins_module *module);
int icmp_shutdown(struct fins_module *module);
int icmp_release(struct fins_module *module);

void icmp_get_ff(struct fins_module *module);
void icmp_fcf(struct fins_module *module, struct finsFrame *ff);
void icmp_read_param(struct fins_module *module, struct finsFrame *ff);
void icmp_set_param(struct fins_module *module, struct finsFrame *ff);
void icmp_exec(struct fins_module *module, struct finsFrame *ff);

void icmp_in_fdf(struct fins_module *module, struct finsFrame *ff); //Processes an ICMP message that just came in
void icmp_handle_error(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len, uint32_t param_id);
void icmp_ping_reply(struct fins_module *module, struct finsFrame* ff, struct icmp_packet *icmp_pkt, uint32_t data_len); //Create a ping reply from a ping request package
uint16_t icmp_checksum(uint8_t *pt, uint32_t len);

void icmp_out_fdf(struct fins_module *module, struct finsFrame *ff); //Processes an ICMP message that's headed out

//don't use 0
#define ICMP_GET_PARAM_FLOWS MOD_GET_PARAM_FLOWS
#define ICMP_GET_PARAM_LINKS MOD_GET_PARAM_LINKS
#define ICMP_GET_PARAM_DUAL MOD_GET_PARAM_DUAL

#define ICMP_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define ICMP_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define ICMP_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#endif /* ICMP_INTERNAL_H_ */
