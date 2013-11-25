/*
 * udp_internal.h
 *
 *  Created on: Apr 27, 2013
 *      Author: Jonathan Reed
 */

#ifndef UDP_INTERNAL_H_
#define UDP_INTERNAL_H_

#include "udp.h"

#include <netinet/in.h>
#include <pthread.h>
#include <sys/time.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <metadata.h>
#include <finsqueue.h>

//ADDED mrd015 !!!!!
#ifdef BUILD_FOR_ANDROID
#include <sys/endian.h>
#endif

#define IP_MAXLEN 65535
#define IP_MINLEN 5
#define IP_HEADER_LEN 12		/* IP header length in bytes, 96 bits */
#define U_HEADER_LEN 8 										/* UDP header length in bytes, 64 bits. */
#define U_MAXLEN  4096  	/* Maximum amount of data in the UDP packet */

#define UDP_PROTOCOL 	17									/* udp protocol number used in the pseudoheader	*/
#define IGNORE_CHEKSUM  0									/* the checksum value when it is not being used */

#define UDP_MSL_TO_DEFAULT 512000

//TODO change back to 2^16?
#define UDP_SENT_LIST_MAX (2*65536)

struct udp_sent {
	struct finsFrame *ff;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	struct timeval stamp;
};
struct udp_sent *udp_sent_create(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
int udp_sent_host_test(struct udp_sent *sent, uint32_t *host_ip, uint16_t *host_port);
int udp_sent_match_test(struct udp_sent *sent, uint8_t *data, uint32_t *data_len);
void udp_sent_free(struct udp_sent *sent);

//void udp_sent_list_gc(struct udp_sent_list *sent_list, double timeout);

struct udp_header_frag { //TODO remove? is same as udp packet
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t len;
	uint16_t checksum;
	uint8_t data[];
};

struct udp_header {
	uint16_t u_src; /*UPD source port number */
	uint16_t u_dst; /*UDP destination port */
	uint16_t u_len; /*Length of UDP packet */
	uint16_t u_cksum; /* UDP checksum all 1's means no checksum*/
};

struct udp_packet {
	uint16_t u_src; /*UPD source port number */
	uint16_t u_dst; /*UDP destination port */
	uint16_t u_len; /*Length of UDP packet */
	uint16_t u_cksum; /* UDP checksum all 1's means no checksum*/
	uint8_t u_data[]; /*Data in the packet*/
};

struct udp_metadata_parsed {
	uint32_t u_IPsrc; /* IP source from metadata */
	uint32_t u_IPdst; /* IP destination from metadata */
	uint16_t u_prcl; /* protocol number should  be 17 from metadata */
	uint16_t u_pslen; /* length of the UDP packet from the pseudoheader */
	uint16_t u_srcPort; /* The Source port address*/
	uint16_t u_destPort; /* destination port address */

};

struct udp_statistics {
	uint16_t badChecksum; /* total number of datagrams that have a bad checksum*/
	uint16_t noChecksum; /* total number of datagrams with no checksum */
	uint16_t mismatchingLengths; /* total number of datagrams with mismatching datagram lengths from the header and pseudoheader */
	uint16_t wrongProtocol; /* total number of datagrams that have the wrong Protocol value in the pseudoheader */
	uint32_t totalBadDatagrams; /* total number of datagrams that were thrown away */
	uint32_t totalRecieved; /* total number of incoming UDP datagrams */
	uint32_t totalSent; /* total number of outgoing UDP datagrams */
};

/*UDP constant port value */

#define ULPORT 			2050 					/*initial UDP local port number*/

/* assigned UDP port numbers*/

#define UP_ECHO			7						/* echo server */
#define UP_DISCARD		9						/*discards packet*/
#define UP_USERS		11						/* users server */
#define UP_DAYTIME		13						/*day and time server */
#define UP_QOTD			17						/*quote of the day*/
#define UP_CHARGEN		19						/*Character generator */
#define UP_TIME			37						/* time server */
#define UP_WHOIS		43						/* Who is server (user information) */
#define UP_DNAME		53						/*domain name server */
#define UP_TFTP			69						/* trivial file transfer protocol server */
#define UP_RWHO			513						/* remote who server (ruptime) */
#define UP_RIP			520						/* route information exchange (RIP) */

//unsigned short UDP_checksum(struct udp_packet *pcket, struct udp_metadata_parsed *meta);
uint16_t UDP_checksum(struct udp_packet *pcket, uint32_t src_ip, uint32_t dst_ip);

int UDP_InputQueue_Read_local(struct finsFrame *pff_local);

//static inline unsigned short from64to16(unsigned long x);

uint16_t UDP_checkSeparate(uint32_t src, uint32_t dest, uint16_t len, uint16_t protocol, uint16_t wsum);

#define UDP_LIB "udp"
#define UDP_MAX_FLOWS 	3
#define UDP_FLOW_IPV4 	0
#define UDP_FLOW_ICMP 	1
#define UDP_FLOW_DAEMON	2

struct udp_data {
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[UDP_MAX_FLOWS];

	pthread_t switch_to_udp_thread;

	struct udp_statistics stats;
	struct linked_list *sent_packet_list; //linked list of udp_sent structs, representing UDP datagrams sent
};

int udp_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int udp_run(struct fins_module *module, pthread_attr_t *attr);
int udp_pause(struct fins_module *module);
int udp_unpause(struct fins_module *module);
int udp_shutdown(struct fins_module *module);
int udp_release(struct fins_module *module);

int udp_to_switch(struct fins_module *module, struct finsFrame *ff);
void udp_get_ff(struct fins_module *module);
void udp_fcf(struct fins_module *module, struct finsFrame *ff);
void udp_read_param(struct fins_module *module, struct finsFrame *ff);
void udp_set_param(struct fins_module *module, struct finsFrame *ff);

void udp_exec(struct fins_module *module, struct finsFrame *ff);
void udp_exec_clear_sent(struct fins_module *module, struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);

//void udp_exec_reply(struct fins_module *module, struct finsFrame *ff);
void udp_error(struct fins_module *module, struct finsFrame *ff);

void udp_in_fdf(struct fins_module *module, struct finsFrame *ff);
void udp_out_fdf(struct fins_module *module, struct finsFrame *ff);

void udp_interrupt(struct fins_module *module);

#define UDP_EXEC_CLEAR_SENT 0

#define UDP_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define UDP_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define UDP_SET_PARAM_DUAL 	MOD_SET_PARAM_DUAL

#define UDP_ERROR_TTL 0
#define UDP_ERROR_DEST_UNREACH 1
#define UDP_ERROR_GET_ADDR 2

#endif /* UDP_INTERNAL_H_ */
