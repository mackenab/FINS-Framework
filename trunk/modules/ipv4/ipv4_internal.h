/*
 * ipv4_internal.h
 *
 *  Created on: Apr 24, 2013
 *      Author: Jonathan Reed
 */

#ifndef IPV4_INTERNAL_H_
#define IPV4_INTERNAL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <net/if.h>

#include <finsdebug.h>
#include <finstypes.h>
#include <finstime.h>
#include <finsqueue.h>
#include <metadata.h>

#include "ipv4.h"

/* Internet Protocol (IP)  Constants and Datagram Format		*/

struct ip4_packet {
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

struct ip4_packet_header {
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
};

struct ip4_header {
	uint32_t source;
	uint32_t destination;
	uint8_t version;
	uint8_t header_length;
	uint8_t differentiated_service;
	uint16_t packet_length;
	uint16_t id;
	uint16_t flags;
	uint16_t fragmentation_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
};

struct ip4_settings {
	uint32_t ip;
	uint32_t mask;
	uint32_t gateway;
};

struct ipv4_statistics {
	/* Incomming direction */
	uint16_t badhlen; /* packet with invalid IP header length 				*/
	uint16_t badlen; /* packet with inconsistent IP header and data lengths 	*/
	uint16_t badoptions; /**< @todo packet with error in options - not yet implemented	*/
	uint16_t badsum; /* packet with bad checksum								*/
	uint16_t badver; /* packet with an IP version other than 4				*/
	uint16_t cantforward; /* packet received for an unreachable destination		*/
	uint16_t delivered; /* packets delivered to the "upper" layer				*/
	uint16_t forwarded; /**< @todo packets forwarded - not yet implemented		*/
	uint16_t fragdropped; /* fragments dropped, either out of space or duplicated */
	uint16_t fragments; /* fragments received									*/
	uint16_t fragerror; /* no more fragments and do not fragment flags set		*/
	uint16_t timedout; /* packets timed out during reassembly					*/
	uint16_t noproto; /* packets with an unknown protocol number				*/
	uint16_t reassembled; /* packets reassembled									*/
	uint16_t tooshort; /* packets with too small declared data length			*/
	uint16_t toosmall; /* packets too small to contain IPv4 packet				*/
	uint32_t receivedtotal; /* total number of received packets						*/
	uint32_t droppedtotal; /* total number of packets dropped						*/
	/* Outgoing direction */
	uint16_t cantfrag; /* packets discarded because of don't fragment bit - not yet implemented */
	uint16_t fragmented; /* packets successfully fragmented						*/
	uint16_t noroute; /* packets discarded because of no route to destination */
	uint16_t outdropped; /* output packets dropped								*/
	uint32_t outfragments; /* fragments created for output							*/

};

struct ip4_reass_list {
	struct ip4_reass_list *next_packet, *previous_packet;
	uint8_t ttl;
	struct ip4_header header;
	int first_hole_rel_pointer;
	void *buffer;
	uint16_t length;
	uint16_t hole_count;
};

struct ip4_reass_hole {
	uint16_t first;
	uint16_t last;
	uint16_t next_hole_rel_pointer;
	uint16_t prev_hole_rel_pointer;
};

struct ip4_fragment {
	uint16_t first;
	uint16_t last;
	uint16_t data_length;
	uint8_t more_fragments;
	void *data;
};

struct ip4_route_request {
	struct nlmsghdr msg;
	struct rtmsg rt;
	char buf[1024];
};

struct ip4_routing_table {
	uint32_t dst;
	uint32_t gw;
	uint32_t mask; //TODO change back to number?
	uint32_t metric;
	//unsigned int interface;
	uint32_t interface; //TODO change back to number? so looks up in interface list

	struct ip4_routing_table *next_entry;
};

struct ip4_next_hop_info {
	uint32_t address;
	//int interface;
	uint32_t interface;
};

/* Basic IPv4 definitions */
#define	IP4_ALEN		4		/* IP address length in bytes (octets)					*/
#define	IP4_VERSION		4		/* current version value								*/
#define	IP4_MIN_HLEN	20		/* minimum IP header length (in bytes)					*/
#define	IP4_INIT_TTL	255		/* Initial time-to-live value							*/
#define	IP4_MAXLEN		65535	/* Maximum IP datagram length (bytes)					*/
#define IP4_BUFFLEN		9000	/* Initial reassembly buffer size (bytes)				*/
#define IP4_REASS_TTL	60		/* Time (sec) to wait for fragments of packet to arrive	*/
#define IP4_PCK_LEN		1500	/* Length of IP packets to be constructed				*/
/* IPv4 masks*/
#define	IP4_MF			0x1		/* more fragments bit			*/
#define	IP4_DF			0x2		/* don't fragment bit			*/
#define	IP4_FRAGOFF		0x1fff	/* fragment offset mask			*/
#define	IP4_PREC		0xe0	/* precedence portion of TOS	*/

/* IP options */
#define	IP4O_COPY		0x80	/* copy on fragment mask				*/
#define IP4O_CLASS		0x60	/* option class							*/
#define	IP4O_NUM		0x17	/* option number						*/
#define	IP4O_EOOP		0x00	/* end of options						*/
#define	IP4O_NOP		0x01	/* no operation							*/
#define	IP4O_SEC		0x82	/* DoD security/compartmentalization	*/
#define	IP4O_LSRCRT		0x83	/* loose source routing					*/
#define	IP4O_SSRCRT		0x89	/* strict source routing				*/
#define	IP4O_RECRT		0x07	/* record route							*/
#define	IP4O_STRID		0x88	/* stream ID							*/
#define	IP4O_TIME		0x44	/* Internet time stamp					*/

/* Some Assigned Protocol Numbers */
#define	IP4_PT_ICMP		1		/* protocol type for ICMP packets	*/
#define	IP4_PT_IGMP		2		/* protocol type for IGMP packets	*/
#define	IP4_PT_TCP		6		/* protocol type for TCP packets	*/
#define IP4_PT_EGP		8		/* protocol type for EGP packets	*/
#define	IP4_PT_UDP		17		/* protocol type for UDP packets	*/
#define	IP4_PT_OSPF		89		/* protocol type for OSPF packets	*/

/* IP Precedence values */
#define	IP4_PR_NETCTL	0xe0	/* Network control		*/
#define	IP4_PR_INCTL	0xc0	/* Internet control		*/
#define	IP4_PR_CRIT		0xa0	/* Critical				*/
#define	IP4_PR_FLASHO	0x80	/* Flash over-ride		*/
#define	IP4_PR_FLASH	0x60	/* Flash 				*/
#define	IP4_PR_IMMED	0x40	/* Immediate			*/
#define	IP4_PR_PRIO		0x20	/* Priority				*/
#define	IP4_PR_NORMAL	0x00	/* Normal				*/

/* Other constants */
#define DIR_OUT			0
#define DIR_IN			1
#define	IP4_NETLINK_BUFF_SIZE		4096

/* macro to compute a datagram's header length (in bytes)	*/
#define	IP4_HLEN(pip)			((pip->ip_verlen & 0xf)<<2)
/* macro to get the datagram's version number				*/
#define IP4_VER(pip)			(pip->ip_verlen>>4)
/* macro to get datagram's flags							*/
#define IP4_FLG(fragoff)		((fragoff>>13)&0x7)

#define IP4_ETH_TYPE  0x0800

/* macros to determine IP address class*/
#define	IP4_CLASSA(x) (((x) & 0x80000000) == 0)		/* IP Class A */
#define	IP4_CLASSB(x) (((x) & 0xc0000000) == 0x80000000)	/* IP Class B */
#define	IP4_CLASSC(x) (((x) & 0xe0000000) == 0xc0000000)	/* IP Class C */
#define	IP4_CLASSD(x) (((x) & 0xf0000000) == 0xe0000000)	/* IP Class D */
#define	IP4_CLASSE(x) (((x) & 0xf8000000) == 0xf0000000)	/* IP Class E */

uint16_t ipv4_checksum(struct ip4_packet* ptr, int length);
int IP4_dest_check(uint32_t destination);
//void IP4_reass(void);

uint8_t IP4_add_fragment(struct ip4_reass_list*, struct ip4_fragment*);
struct ip4_packet* IP4_reass(struct ip4_header *header, struct ip4_packet *packet);
struct ip4_reass_list* IP4_new_packet_entry(struct ip4_header* pheader, struct ip4_reass_list* previous, struct ip4_reass_list* next);
struct ip4_fragment* IP4_construct_fragment(struct ip4_header* pheader, struct ip4_packet* ppacket);
struct ip4_reass_hole* IP4_previous_hole(struct ip4_reass_hole* current_hole);
struct ip4_reass_hole* IP4_next_hole(struct ip4_reass_hole* current_hole);
void IP4_remove_hole(struct ip4_reass_hole* current_hole, struct ip4_reass_list *list);
struct ip4_fragment IP4_fragment_data(void *data, uint16_t length, uint16_t offest, uint16_t fragment_size);

struct ip4_routing_table *IP4_get_routing_table();
struct ip4_routing_table *IP4_sort_routing_table(struct ip4_routing_table *table_pointer);
void IP4_print_routing_table(struct ip4_routing_table *table_pointer);
struct ip4_next_hop_info IP4_next_hop(struct fins_module *module, uint32_t dst);
int ipv4_forward(struct fins_module *module, struct finsFrame *ff, struct ip4_packet* ppacket, uint32_t dest, uint16_t length);

int InputQueue_Read_local(struct finsFrame *pff);
void IP4_exit(void);

//void ipv4_exec_reply_get_addr(struct finsFrame *ff, uint64_t src_mac, uint64_t dst_mac);
//void ipv4_exec_reply_get_addr(struct finsFrame *ff, uint64_t src_mac, uint32_t src_ip, uint64_t dst_mac, uint32_t dst_ip);

#define IPV4_ADDRESS_LIST_MAX 	512
#define IPV4_ROUTE_LIST_MAX 	512
#define IPV4_ADDR_ANY_IP 		IP4_ADR_P2H(0,0,0,0)
#define IPV4_ADDR_EVERY_IP 		IP4_ADR_P2H(255,255,255,255)

#define IPV4_LIB "ipv4"
#define IPV4_MAX_FLOWS 		4
#define IPV4_FLOW_INTERFACE 0
#define IPV4_FLOW_ICMP 		1
#define IPV4_FLOW_TCP 		2
#define IPV4_FLOW_UDP 		3

struct ipv4_data {
	struct linked_list *link_list; //linked list of link_record structs, representing links for this module
	uint32_t flows_num;
	struct fins_module_flow flows[IPV4_MAX_FLOWS];

	pthread_t switch_to_ipv4_thread;

	struct linked_list *addr_list; //list of IPv4 addresses for all of the interfaces
	struct addr_record *addr_loopback;
	struct addr_record *addr_main;

	struct linked_list *route_list; //list of route_record, for a routing table
	//struct ip4_reass_list *packet_list = NULL;
	uint16_t unique_id;


	struct ipv4_statistics stats;
};

int ipv4_init(struct fins_module *module, metadata_element *params, struct envi_record *envi);
int ipv4_run(struct fins_module *module, pthread_attr_t *attr);
int ipv4_pause(struct fins_module *module);
int ipv4_unpause(struct fins_module *module);
int ipv4_shutdown(struct fins_module *module);
int ipv4_release(struct fins_module *module);

void ipv4_get_ff(struct fins_module *module);
void ipv4_fcf(struct fins_module *module, struct finsFrame *ff);
void ipv4_read_param(struct fins_module *module, struct finsFrame *ff);
void ipv4_set_param(struct fins_module *module, struct finsFrame *ff);
void ipv4_exec(struct fins_module *module, struct finsFrame *ff);
void ipv4_exec_reply(struct fins_module *module, struct finsFrame *ff);
void ipv4_exec_reply_get_addr(struct fins_module *module, struct finsFrame *ff);

void ipv4_error(struct fins_module *module, struct finsFrame *ff);

void ipv4_in_fdf(struct fins_module *module, struct finsFrame *ff);
void ipv4_send_fdf_in(struct fins_module *module, struct finsFrame *ff, struct ip4_header *pheader, struct ip4_packet *ppacket);

void ipv4_out_fdf(struct fins_module *module, struct finsFrame *ff);
void ipv4_const_header(struct fins_module *module, struct ip4_packet *packet, uint32_t source, uint32_t destination, uint8_t protocol);
void ipv4_send_fdf_out(struct fins_module *module, struct finsFrame *ff, struct ip4_packet *ppacket, uint32_t address, int32_t if_index);

#define IPV4_ERROR_TTL 0
#define IPV4_ERROR_DEST_UNREACH 1
#define IPV4_ERROR_GET_ADDR 2

//don't use 0
#define IPV4_READ_PARAM_FLOWS MOD_READ_PARAM_FLOWS
#define IPV4_READ_PARAM_LINKS MOD_READ_PARAM_LINKS
#define IPV4_READ_PARAM_DUAL MOD_READ_PARAM_DUAL

#define IPV4_SET_PARAM_FLOWS MOD_SET_PARAM_FLOWS
#define IPV4_SET_PARAM_LINKS MOD_SET_PARAM_LINKS
#define IPV4_SET_PARAM_DUAL MOD_SET_PARAM_DUAL

#endif /* IPV4_INTERNAL_H_ */
