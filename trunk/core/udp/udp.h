/*
 * udp.h
 *
 *  Created on: Jun 28, 2010
 *      Author: Abdallah Abdallah
 */

#ifndef UDP_H_
#define UDP_H_

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
#define UDP_SENT_LIST_MAX (2*65536) //TODO change back to 2^16?
struct udp_sent { //TODO move this functionality to common, or data_structure
	struct udp_sent *next;

	struct finsFrame *ff;
	uint32_t host_ip;
	uint16_t host_port;
	uint32_t rem_ip;
	uint16_t rem_port;

	struct timeval stamp;
};

struct udp_sent *udp_sent_create(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void udp_sent_free(struct udp_sent *sent);

struct udp_sent_list {
	uint32_t max;
	uint32_t len;
	struct udp_sent *front;
	struct udp_sent *end;
};

//TODO convert to hardcoded sent_list, so no create/free
struct udp_sent_list *udp_sent_list_create(uint32_t max);
void udp_sent_list_append(struct udp_sent_list *sent_list, struct udp_sent *sent);
struct udp_sent *udp_sent_list_find(struct udp_sent_list *sent_list, uint8_t *data, uint32_t data_len);
struct udp_sent *udp_sent_list_remove_front(struct udp_sent_list *sent_list);
void udp_sent_list_remove(struct udp_sent_list *sent_list, struct udp_sent *sent);
int udp_sent_list_is_empty(struct udp_sent_list *sent_list);
int udp_sent_list_has_space(struct udp_sent_list *sent_list);
void udp_sent_list_free(struct udp_sent_list *sent_list);
void udp_sent_list_gc(struct udp_sent_list *sent_list, double timeout);

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

void udp_init(void);
void udp_run(pthread_attr_t *fins_pthread_attr);
void udp_shutdown(void);
void udp_release(void);

//unsigned short UDP_checksum(struct udp_packet *pcket, struct udp_metadata_parsed *params);
uint16_t UDP_checksum(struct udp_packet *pcket, uint32_t src_ip, uint32_t dst_ip);

#define EXEC_UDP_CLEAR_SENT 0

void udp_fcf(struct finsFrame *ff);
void udp_exec(struct finsFrame *ff);
void udp_exec_clear_sent(struct finsFrame *ff, uint32_t host_ip, uint16_t host_port, uint32_t rem_ip, uint16_t rem_port);
void udp_error(struct finsFrame *ff);

void udp_in_fdf(struct finsFrame *ff);
void udp_out_fdf(struct finsFrame *ff);

struct finsFrame *create_ff(int dataOrCtrl, int direction, int destID, int PDU_length, uint8_t *PDU, metadata *params);
int UDP_InputQueue_Read_local(struct finsFrame *pff_local);
void udp_get_ff(void);
int udp_to_switch(struct finsFrame *ff);
//static inline unsigned short from64to16(unsigned long x);

uint16_t UDP_checkSeparate(uint32_t src, uint32_t dest, uint16_t len, uint16_t protocol, uint16_t wsum);

#define ERROR_ICMP_TTL 0
#define ERROR_ICMP_DEST_UNREACH 1

#endif
