/**
 * @file wifidemux.h
 *
 *  @date Nov 23, 2010
 *      @author Abdallah Abdallah
 *
 *      @brief some of the code below is taken from an unknown online
 *      resource.
 */

#ifndef WIFIDEMUX_H_
#define WIFIDEMUX_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>




#include <linux/if_ether.h>
#include <pthread.h>
#include "getMAC_Address.h"
#include <finstypes.h>
#include <finsdebug.h>




/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* IPv4 header ,99.99% its size is 20 Bytes */
#define SIZE_IPv4 20

/* UDP header ,99.99% its size is only 8 Bytes */
#define SIZE_UDP 8

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/** Header calculations Macros */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};



/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};


struct ipv4_packet {

		   u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
	        u_char  ip_tos;                 /* type of service */
	        u_short ip_len;                 /* total length */
	        u_short ip_id;                  /* identification */
	        u_short ip_off;                 /* fragment offset field */
	        #define IP_RF 0x8000            /* reserved fragment flag */
	        #define IP_DF 0x4000            /* dont fragment flag */
	        #define IP_MF 0x2000            /* more fragments flag */
	        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
	        u_char  ip_ttl;                 /* time to live */
	        u_char  ip_p;                   /* protocol */
	        u_short ip_sum;                 /* checksum */
	        struct  in_addr ip_src,ip_dst;  /* source and dest address */
			unsigned char *transportload;


};



/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct tcp_datagram{
	 u_short th_sport;               /* source port */
	        u_short th_dport;               /* destination port */
	        tcp_seq th_seq;                 /* sequence number */
	        tcp_seq th_ack;                 /* acknowledgement number */
	        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	        u_char  th_flags;
	        #define TH_FIN  0x01
	        #define TH_SYN  0x02
	        #define TH_RST  0x04
	        #define TH_PUSH 0x08
	        #define TH_ACK  0x10
	        #define TH_URG  0x20
	        #define TH_ECE  0x40
	        #define TH_CWR  0x80
	        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	        u_short th_win;                 /* window */
	        u_short th_sum;                 /* checksum */
	        u_short th_urp;                 /* urgent pointer */

	        unsigned char *payload;

};


struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
	u_short	uh_len;			/* Total Datagram length  ( header + Payload )*/
        u_short uh_sum;                 /* checksum */

};

struct udp_datagram
{
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short	uh_len;			/* Total Datagram length  ( header + Payload )*/
    u_short uh_sum;                 /* checksum */
    unsigned char *payload;


};
/** Headers size defined externally as Global Variables to allow the
 * protocol handlers to update them
 * */


 int size_ip;
 int size_tcp;



/** Functions prototypes, full definition found in wifidemux.c */

 void arp_handler(unsigned char* arp_packet, u_int length);
 void rarp_handler(unsigned char* rarp_packet, u_int length);

void ip4_handler(unsigned char* arp_packet, u_int length);

void parse_frame (int framelength,u_char *packet);



#endif /* WIFIDEMUX_H_ */
