/**
 * @file htoi.c
 *
 * @date July 2, 2010
 * @brief has all the constants definitions and the FDF/FCF , and FinsFrame format.
 * @version 2 fix the define values to be into capital letters
 * @author: Abdallah Abdallah
 */
/*
 * This code includes some modified parts of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>





#ifndef FINSTYPES_H_
#define FINSTYPES_H_

/* Definition of the modules IDs */
#define SOCKETSTUBID 55
#define UDPID	44
#define TCPID	33
#define IPID	22
#define WIFISTUBID	11

/* Definition of the possible Opcodes */

#define READREQUEST 111
#define READREPLY	222
#define WRITEREQUEST 333
#define WRITECONF	444
#define QUERYREQUEST	555
#define QUERYREPLY	666

/* Definition of data/control as well as direction flags */
#define DATA 0
#define CONTROL 1
#define UP 0
#define DOWN 1

/*meta data related definitions */
#define MAX_METADATASIZE	200

/* Protocols header lengths */
#define ETHERHDLEN	12
#define IPHDLEN		20
#define TCPHDLEN	20
#define UDPHDLEN	8

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6


/* Ethernet header */
struct ethernet_header {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_header {
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

struct udp_header {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
	u_short	uh_len;			/* Total Datagram length  ( header + Payload )*/
        u_short uh_sum;                 /* checksum */

};

struct metaBlock
{

	const struct ethernet_header *ether;  /* The ethernet header [1] */
	const struct ip_header *ip;              /* The IP header */
	const struct tcp_header *tcp;            /* The TCP header */
	const struct udp_header *udp;            /* The UDP header */

};

typedef struct metaBlock* metadata;

struct tableRecord
{
	unsigned char sourceID;
	unsigned char directionFlag;
	unsigned char vci;
	unsigned char destinationID;
	struct tableRecord *next;
};

/*
 struct finsDataFrame
{

	/** Only for FINS DATA FRAMES */
/*
	unsigned char directionFlag;
	unsigned int	pduLength;
	unsigned char 	*pdu;
	unsigned char metaData[MAX_METADATASIZE];

};    */


struct finsDataFrame
{

	/** Only for FINS DATA FRAMES */

	unsigned char directionFlag;
	unsigned int	pduLength;
	unsigned char 	*pdu;
	metadata meta;

};



struct finsCtrlFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	/* Special fields for control frames depending on the Opcode */
	unsigned int paramterID;
	void *paramterValue;
	struct tableRecord *replyRecord;

};





struct finsFrame
{

/* Common Fields between data and control */
unsigned char dataOrCtrl;
unsigned char destinationID;
union
{
struct finsDataFrame dataFrame;
struct finsCtrlFrame ctrlFrame;
};

};



struct readRequestFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

unsigned int paramterID;


};

struct readReplyFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

void *paramterValue;


};

struct writeRequestFrame
{
	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

unsigned int paramterID;
void *paramterValue;


};


struct writeConfirmationFrame
{
	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

};

struct queryRequestFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

};



struct queryReplyFrame
{

	/* only for FINS control frames  */
	unsigned char senderID;
	unsigned short int opcode;
	unsigned int serialNum;

	struct tableRecord *replyRecord;
};



#endif /* FINSTYPES_H_ */
