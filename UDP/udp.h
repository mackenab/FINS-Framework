/*
 * udp.h
 *
 *  Created on: Jun 28, 2010
 *      Author: alex
 */

#ifndef UDP_H_
#define UDP_H_

#define IP_MAXLEN 65535
#define IP_MINLEN 5
#define U_HEADER_LEN 8 										/* UDP header length in bytes, 64 bits. */
#define U_MAXLEN  (IP_MAXLEN-(IP_MINLEN<<2)-U_HEADER_LEN)  	/* Maximum amount of data in the UDP packet */

#define UDP_PROTOCOL 	17									/* udp protocol number used in the pseudoheader	*/
#define IGNORE_CHEKSUM  0									/* the checksum value when it is not being used */




struct udp_packet {
	uint16_t u_src; 			/*UPD source port number */
	uint16_t u_dst; 			/*UDP destination port */
	uint16_t u_len; 			/*Length of UDP packet */
	uint16_t u_cksum; 			/* UDP checksum all 1's means no checksum*/
	char u_data[U_MAXLEN]; 		/*Data in the packet*/
};

struct udp_metadata_parsed {
	uint32_t u_IPsrc; 			/* IP source from metadata */
	uint32_t u_IPdst;			/* IP destination from metadata */
	uint16_t u_prcl; 			/* protocol number should  be 17 from metadata */
	uint16_t u_pslen;			/* length of the UDP packet from the pseudoheader */
	uint16_t u_srcPort;			/* The Source port address*/
	uint16_t u_destPort;		/* destination port address */

};

struct udp_statistics{
	uint16_t badChecksum;			/* total number of datagrams that have a bad checksum*/
	uint16_t noChecksum;			/* total number of datagrams with no checksum */
	uint16_t mismatchingLengths;	/* total number of datagrams with mismatching datagram lengths from the header and pseudoheader */
	uint16_t wrongProtocol;			/* total number of datagrams that have the wrong Protocol value in the pseudoheader */
	uint32_t totalBadDatagrams;		/* total number of datagrams that were thrown away */
	uint32_t totalRecieved;			/* total number of incoming UDP datagrams */
	uint32_t totalSent;				/* total number of outgoing UDP datagrams */
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



#define IP4_ADR_P2N(a,b,c,d) 	(16777216ul*a + (65536ul*b) + (256ul*c) + (d))



unsigned short UDP_checksum(struct udp_packet* pcket,
		struct udp_metadata_parsed* meta);
void udp_in(struct finsFrame* ff);
void udp_out(struct finsFrame* ff);
struct finsFrame* create_ff(int dataOrCtrl, int direction, int destID,  int PDU_length, unsigned char* PDU, unsigned char* metadata );
int UDP_InputQueue_Read_local(struct finsFrame *pff_local);
void udp_get_FF();
#endif
