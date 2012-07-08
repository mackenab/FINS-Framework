/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * 
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 * 
 * The Ethernet size is always 14 bytes.
 * 
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
 * you're using structures, you must use structures where the members 
 * always have the same size on all platforms, because the sizes of the 
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
 * the protocol specification, not by the way a particular platform's C 
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after 
 * the beginning of the packet data.  To find the TCP header, look 
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 * 
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end 
 * of the captured data in the packet - you might, for example, have a 
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
 * small for an IP header.  The length of the captured data is given in 
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
 * the length of the packet, if you're capturing with a snapshot length 
 * other than a value >= the maximum packet size.
 * <end of response>
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 * 
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 * 
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
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

#include <linux/if_ether.h>
#include <pthread.h>
#include "getMAC_Address.h"
#include "finstypes.h"
#include "finsdebug.h"
#include "list.h"


void *packet_capture(void *device);
 void *packet_inject(void *device);
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
/* thread list for both capturing an injecting */
struct thread_list {
    pthread_t capture_thread;
    pthread_t inject_thread;
};


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
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

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

struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
	u_short	uh_len;			/* Total Datagram length  ( header + Payload )*/
        u_short uh_sum;                 /* checksum */
        
};

/* Headers size defined as Global Variables to allow the protocol handlers to update them */

	int size_ip;
	int size_tcp;
	int size_udp = 8;


List L;
Position P;




void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

/* 
* Hanlde the TCP packets 

*/

void tcp_handler(const struct sniff_tcp *tcp,u_short ip_length  )
{
	
	int size_payload;	
	const char *payload;                    /* Packet payload */
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(tcp + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ip_length - (size_ip + size_tcp);
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

return;



}

/* 
* Hanlde the UDP packets 

*/


void udp_handler(const struct sniff_udp *udp)
{

	int size_payload;	
	const char *payload;                    /* Packet payload */
	
	
	printf("   Src port: %d\n", ntohs(udp->uh_sport));
	printf("   Dst port: %d\n", ntohs(udp->uh_dport));

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(udp + size_udp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(udp->uh_len) - size_udp ;
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

return;


}


void handling (u_char *packet)
{

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const char *payload;                    /* Packet payload */



/*
	int size_ip;
	int size_tcp;
	int size_udp = 8;
	int size_payload;
	*/
	int size_payload;
	u_short ether_t;

	/* this is the child process */
        printf("this is the child, will continue processing the data \n");

		/* define ethernet header */
			ethernet = (struct sniff_ethernet*)(packet);

			ether_t = ntohs(ethernet->ether_type);
			printf("%X \n", ether_t);
				/* determine Network protocol */
			switch (ether_t){
					case ETH_P_IP:
								printf("   Protocol: IPv4\n");
								break;
					case ETH_P_LOOP:
								printf("   Protocol: Ethernet Loopback packet\n");
								return;
					case ETH_P_ARP:
								printf("   Protocol: ARP\n");
								return;
					case ETH_P_RARP:
								printf("   Protocol: RARP\n");
								return;
					default :
								printf("   Protocol: unknown network\n");
								return;
							}
			/* define/compute ip header offset */
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}

			/* print source and destination IP addresses */
			printf("       From: %s\n", inet_ntoa(ip->ip_src));
			printf("         To: %s\n", inet_ntoa(ip->ip_dst));

			/* determine Transport protocol */
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					printf("   Protocol: TCP\n");
					break;

				case IPPROTO_UDP:
					printf("   Protocol: UDP\n");
					return;
				case IPPROTO_ICMP:
					printf("   Protocol: ICMP\n");
					return;
				case IPPROTO_IP:
					printf("   Protocol: IP\n");
					return;
				default:
					printf("   Protocol: unknown transport\n");
					return;
			}

			/*
			 *  OK, this packet is TCP.
			 */

			/* define/compute tcp header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20)
			{
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("   Src port: %d\n", ntohs(tcp->th_sport));
			printf("   Dst port: %d\n", ntohs(tcp->th_dport));

			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

			/*
			 * Print payload data; it might be binary, so don't just
			 * treat it as a string.
			 */
			if (size_payload > 0)
			{
				printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
				//print the whole packet instead of only the payload
				//print_payload(packet, strlen(packet));

			}
			else
			{
			printf("   Payload (%d bytes):\n", size_payload);

			}

		return;




}

/**
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packetReceived)
{
		static int count = 1;                   /* packet counter */
		u_char *packet;						 	/* Packet Pointer */

		printf("\nPacket number %d:\n", count);
		count++;

		if (header->caplen != header->len)
		{
			printf("Snaplen value is not enough to capture the whole packet as it is on wire \n");
			exit(1);
		}
		packet= (u_char *) malloc(header->caplen);
		memcpy(packet,packetReceived,header->caplen);


		//Insert( packet, L, P );
		handling(packet);
		free(packet);
		return;


}  // end of the function got_packet

void main(int argc, char **argv)
{

	L = MakeEmpty( NULL );		/* Initialize the packets buffer */
	P = Header( L );

	/* threads handling variables */
	struct thread_list threads;


	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	/* check for capture device name on command-line */
	if (argc == 2)
	{
		dev = argv[1];
		}
		else if (argc > 2) {
			fprintf(stderr, "error: unrecognized command-line options\n\n");
			print_app_usage();
			exit(EXIT_FAILURE);
		}
		else {
			/* find a capture device if not specified on command-line */
			dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
				exit(EXIT_FAILURE);
			}
	}


	/* Time to split into two threads : One for capturing and one for injection */

    if ( ( pthread_create ( &threads.capture_thread, NULL,
                            packet_capture,dev ) ) != 0 )
    {
        printf ( "\nError: Capture thread creation.\n" );
        exit ( 1 );
    }

    if ( ( pthread_create ( &threads.inject_thread, NULL,
                            packet_inject, dev ) ) != 0 )
    {
        printf ( "\nError: Inject thread creation.\n" );
        exit ( 1 );
    }


    pthread_join ( threads.capture_thread, NULL );
   pthread_join ( threads.inject_thread, NULL );


	PRINT_DEBUG("\nCapture complete.\n");
	PRINT_DEBUG("\nINJECTION complete.\n");
return;
}




void *packet_capture(void *device)
{
	printf("\n capture thread \n");

	pcap_t *handle;				/* packet capture handle */

	/* we need to filter frames based on the sender mac address !!
	 * if the sender mac address is our then, we dont sniff this frame !
	 * while we sniff any frame that is originated by someone else
	 * We can not depends on the sender IP address because this means we will
	 * still sniff outgoing packets generated by other network protocols
	 * such as ARP or IPv6
	 */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	unsigned char dev_macAddress[17];
	char *filter_exp;
	unsigned char *dev;
	filter_exp= (char *)malloc (100);
	strcat(filter_exp,"ether src not ");

	//char filter_exp[] = "ether src 00:1e:2a:52:ec:9c";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;				/* subnet mask */
	bpf_u_int32 net;				/* ip */
	int num_packets = 20;			/* number of packets to capture */
	int data_linkValue;
	print_app_banner();

	dev =(unsigned char *)device;

/* Build the filter expression based on the mac address of the passed
	 * device name
	 */
	getDevice_MACAddress(dev_macAddress,dev);
	strcat(filter_exp,dev_macAddress);
	//strcat(filter_exp," and not arp");
	strcpy(filter_exp,"not arp");
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	data_linkValue = pcap_datalink(handle);
	if (data_linkValue != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	printf("Datalink layer Description: %s \n",pcap_datalink_val_to_description(data_linkValue));

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	/* now we can set our callback function */
		pcap_loop(handle, 20, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

return NULL;
}

void *packet_inject(void *device)
{
		printf("\n Inject thread \n");

		static int numberOfCalls= 0;

		numberOfCalls ++;
		pcap_t *inject_handle;				/* packet capture handle */
		unsigned char *packet_data;
		packet_data = (unsigned char *)malloc(500);
		int lenghtOfData;

	/** Prepration of fake IP packet */
		char fakeData[]="001b2ff486cc001cbf871afd080045000028c8b6400040069f1bc0a801033ff5d15db39800506244457629f0d03f50111fa3675f0000";
		int i,j;

		unsigned char *token;
		unsigned char buf;
		token=(unsigned char *)malloc(3);
		j=0;
	/** NOTE THAT IF THE DATA to be copied has
	 * NULL equal characters , strlen  does not work correclty because
	 * it detects false NULL termination !!!!! DAM IT
	 */
		j=0;
		for (i=0; i< strlen(fakeData); i=i+2)
		{
			strncpy(token,&fakeData[i],2);
			PRINT_DEBUG("%s",token);
			buf=htoi(token);
//			if (buf == '\0')
	//			PRINT_DEBUG("ooops");
			PRINT_DEBUG("%d--%u",j+1,buf);
			strcat(packet_data,&buf);

			j=j+1;
		}

		PRINT_DEBUG("%s\n",fakeData);
		PRINT_DEBUG("%s\n",packet_data);
		lenghtOfData = j-1;
		PRINT_DEBUG("%d",strlen(fakeData));
		PRINT_DEBUG("%d",lenghtOfData);


		char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
		unsigned char *dev;
		struct bpf_program fp;			/* compiled filter program (expression) */
		bpf_u_int32 mask;				/* subnet mask */
		bpf_u_int32 net;				/* ip */
		dev= (unsigned char *)device;


		/* Setup the Injection Interface */
		    if ( ( inject_handle = pcap_open_live ( dev, BUFSIZ,
		                             1, -1, errbuf ) ) == NULL )
		    {
		        printf ( "\nError: %s\n", errbuf );
		        exit ( 1 );
		    }

		    /** pcap_t *pcap_open_live(const char *device, int snaplen,
		                 int promisc, int to_ms, char *errbuf);

		  		DESCRIPTION
		         pcap_open_live()  is  used to obtain a packet capture handle to look at
		         packets on the network.  device is a string that specifies the  network
		         device  to  open;  on Linux systems with 2.2 or later kernels, a device
		         argument of "any" or NULL can be  used  to  capture  packets  from  all
		         interfaces.

		         snaplen specifies the snapshot length to be set on the handle.

		         promisc specifies if the interface is to be put into promiscuous mode.

		         to_ms specifies the read timeout in milliseconds.
		       *
		       */






 /*  While sending buffer is not empty*/
	i=0;
	for (i=0;i <= 10; i++)

{

		sleep(1);
		pcap_inject ( inject_handle, packet_data,lenghtOfData );
		PRINT_DEBUG("\n Message #%d has been injected",i);


}

    pcap_close ( inject_handle );
    free(packet_data);
    PRINT_DEBUG("\n%d",numberOfCalls);
    PRINT_DEBUG("\n end of injection thread");

return NULL;
}
