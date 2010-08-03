/*
 * UDP test.c
 *
 *  Created on: Jun 30, 2010
 *      Author: alex
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include "finstype.h"
#include "udp.h"

struct udp_statistics udpStat;

//void main(){
//	while(1){
//		udp_get_FF();
//	}
//}

/* checksum test */
//int main() {
//
//	struct udp_packet packet2;
//	struct udp_metadata_parsed pseudoheader2;
//	struct udp_packet* packet_ptr;
//	struct udp_metadata_parsed* pseudoheader_ptr;
//	unsigned short checksum = 0;
//
//
//	packet2.u_src = 1087;
//	packet2.u_dst = 13;
//	packet2.u_len = 15;
//	pseudoheader2.u_pslen = 15;
//	pseudoheader2.u_prcl = 17;
//	pseudoheader2.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
//	pseudoheader2.u_IPdst = IP4_ADR_P2N(171,2,14,10);
//	packet2.u_cksum = 0;
//	char str[10] = "TESTING";
//	strcpy(packet2.u_data, str);
//
//	printf("The packet's data is %s\n", packet2.u_data);
//
//	pseudoheader_ptr = &pseudoheader2;
//	packet_ptr = &packet2;
//
//
//	printf("Packet ptr's checksum is %i\n", packet_ptr->u_cksum);
//	printf("Packet2's checksum is %i\n", packet2.u_cksum);
//	printf("The checksums value is %i \n", checksum);
//
//	checksum = UDP_checksum(packet_ptr, pseudoheader_ptr);
//
//	printf("The checksums value is %i \n ", checksum);
//
//	return(0);
//	}

/* udp_in test */

//int main() {
//
//	struct udp_packet packet2;
//	struct udp_metadata_parsed pseudoheader2;
//	struct finsFrame* pff;
//	struct finsFrame ff;
//	unsigned short checksum = 26900;
//
//
//	packet2.u_src = 1087;
//	packet2.u_dst = 13;
//	packet2.u_len = 15;
//	pseudoheader2.u_pslen = 15;
//	pseudoheader2.u_prcl = 17;
//	pseudoheader2.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
//	pseudoheader2.u_IPdst = IP4_ADR_P2N(171,2,14,10);
//	packet2.u_cksum = checksum;
//	char str[10] = "TESTING";
//	strcpy(packet2.u_data, str);
//
//	ff.dataFrame.pdu = &packet2;
//
//	memcpy(&ff.dataFrame.metaData, &pseudoheader2, 16);
//
//	ff.dataFrame.pduLength = packet2.u_len;
//	ff.dataOrCtrl = DATA;
//	ff.destinationID = UDPID;
//	ff.dataFrame.directionFlag = UP;
//
//
//	pff = &ff;
//
//	printf("The metadata's value for the length is %d\n", pseudoheader2.u_pslen);
//				printf("The UDP packet's value for the length is %d\n", packet2.u_len);
//	udp_in(pff);
//
//
//	return(0);
//	}

/* udp_out test */
int main() {
	struct udp_metadata_parsed meta;
	struct finsFrame* pff;
	struct finsFrame ff;
	unsigned short checksum = 0;

	char str[20] = "00000000TESTING";

	ff.dataFrame.pdu = &str[0];


	meta.u_IPdst = IP4_ADR_P2N(171,2,14,10);
	meta.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
	meta.u_destPort = 13;
	meta.u_srcPort = 1087;



	ff.dataFrame.pduLength = 7;
	ff.dataOrCtrl = DATA;
	ff.destinationID = UDPID;
	ff.dataFrame.directionFlag = DOWN;


	memcpy(&ff.dataFrame.metaData, &meta, 16);
	pff = &ff;

//	printf("The metadata's value for the length is %d\n", pseudoheader2.u_pslen);
//	printf("The UDP packet's value for the length is %d\n", packet2.u_len);
	udp_out(pff);

	return (0);
}
