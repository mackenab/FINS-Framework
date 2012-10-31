/*
 * IP4_fdf_out.c
 *
 *  Created on: Jun 14, 2010
 *      Author: rado
 */

#include "IP4.h"
#include "udp.h"
void IP4_send_fdf_in(struct ip4_header* pheader, struct ip4_packet* ppacket)
{
	struct finsFrame fins_frame;
	PRINT_DEBUG("IP4_send_fdf_in() has just been called");
	fins_frame.dataOrCtrl = DATA;
	switch (pheader->protocol)
	{
	case IP4_PT_TCP:
		fins_frame.destinationID = TCPID;
		break;
	case IP4_PT_UDP:
		fins_frame.destinationID = UDPID;
		break;
	case IP4_PT_ICMP:
		fins_frame.destinationID = 0;// todo: ICMPID should be decided
		break;
	}
	fins_frame.dataFrame.directionFlag = UP;
	fins_frame.dataFrame.pduLength = pheader->packet_length;
	fins_frame.dataFrame.pdu = ppacket->ip_data;
	//fins_frame.dataFrame.metaData = .....// todo: metadata needs to be filled with whatever needs to be in meta data
	//output_queue_write(fins_frame);
	struct udp_metadata_parsed meta;
	meta.u_IPdst = pheader->destination;
	meta.u_IPsrc = pheader->source;
	meta.u_prcl = pheader->protocol;
	PRINT_DEBUG("IP plength:%u", meta.u_pslen = pheader->packet_length-IP4_MIN_HLEN);
	memcpy(&fins_frame.dataFrame.metaData, &meta, sizeof(struct udp_metadata_parsed));
	udp_in_fdf(&fins_frame);

}

void IP4_send_fdf_out(struct ip4_packet* ppacket,
		struct ip4_next_hop_info next_hop, uint16_t length)
{
	struct finsFrame fins_frame;
	PRINT_DEBUG("IP4_send_fdf_out() has been just called.");
	fins_frame.dataOrCtrl = DATA;
	fins_frame.destinationID = ETHERSTUBID;
	fins_frame.dataFrame.directionFlag = DOWN;
	fins_frame.dataFrame.pduLength = length;
	fins_frame.dataFrame.pdu = (unsigned char *)ppacket;
	//fins_frame.dataFrame.metaData = ..... // todo: meta data needs to be filled with the required info.
	//output_queue_write(fins_frame);
	wifi_inject(ppacket,length);
}

//todo: needs to be replaced by something meaningful
void output_queue_write(struct finsFrame fins_frame){
	PRINT_DEBUG("Diff: %u",((struct ip4_packet*)fins_frame.dataFrame.pdu)->ip_cksum);
	FILE* f; // create a new file pointer
	if((f=fopen("UDP_IP_out.txt","a"))==NULL) { // open a file
	 printf("could not open file"); // print an error
	 exit(1);
	}
	fputs("+---------+---------------+----------+\n17:25:15,370,334   ETHER\n|0   |00|24|f9|c3|28|00|00|21|6a|56|68|de|08|00|", f);
	int i;
	unsigned char* ptr;
	ptr = fins_frame.dataFrame.pdu;
	for(i = 0; i<fins_frame.dataFrame.pduLength; i++){
		//PRINT_DEBUG("Byte:%.2x|\n",*ptr++);
		fprintf(f,"%.2x|",/*(unsigned char)fins_frame.dataFrame.pdu[i]*/ *ptr++);
	}
	fprintf(f,"\n\n");
	fclose(f);


}
