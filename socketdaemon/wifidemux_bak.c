/*
 * wifidemux.c
 *
 *  Created on: Nov 23, 2010
 *      Author: Abdallah Abdallah
 */

#include "wifidemux.h"


void arp_handler(unsigned char* arp_packet, u_int length)
{
	PRINT_DEBUG("arp handle support to be added later \n");
	struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));


		ff->dataOrCtrl = DATA;
/* SKIP THIS PART NOW
		if ( search_module_table(switchTableCopy,(unsigned char) ETH_P_IP, UP) == NULL )
		{
			PRINT_DEBUG("Searching the switch table fails \n");
			//send to the switch asking for updates
		}
	*/
		ff->destinationID.id = ARPID;
		ff->destinationID.next = NULL;
		ff->dataFrame.directionFlag = UP;
/**
 * SKIP THE META DATA PART Now too
 * METADATA will be sent as NULL
 */

		ff->dataFrame.metaData = NULL;
		ff->dataFrame.pduLength= length;
		ff->dataFrame.pdu = arp_packet;

		/** 1. wait on the semaphore corresponding to wifi_to_swt queue
		 * 2. write to the queue
		 * 3. post the semaphore
		 */

		if (write_queue(ff,wifi_to_swt_bff) == 0 )

			PRINT_DEBUG("writing to the wifi_to_swt_queue failed \n");

		return; // return to the caller (parse_frame)










}

void rarp_handler(unsigned char* rarp_packet, u_int length)
{
	PRINT_DEBUG("rarp handle support to be added later \n");
	return;


}


void ip4_handler(unsigned char* ip4_packet, u_int length)
{

		struct finsFrame *ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));


		ff->dataOrCtrl = DATA;
/* SKIP THIS PART NOW
		if ( search_module_table(switchTableCopy,(unsigned char) ETH_P_IP, UP) == NULL )
		{
			PRINT_DEBUG("Searching the switch table fails \n");
			//send to the switch asking for updates
		}
	*/
		ff->destinationID.id = IPID;
		ff->destinationID.next = NULL;
		ff->dataFrame.directionFlag = UP;
/**
 * SKIP THE META DATA PART Now too
 * METADATA will be sent as NULL
 */

		ff->dataFrame.metaData = NULL;
		ff->dataFrame.pduLength= length;
		ff->dataFrame.pdu = ip4_packet;

		/** 1. wait on the semaphore corresponding to wifi_to_swt queue
		 * 2. write to the queue
		 * 3. post the semaphore
		 */

		if (write_queue(ff,wifi_to_swt_bff) == 0 )

			PRINT_DEBUG("writing to the wifi_to_swt_queue failed \n");

		return; // return to the caller (parse_frame)



}

void parse_frame (int framelength,u_char *frame)
{

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const char *payload;                    /* Packet payload */

	struct ip4_packet* ip_packet;			/* the IP packet */
	struct udp_datagram *udp_dg;

	int size_payload;
	u_short ether_type;

			/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(frame);
	ether_type = ntohs(ethernet->ether_type);

	switch (ether_type){
						case ETH_P_IP:
						PRINT_DEBUG("   Protocol: IPv4\n");

						ip4_handler(frame + SIZE_ETHERNET, framelength - SIZE_ETHERNET);
									break;
						case ETH_P_LOOP:
							PRINT_DEBUG("   Protocol: Ethernet Loopback packet\n");
						ip4_handler(frame + SIZE_ETHERNET, framelength - SIZE_ETHERNET);
									break;
						case ETH_P_ARP:
							PRINT_DEBUG("   Protocol: ARP\n");
						arp_handler(frame + SIZE_ETHERNET, framelength - SIZE_ETHERNET);
									break;
						case ETH_P_RARP:
							PRINT_DEBUG("   Protocol: RARP\n");
							rarp_handler(frame + SIZE_ETHERNET, framelength - SIZE_ETHERNET);
									break;
						default :
							PRINT_DEBUG("Protocol: unknown network\n");
									return;
								}

	return; // return to the caller (the one who polls from the capture_pipe.)

}  // end of parse_frame()
