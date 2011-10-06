/*
 * tcp.c
 *
 *  Created on: Mar 14, 2011
 *      Author: Abdallah Abdallah
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <finstypes.h>
#include <queueModule.h>
#include "tcp.h"

extern sem_t TCP_to_Switch_Qsem;
extern finsQueue TCP_to_Switch_Queue;

extern sem_t Switch_to_TCP_Qsem;
extern finsQueue Switch_to_TCP_Queue;

struct tcp_connection* connections;	//The list of current connections we have



void tcp_get_FF() {

	struct finsFrame *ff;
	do {
		sem_wait(&Switch_to_TCP_Qsem);
		ff = read_queue(Switch_to_TCP_Queue);
		sem_post(&Switch_to_TCP_Qsem);
	} while (ff == NULL);

	if (ff->dataOrCtrl == CONTROL) {
		// send to something to deal with FCF
		PRINT_DEBUG("send to CONTROL HANDLER !");
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == UP)) {
		tcp_in(ff);
		PRINT_DEBUG();
	}
	if ((ff->dataOrCtrl == DATA) && ((ff->dataFrame).directionFlag == DOWN)) {
		tcp_out(ff);
		PRINT_DEBUG();
	}

}



void tcp_init() {

	PRINT_DEBUG("TCP started");
	connections = NULL;
	tcp_srand();
	while (1) {

			tcp_get_FF();
			PRINT_DEBUG();
			//	free(pff);


		}

}



//Get a random number to use as a starting sequence number
int tcp_rand()
{
	return rand();	//Just use the standard C random number generator for now
}

//Seed the above random number generator
void tcp_srand()
{
	srand(time(NULL));	//Just use the standard C random number generator for now
}

//--------------------------------------------
// Calculate the checksum of this TCP segment.
// (basically identical to ICMP_checksum().)
//--------------------------------------------
uint16_t TCP_checksum(struct finsFrame * ff)
{
	int sum = 0;
	unsigned char *w = ff->dataFrame.pdu;
	int nleft = ff->dataFrame.pduLength;

	//if(nleft % 2)  //Check if we've got an uneven number of bytes here, and deal with it accordingly if we do.
	//{
	//	nleft--;  //By decrementing the number of bytes we have to add in
	//	sum += ((int)(ff->dataframe.pdu[nleft])) << 8; //And shifting these over, adding them in as if they're the high byte of a 2-byte pair
		//This is as per specification of the checksum from the RFC: "If the total length is odd, the received data is padded with one
	    // octet of zeros for computing the checksum." We don't explicitly add an octet of zeroes, but this has the same result.
	//}

	while(nleft > 0)
	{
		//Deal with the high and low words of each 16-bit value here. I tried earlier to do this 'normally' by
		//casting the pdu to unsigned short, but the little-vs-big-endian thing messed it all up. I'm just avoiding
		//the whole issue now by treating the values as high-and-low-word pairs, and bit-shifting to compensate.
		sum += (int)(*w++) << 8;  //First one is high word: shift before adding in
		sum += *w++;			  //Second one is low word: just add in
		nleft -= 2;				  //Decrement by 2, since we're taking 2 at a time
	}

	//Fully fill out the checksum
	for(;;)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);  //Get the sum shifted over added into the current sum
		if(!(sum >> 16))  //Continue this until the sum shifted over is zero
			break;
	}
	return ~((uint16_t)(sum));  //Return one's complement of the sum
}


struct finsFrame* tcp_to_fins(struct tcp_segment* tcp)
{
	struct finsFrame* ffreturn = NULL;

	ffreturn = (struct finsFrame*)malloc(sizeof(struct finsFrame));
	ffreturn->dataFrame.pduLength = tcp->datalen + HEADERSIZE(tcp->flags);				//Add in the header size for this, too
	ffreturn->dataFrame.pdu = (unsigned char*)malloc(ffreturn->dataFrame.pduLength);

	ffreturn->dataFrame.metaData = (metadata *)malloc(sizeof(metadata));
	metadata_writeToElement(ffreturn->dataFrame.metaData, "srcport", &(tcp->src_port), META_TYPE_INT);	//Write the source port in
	metadata_writeToElement(ffreturn->dataFrame.metaData, "dstport", &(tcp->dst_port), META_TYPE_INT);	//And the destination port

	//TODO: Remember to get the src and dest IP to stick in the metadata, too.
	// Also remember to fill out the rest of the finsFrame...


	return ffreturn;
}

//------------------------------------------------------------------------------
// Fill out a tcp segment from a finsFrame. Gets the data it needs from the PDU.
//------------------------------------------------------------------------------
struct tcp_segment* fins_to_tcp(struct finsFrame* ff)
{
	struct tcp_segment* tcpreturn = NULL;
	tcpreturn = (struct tcp_segment*)malloc(sizeof(struct tcp_segment));
	uint8_t* ptr = ff->dataFrame.pdu;	//Start pointing at the beginning of the pdu data
	//For big-vs-little endian issues, I shall shift everything and deal with it manually here
	//Source port
	tcpreturn->src_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->src_port += *ptr++;
	//Destination port
	tcpreturn->dst_port = (uint16_t)(*ptr++) << 8;
	tcpreturn->dst_port += *ptr++;
	//Sequence number
	tcpreturn->seq_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->seq_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->seq_num += *ptr++;
	//Acknowledgment number
	tcpreturn->ack_num = (uint32_t)(*ptr++) << 24;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 16;
	tcpreturn->ack_num += (uint32_t)(*ptr++) << 8;
	tcpreturn->ack_num += *ptr++;
	//Flags and data offset
	tcpreturn->flags = (uint16_t)(*ptr++) << 8;
	tcpreturn->flags += *ptr++;
	//Window size
	tcpreturn->win_size = (uint16_t)(*ptr++) << 8;
	tcpreturn->win_size += *ptr++;
	//Checksum
	tcpreturn->checksum = (uint16_t)(*ptr++) << 8;
	tcpreturn->checksum += *ptr++;
	//Urgent pointer
	tcpreturn->urg_pointer = (uint16_t)(*ptr++) << 8;
	tcpreturn->urg_pointer += *ptr++;

	//Now copy the rest of the data, starting with the options
	int optionssize = HEADERSIZE(tcpreturn->flags) - MIN_TCP_HEADER_LEN;
	if(optionssize > 0)
	{
		tcpreturn->options = (uint8_t*)malloc(optionssize);
		int i;
		for(i = 0; i < optionssize; i++)
		{
			tcpreturn->options[i] = *ptr++;
		}
	}

	//And fill in the data length and the data, also
	tcpreturn->datalen = ff->dataFrame.pduLength - HEADERSIZE(tcpreturn->flags);
	if(tcpreturn->datalen > 0)
	{
		tcpreturn->data = (uint8_t*)malloc(tcpreturn->datalen);
		int i;
		for(i = 0; i < tcpreturn->datalen; i++)
		{
			tcpreturn->data[i] = *ptr++;
		}
	}

	return tcpreturn;	//Done
}

struct tcp_connection* find_tcp_connection(struct tcp_segment* tcp)
{
	return NULL;
}















