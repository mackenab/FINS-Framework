/*
 * @file tcp_in.c
 *
 *  @date Jun 21, 2011
 *      @author Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "tcp.h"

extern struct tcp_connection* connections;	//The list of current connections we have

void tcp_in(struct finsFrame *ff)
{
	//First things first. Check the checksum, and discard if it's bad.
	if(TCP_checksum(ff))
	{
		//Packet is bad if checksum != 0
		PRINT_DEBUG("Bad checksum in TCP packet. Dropping...");
		return;
	}
	//Get TCP info from this frame
	struct tcp_segment* tcp = fins_to_tcp(ff);
	//Find what connection this belongs to
	struct tcp_connection* connect = find_tcp_connection(tcp);

	/*//See if this has the next expected sequence number.
	if(tcp->seq_num == next_expected_seq)	//If so, forward to application as-is.
	{
		//next_expected_seq += tcp->datalen;	//Increment our next expected sequence number to be the next part of the data that we want


	}
	else									//If not, stick in queue for later. We could drop it, but that's lame
	{

	}*/






}
