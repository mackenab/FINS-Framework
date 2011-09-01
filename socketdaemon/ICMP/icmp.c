/**
 * icmp.c
 *
 *  Created on: Mar 15, 2011 - June 22, 2011
 *      Author: Abdallah Abdallah & Mark Hutcheson
 */

#include "icmp.h"


extern sem_t ICMP_to_Switch_Qsem;
extern finsQueue ICMP_to_Switch_Queue;

extern sem_t Switch_to_ICMP_Qsem;
extern finsQueue Switch_to_ICMP_Queue;


//--------------------------------------------
// We're getting an ICMP packet in. Process it
//--------------------------------------------
void ICMP_in(struct finsFrame *ff)
{
	//TODO: If raw socket or something like that, we'll get the IP header too. Test for this somehow.

	//First step: Check the checksum.
	if(ICMP_checksum(ff) != 0)
	{
		PRINT_DEBUG("ICMP_in(): Error in checksum of packet. Discarding...");
		return; //Discard packet if checksum is bad
	}
	//Second step: get the type and code from the ICMP header from the frame. Is this how we should do it?
	uint16_t protocol = 0;

	unsigned char Type;
	unsigned char Code;

	//Make sure this protocol is correct ( == ICMP)
	if(metadata_readFromElement(ff->dataFrame.metaData, "protocol", &protocol) != CONFIG_FALSE)
	{ //If this fails, we'll assume that the protocol is correct
		if(ntohl(protocol) != ICMP_PROTOCOL)
		{
			PRINT_DEBUG("ICMP_in(): Protocol =/= ICMP! Discarding frame...");
			return; //Stop here
		}
	}

	//Get the type and code from the ICMP message
	Type = ff->dataFrame.pdu[0];
	Code = ff->dataFrame.pdu[1];

	struct finsFrame* ffForward = NULL; //Used by various cases to forward packets onward to wherever they need to go

	//Determine what to do with this ICMP message based on its type and code
	switch(Type)
	{
	case TYPE_ECHOREPLY:
		if(Code == CODE_ECHO)
		{
			//Send to the application that created the echo request. Should I make this as a new packet, or just change where this packet is headed?
			//I shall make new packet.
			if(!ICMP_copy_finsFrame(ff, ffForward))
				break;
			ffForward->destinationID.id = SOCKETSTUBID;
			ICMP_send_FF(ffForward);
		}
		else
			PRINT_DEBUG("ICMP_in(): Error in ICMP packet code. Dropping...");
		break;
	case TYPE_DESTUNREACH:
		//TODO: Decide what to do here. Create some kind of error message somewhere and send to the application.
		//Send to the application that sent the original UDP packet. Again, should I create a new packet or just forward this one?
		//if(!ICMP_copy_finsFrame(ff, ffForward))
		//	break;
		//ffForward->destinationID.id = SOCKETSTUBID;	//Right? Or the UDP stub?
		//ICMP_send_FF(ffForward);
		break;
	case TYPE_ECHOREQUEST:
		if(Code == CODE_ECHO)
		{
			//Create an echo reply packet and send it out
			ICMP_ping_reply(ff);
		}
		else
			PRINT_DEBUG("ICMP_in(): Error in ICMP packet code. Dropping...");
		break;
	case TYPE_TTLEXCEED:
		//Notify the application that sent the original packet that its TTL expired. Just forward the packet or create a new one?
		if(!ICMP_copy_finsFrame(ff, ffForward))
			break;
		ffForward->destinationID.id = SOCKETSTUBID;
		ICMP_send_FF(ffForward);
		break;
	default:
		//Drop the packet
		PRINT_DEBUG("ICMP_in(): The type of this received ICMP packet is currently unsupported. Have a nice day. Dropping...");
		break;
	}
}

//-------------------------------------------------------
// We're sending an ICMP packet out. Process it and send.
//-------------------------------------------------------
void ICMP_out(struct finsFrame *ff)
{
	//First step: get the type and code from the ICMP header from the frame
	unsigned char Type;
	unsigned char Code;
	uint16_t protocol = 0;
	struct finsFrame* ffForward = NULL;

	//Make sure this protocol is correct ( == ICMP)
	if(metadata_readFromElement(ff->dataFrame.metaData, "protocol", &protocol) != CONFIG_FALSE)
	{ //If this fails, we'll assume that the protocol is = ICMP
		if(ntohl(protocol) != ICMP_PROTOCOL)
		{
			if(ntohl(protocol) != UDP_PROTOCOL)
			{
				PRINT_DEBUG("ICMP_out(): Incorrect protocol. Dropping frame...")
				return; //Stop here
			}
			else
			{
				//Get the type and code from the UDP message, in the correct location
				Type = ff->dataFrame.pdu[0];
				Code = ff->dataFrame.pdu[1];
			}
		}
		else
		{
			//Get the type and code from the ICMP message
			//Check the ICMP command to be sure that it's == unreachable
			/*
			if(metadata_readFromElement(ff->dataFrame.metadata, "ICMP Command", &IP_Dest) == CONFIG_FALSE)
			{
				PRINT_DEBUG("Missing data in FINS frame: no destination IP");
				return; //Stop here
			}
			IP_Dest = ntohl(IP_Dest);	//Make sure we don't have little-vs-big-endian problems*/
			Type = TYPE_DESTUNREACH;//TODO: iff "ICMP Command" == unreachable
			Code = CODE_PORTUNREACH;//TODO: Will we be able to figure this out from the metadata?
		}
	}


	//Determine what to do with this ICMP message based on its type and code
	switch(Type)
	{
	case TYPE_DESTUNREACH:
		//This'll be a UDP packet from the UDP socket stub. Create the ICMP packet with the correct error data and send it out.
		IMCP_create_unreach(ff);
		break;
	case TYPE_ECHOREQUEST:
		if(Code == CODE_ECHO)
		{
			//Just do some stuff to change the destination and send this packet out as-is
			if(!ICMP_copy_finsFrame(ff, ffForward))
				break;
			ffForward->destinationID.id = ETHERSTUBID;	//Right?
			ICMP_send_FF(ffForward);
		}
		else
			PRINT_DEBUG("ICMP_out(): Error in ICMP packet code. Dropping...");
		break;
	default:
		//Drop the packet
		PRINT_DEBUG("ICMP_out(): This type of this outgoing ICMP packet is currently unsupported. Have a nice day.");
		break;
	}
}

//---------------------------------------------------
// Retrieve a finsFrame from the queue and process it
//---------------------------------------------------
void ICMP_get_FF(struct finsFrame *ff)
{
	// Poll the queue constantly to see if there's anything there. Is this a good use of resources?
	do
	{
		sem_wait (&Switch_to_ICMP_Qsem);
			ff = read_queue(Switch_to_ICMP_Queue);
		sem_post (&Switch_to_ICMP_Qsem);
	} while (ff == NULL);

	if(ff->dataOrCtrl == CONTROL)
	{
		// send to something to deal with FCF
		PRINT_DEBUG("ICMP_get_FF(): Control frame. Send to control handler!");
	}
	else if((ff->dataFrame).directionFlag == UP)	//Incoming ICMP packet (coming in from teh internets)
	{
		ICMP_in(ff);
	}
	else if((ff->dataFrame).directionFlag == DOWN)	//Outgoing ICMP packet (going out from us to teh internets)
	{
		ICMP_out(ff);
	}
}

//-----------------------------------------------
// ICMP_send_ff(): Put a finsFrame onto the queue
//-----------------------------------------------
void ICMP_send_FF(struct finsFrame *ff)
{
	int result;
	//Just queue this frame up to go
	do
	{
		sem_wait (&ICMP_to_Switch_Qsem);
		result = write_queue(ff, ICMP_to_Switch_Queue); //Should we just hope this works, or check the return value and loop? I shall loop.
		sem_post (&ICMP_to_Switch_Qsem);
	} while(result == 0);
}

//-------------------------
// Start our main ICMP loop
//-------------------------
void ICMP_init()
{
	PRINT_DEBUG("ICMP_init(): ICMP Started");
	struct finsFrame *pff = NULL;
	while (1)
	{
		ICMP_get_FF(pff);
		PRINT_DEBUG("%d",(int)pff);
		//Note that we always clean up the frame, no matter what we do with it. If the frame needs to go somewhere else also, we make a copy.
		//Shouldn't we use freeFinsFrame() instead of just free()? I think so, so I will here
		free(pff->dataFrame.pdu); //AVOID PDU MEMORY LEAK WITH freeFinsFrame()! TODO: Comment this out if the memory leak problem gets fixed.
		freeFinsFrame(pff);
	}
}

//-------------------------------------------
// Calculate the checksum of this ICMP packet
//-------------------------------------------
unsigned short ICMP_checksum(struct finsFrame * ff)
{
	int sum = 0;
	unsigned char *w = ff->dataFrame.pdu;
	int nleft = ff->dataFrame.pduLength;

	if(nleft % 2)  //Check if we've got an uneven number of bytes here, and deal with it accordingly if we do.
	{
		nleft--;  //By decrementing the number of bytes we have to add in
		sum += ((int)((ff->dataFrame).pdu[nleft])) << 8; //And shifting these over, adding them in as if they're the high byte of a 2-byte pair
		//This is as per specification of the checksum from the RFC: "If the total length is odd, the received data is padded with one
	    // octet of zeros for computing the checksum." We don't explicitly add an octet of zeroes, but this has the same result.
	}

	while(nleft > 1) //Could also do nleft > 0 here, same difference
	{
		//Deal with the high and low words of each 16-bit value here. I tried earlier to do this 'normally' by
		//casting the pdu to unsigned short, but the little-vs-big-endian thing messed it all up. I'm just avoiding
		//the whole issue now by treating the values as high-and-low-word pairs, and bit-shifting to compensate.
		sum += (int)(*w++) << 8;  //First one is high word: shift before adding in
		sum += *w++;			  //Second one is low word: just add in
		nleft -= 2;				  //Decrement by 2, since we're taking 2 at a time
	}

	//Fully fill out the data
	for(;;)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);  //Get the sum shifted over added into the current sum
		if(!(sum >> 16))  //Continue this until the sum shifted over is zero
			break;
	}
	return ~((u_short)(sum));  //Return one's complement of the sum
}

//------------------------------------------------------------------------------
// Create a ping reply message (from the ping request message) when we're pinged
//------------------------------------------------------------------------------
void ICMP_ping_reply(struct finsFrame* ff)
{
	//Create new dataframe, copying the old one. Do I have to do this by hand with malloc(),
	//or do either of the copy-frame-to-frame functions work at all? They look like they shouldn't, and neither of them are used anywhere.
	struct finsFrame* ffout = NULL;

	//Copy the finsFrame ff into ffout. Is there a function to do this for us? Because if there isn't, there should be. Use my function for now.
	if(!ICMP_copy_finsFrame(ff, ffout))
		return; //Stop here if it failed

	//Get source and destination IP's from finsFrame
	IP4addr IP_Dest, IP_Src;
	if(metadata_readFromElement(ffout->dataFrame.metaData, "ipsrc", &IP_Src) == CONFIG_FALSE)
	{
		PRINT_DEBUG("ICMP_ping_reply(): Missing data in FINS frame metadata: no source IP");
		return; //Stop here
	}
	if(metadata_readFromElement(ffout->dataFrame.metaData, "ipdst", &IP_Dest) == CONFIG_FALSE)
	{
		PRINT_DEBUG("ICMP_ping_reply(): Missing data in FINS frame metadata: no destination IP");
		return; //Stop here
	}

	//Write our IP to the "ipsrc". Do we actually care about doing this? Or will the ethernet stub handle this properly anyhow? Oh, well.
	//I shall do it.
	metadata_writeToElement(ffout->dataFrame.metaData, "ipsrc", &IP_Dest, CONFIG_TYPE_STRING);

	//Write the original "src IP" to the data as the destination IP
	metadata_writeToElement(ffout->dataFrame.metaData, "ipdst", &IP_Src, CONFIG_TYPE_STRING);

	//Make sure this goes to the right place. Is this what we have to do to send out an ICMP packet?
	ffout->destinationID.id = JINNIID;		//Go to the socket stub (Socket jinni)
	ffout->destinationID.next = NULL;		//I have no idea what this does, so I'll set it to null for now.
	ffout->dataFrame.directionFlag = DOWN;	//Go out (Down the stack)

	//Set the type to be a reply to the received echo.
	ffout->dataFrame.pdu[0] = TYPE_ECHOREPLY;

	//Clear the current checksum
	ffout->dataFrame.pdu[2] = 0;
	ffout->dataFrame.pdu[3] = 0;

	//Calculate the checksum and stick it in
	unsigned short check = ICMP_checksum(ffout);
	//Split it up correctly, of course
	ffout->dataFrame.pdu[2] = (check >> 8);
	ffout->dataFrame.pdu[3] = (check & 0xFF);

	//Send the packet out
	ICMP_send_FF(ffout);
}

//----------------------------------------------------------------------------------------------------------------
// Copy one FINS frame to another. Using my own function here, because the other two that I've seen have PROBLEMS.
//----------------------------------------------------------------------------------------------------------------
int ICMP_copy_finsFrame(struct finsFrame* src, struct finsFrame* dst)
{
	dst = (struct finsFrame *)malloc(sizeof(struct finsFrame));
	dst->dataOrCtrl = src->dataOrCtrl;
	dst->destinationID = src->destinationID;
	//DATA frame
	if(dst->dataOrCtrl == DATA)
	{
		dst->dataFrame.directionFlag = src->dataFrame.directionFlag;
		dst->dataFrame.pduLength = src->dataFrame.pduLength;
		dst->dataFrame.pdu = (char *)malloc(src->dataFrame.pduLength);
		memcpy(dst->dataFrame.pdu,src->dataFrame.pdu,src->dataFrame.pduLength);
		dst->dataFrame.metaData = src->dataFrame.metaData;	//TODO Duz this work?
	}
	//CONTROL frame
	else if(dst->dataOrCtrl == CONTROL)
	{
		dst->ctrlFrame.opcode = src->ctrlFrame.opcode;
		dst->ctrlFrame.paramterID = src->ctrlFrame.paramterID;
		dst->ctrlFrame.paramterValue = src->ctrlFrame.paramterValue;
		dst->ctrlFrame.replyRecord = src->ctrlFrame.paramterValue;
		dst->ctrlFrame.senderID = src->ctrlFrame.senderID;
		dst->ctrlFrame.serialNum = src->ctrlFrame.serialNum;
	}
	else
	{
		PRINT_DEBUG("Unsupported finsFrame type in ICMP_copy_finsFrame(). Should have been either CONTROL or DATA. Dropping...");
		return 0; //Failure
	}
	return 1; //Success
}

//-----------------------------------------------------------------------------
// Create a "Destination Unreachable" ICMP message with data given from the UDP
//-----------------------------------------------------------------------------
void IMCP_create_unreach(struct finsFrame* ff)
{
	int totallen = 0;	//How many bytes we want our ICMP message to be
	struct finsFrame* ffout;	//The final "destination unreachable" finsFrame that we'll send out
	int checksum = 0;

	//So this finsFrame has the IP header and UDP stuff. As per RFC 792 spec, we need the IP header + 64 bits of the UDP datagram.
	//How many bytes is all this?
	totallen = (ff->dataFrame.pdu[0]) & 0x0F;	//Grab the first 8 bits. Header length is in bits 4-7 of this.
	totallen *= 4;	//Since this length is the number of 32-bit words in the header, we multiply by 4 to get the number of bytes
	totallen += 8 + ICMP_HEADER_SIZE;	//The length we want is the length of the IP header + (64 bits = 8 bytes) + 8 byte ICMP header
	//Now that we have the total length, we can create the finsFrame that has the PDU length we want

	ffout = (struct finsFrame *)malloc(sizeof(struct finsFrame));	//Allocate memory for the frame
	ffout->dataOrCtrl = DATA;	//We're sending a data packet here
	ffout->destinationID.id = JINNIID;	//Go to the socket stub
	ffout->destinationID.next = NULL;	//TODO: Still no idea what this does
	ffout->dataFrame.directionFlag = DOWN;	//Out
	ffout->dataFrame.pduLength = totallen;	//Make the total length correct
	ffout->dataFrame.pdu = (char *)malloc(totallen);	//Allocate memory for the data we'll be sticking in
	metadata_create(ffout->dataFrame.metaData);	//TODO: Right?

	//I treat all the ICMP stuff as raw data, rather than encapsulating it in structs, due to working with such structs earlier this summer
	//and running into a ton of little-vs-big-endian issues. Handling the raw data this way is easier for me than remembering to htons()
	//everything, especially because most ICMP headers contain variably-sized data.

	//Fill in the ICMP header data.
	ffout->dataFrame.pdu[0] = TYPE_DESTUNREACH; //set to destination unreachable message
	ffout->dataFrame.pdu[1] = CODE_PORTUNREACH; //MAYBE. TODO: get info about what unreachable code we should here, from the metadata.
	//Clear the checksum and "unused" fields
	memset(ffout->dataFrame.pdu[2], 0, ICMP_HEADER_SIZE - 2);

	//Copy the rest of the data over
	memcpy(ffout->dataFrame.pdu[ICMP_HEADER_SIZE], ff->dataFrame.pdu, totallen - ICMP_HEADER_SIZE);

	//Compute the checksum
	checksum = ICMP_checksum(ffout);
	//And set the checksum field(s)
	ffout->dataFrame.pdu[2] = checksum >> 8;
	ffout->dataFrame.pdu[3] = (checksum & 0xFF);

	//Done! Send out the frame
	ICMP_send_FF(ffout);

}


