/*
 * finstypes.c
 *
 *  Created on: Jul 21, 2011
 *      Author: dell-kevin
 */


#include "finstypes.h"
#include <stdio.h>
#include <stdlib.h>

int serializeCtrlFrame (struct finsFrame * ff, unsigned char **buffer)
/* serializes a fins control frame for transmission to an external process
 * - pass it the frame (finsFrame) and it will fill in the pointer to the frame, uchar*
 * -- and return the length of the array (return int);
 * - this is used to send a control frame to an external app
 * - we can't send pointers outside of a process
 * - called by the sender
 */
{
	// MST: I think we only need to worry about a subset of these, mainly the read/read reply/set
	// types. For the others, why don't you serialize part of the info and send that or
	// just not do anything -- use your best judgement.
	// We probably won't know how all of the information is stored unless we go nuts
	// and start including a whole bunch of stuff -- this is where it would be great
	// to have objects that could serialize themselves. Oh well.

	//switch (finsFrame->opcode)
	// CTRL_READ_PARAM: ...
	// CTRL_READ_PARAM_REPLY: ...
	// CTRL_ALERT: ...
	// CTRL_ERROR: ...
	// CTRL_SET_PARAM:...
	// CTRL_EXEC: ...
	// CTRL_EXEC_REPLY: ...
	// default: ...

	//load buffer

//	if(sizeof(buffer) < sizeof(itoa(ff->dataOrCtrl) + ff->destinationID.id + ff->ctrlFrame.name + itoa(ff->ctrlFrame.opcode) + itoa(ff->ctrlFrame.senderID) + itoa(ff->ctrlFrame.serialNum) + sizeof((char)ff->ctrlFrame.data)))

	PRINT_DEBUG("In serializeCtrlFrame!")



	//PRINT_DEBUG("\ntemp_buffer: %s\nsize of temp_buffer: %d",temp_buffer,sizeof(temp_buffer));

	//initialize buffer

        int buf_size = strlen((char *)ff->ctrlFrame.data) + strlen(ff->ctrlFrame.name) + 3*sizeof(unsigned char) + 2*sizeof(int) + sizeof(unsigned short int) + sizeof(unsigned int);

        //PRINT_DEBUG("SIZE OF BUF_SIZE = %d", buf_size);

	*buffer = (unsigned char *) malloc(buf_size);

	unsigned char * temporary = *buffer;

	//DATA OR CONTROL
	memcpy((unsigned char *)*buffer,&(ff->dataOrCtrl),sizeof(unsigned char));
        //PRINT_DEBUG("\nbuffer1:%s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//DESTINATION ID
	memcpy((unsigned char *)*buffer,&(ff->destinationID.id),sizeof(unsigned char));
        //PRINT_DEBUG("buffer2:%s",*buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//send size of name first
	int temp = strlen(ff->ctrlFrame.name);
	memcpy((unsigned char *)*buffer,&temp,sizeof(int));

	//increment pointer
	*buffer += sizeof(int);

	//NAME
	//strcat((unsigned char *)*buffer, ff->ctrlFrame.name);
	memcpy((unsigned char *)*buffer,ff->ctrlFrame.name,temp);
        //PRINT_DEBUG("buffer3:%s", *buffer);

	//increment pointer
	*buffer += temp;

	//OPCODE
//	strncat((unsigned char *)*buffer, (unsigned char *) (&(htonl(ff->ctrlFrame.opcode))), sizeof(int));
	memcpy((unsigned char *)*buffer,&(ff->ctrlFrame.opcode),sizeof(unsigned short int));
        //PRINT_DEBUG("buffer4 = %s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned short int);

	//SENDERID
	//strncat((unsigned char *)*buffer, &(ff->ctrlFrame.senderID),sizeof(unsigned char *));
	memcpy((unsigned char *)*buffer,&(ff->ctrlFrame.senderID),sizeof(unsigned char ));
        //PRINT_DEBUG("buffer5:%s", *buffer);

	//increment pointer
	*buffer += sizeof(unsigned char);

	//SERIALNUM
	memcpy((unsigned char *)*buffer,&(ff->ctrlFrame.serialNum),sizeof(unsigned int));
        //PRINT_DEBUG("buffer6: %s", *buffer);

	*buffer += sizeof(unsigned int);

	//fill in known/common parts
	switch (ff->ctrlFrame.opcode)
	{
	case CTRL_READ_PARAM:
		break;

	case CTRL_READ_PARAM_REPLY:
		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//send size of data first
		temp = strlen((char *)(ff->ctrlFrame.data));
		memcpy((unsigned char *)*buffer,&temp,sizeof(int));

		//increment buffer
		*buffer += sizeof(int);

		//send data itself
		memcpy(*buffer,(char *)(ff->ctrlFrame.data),temp);
                //PRINT_DEBUG("CSP: buffer7 = %s, temp = %d, data = %s", *buffer,temp,((char *)(ff->ctrlFrame.data)));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;

	}

	//decrement pointer
	*buffer = temporary;
	PRINT_DEBUG("Final value of buffer:%s",*buffer)

        return strlen(*buffer);
}

struct finsFrame* unserializeCtrlFrame (unsigned char * buffer, int length)
/* does the opposite of serializeCtrlFrame; used to reconstruct a controlFrame
 * - pass it the byte array and the length and it will give you a pointer to the
 * -- struct.
 * - called by the receiver
 */
{
	/* again, we'll probably only have to deal with a subset of the types here.
	 * I'm OK with just doing what we know we'll pass back and forth and we
	 * can worry about the rest later. -- MST
	 */
	PRINT_DEBUG("In unserializeCtrlFrame!")

	struct finsFrame * ff = malloc(sizeof(struct finsFrame));

//	PRINT_DEBUG("\nThe value of buffer = %s", buffer,length);

	//DATA OR CONTROL
	memcpy(&(ff->dataOrCtrl),(unsigned char *)buffer,sizeof(unsigned char));
        //PRINT_DEBUG("buffer1 = %s, dataOrCtrl = %d", buffer,ff->dataOrCtrl);
	buffer += sizeof(unsigned char);

	//DESTINATION ID
	memcpy(&(ff->destinationID),(unsigned char *)buffer,sizeof(unsigned char));
        //PRINT_DEBUG("buffer2 = %s, destination = %d", buffer,ff->destinationID.id);
	buffer += sizeof(unsigned char);

	//NAME
	//retrieve size of name first
	int temp = 0;
	memcpy(&temp,(unsigned char *)buffer,sizeof(int));
	buffer += sizeof(int);

        //PRINT_DEBUG("temp = %d", temp);

	//retrieve the name
	ff->ctrlFrame.name = malloc(temp);
	memcpy(ff->ctrlFrame.name,(unsigned char *)buffer,temp);
        //PRINT_DEBUG("buffer3 = %s, name = %s", buffer,ff->ctrlFrame.name);
	buffer += temp;

	//OPCODE
	memcpy(&(ff->ctrlFrame.opcode),(unsigned char *)buffer,sizeof(unsigned short int));
        //PRINT_DEBUG("buffer4 = %s, opcode = %d", buffer,ff->ctrlFrame.opcode);
        buffer += sizeof(unsigned short int);

	//SENDERID
	memcpy(&(ff->ctrlFrame.senderID),(unsigned char *)buffer,sizeof(unsigned char));
        //PRINT_DEBUG("buffer5 = %s, senderID = %d", buffer,ff->ctrlFrame.senderID);
	buffer += sizeof(unsigned char);

	//SERIALNUM
	memcpy(&(ff->ctrlFrame.serialNum),(unsigned char *)buffer,sizeof(unsigned int));
        //PRINT_DEBUG("buffer6 = %s, serialNum = %d", buffer,ff->ctrlFrame.serialNum);
	buffer += sizeof(unsigned int);

	//DATA
	//fill in known/common parts
	switch (ff->ctrlFrame.opcode)
	{
	case CTRL_READ_PARAM:

		break;

	case CTRL_READ_PARAM_REPLY:

		break;

	case CTRL_ALERT:

		break;

	case CTRL_ERROR:

		break;

	case CTRL_SET_PARAM:
		//retrieve size of data first
		temp = 0;
		memcpy(&temp,(unsigned char *)buffer,sizeof(int));

                //PRINT_DEBUG("CSP: buffer6.25 = %s", buffer);

		//increment buffer
		buffer += sizeof(int);
                //PRINT_DEBUG("CSP: buffer6.5 = %s", buffer);

		//retrieve data itself
		ff->ctrlFrame.data = malloc(temp);
		memcpy((char *)(ff->ctrlFrame.data),buffer,temp);
                //PRINT_DEBUG("CSP: buffer7 = %s, temp = %d, data = %s", buffer, temp,(char *)(ff->ctrlFrame.data));
		break;

	case CTRL_EXEC:

		break;

	default:
		return 0;
		break;
	}

	return ff;
}
