#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "finstypes.h"

//the goal of the following functions is to generate fins control frames and populate a file

struct finsFrame GenFrame(unsigned char senderId, unsigned char destinationID, unsigned short int Opcode, struct tableRecord *E);


/** @brief Populates a binary file with artifically generated FINS control frames, The function can be used to create randomly generated FINS control frame (inbound or outbound) for any module

@param FileName is the name of the file
 */


void PopulateFile(char *fileName)
{


	int recordsNum; /**<refers to the number of records created*/
	int J; /**<refers to the iterations*/
	int rType; /**<refers to the operation type (e.g. read reply, write confirm etc.)*/

	unsigned char SId, DId;/**<refer to the module ID of the destination (or source) */

	struct finsFrame testFrame;


	FILE *ptrMyfile;

	ptrMyfile=fopen(fileName,"w");
	if (!ptrMyfile)                               //open file for writing , exit if it cannot open
	{
		printf("Unable to open file!");
		exit (0);
	}


	printf("How many records to create and load into the file?\n");

	scanf("%d", &recordsNum);


	srand ( (unsigned)time (0) );


	for (J=0;J<recordsNum;J++)
	{


		rType = rType%4 + 1;


		DId = (rand()%6+1)*11;
		SId = (rand()%6+1)*11;

		if (SId==DId)
		{
			while (SId==DId)
				DId = (rand()%6+1)*11;

		}

		/*Once a random source or destination module have been chosen it is time to generate FINS frame
    The following conditions specify which of the actions has to be carried out
		 */

		if (rType == 1)  // read parameter request

			testFrame= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 111,NULL);


		if (rType==2) //read parameter reply
			testFrame= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 222,NULL);

		if (rType==3) //write parameter request
			testFrame= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 333,NULL);

		if (rType==4) //write confirmation
			testFrame= GenFrame((unsigned char) SId, (unsigned char) DId, (unsigned short int) 444,NULL);


		fwrite(&testFrame, sizeof(struct finsFrame), 1, ptrMyfile);     //the FINS control frame is then written to the opened binary file as a structure


	}//generate for all the records (ends for loop)





	fclose(ptrMyfile);    // closes the file


	//the following code is only to test whether the written file can be printed on screen or not.

	ptrMyfile=fopen(fileName,"r");

	if (ptrMyfile)

	{
		for (J=0;J<recordsNum;J++){
			fread(&testFrame,sizeof(struct finsFrame),1,ptrMyfile);
			printf("Sender ID : %d\n",testFrame.ctrlFrame.senderID);
			printf("Paramter ID : %d\n",testFrame.ctrlFrame.paramterID);

			printf("Serial Number : %d\n",testFrame.ctrlFrame.serialNum);
			printf("OpCode : %d\n",testFrame.ctrlFrame.opcode);

			printf("Destination ID : %d\n\n",testFrame.destinationID.id);}
	}
	fclose(ptrMyfile);

};// end function



/** @brief Throws back finsFrame based on its input parameters 
@param senderId is the identity of the sending module
@param destinationID is the identity of the receiving module
@param opcode is the exact operation being carried out (e.g. write parameter request or read parameter reply)
@param E is a table record that is passed and is used only in case of a query request
 */


struct finsFrame GenFrame(unsigned char senderId, unsigned char destinationID, unsigned short int Opcode, struct tableRecord *E)
{


	struct finsCtrlFrame cFrame;
	struct finsFrame outgoingFrame;
	float *f;

	cFrame.senderID = senderId;
	cFrame.opcode = Opcode;


	//serial number, parameter value and parameter ID are randomly generated

	cFrame.serialNum = rand() ;


	cFrame.paramterID = rand();


	f = (float *) rand();

	cFrame.paramterValue = f;


	if (Opcode==QUERYREPLY)   //if the opcode corresponds to a query reply, the FINS control frame makes a reference to a reply record
		cFrame.replyRecord = E;
	else
		cFrame.replyRecord = NULL;

	outgoingFrame.ctrlFrame=cFrame;
	outgoingFrame.dataOrCtrl = CONTROL;

	outgoingFrame.destinationID.id = destinationID;
	outgoingFrame.destinationID.next = NULL;

	return outgoingFrame;

};


