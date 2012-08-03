#include <stdio.h>
#include <stdlib.h>
#include "finstypes.h"
#include "popfins.h"
#include "ctestharness.h"


/*this main function initializes a binary file with artificially created FINS control frame
then this file is read and printed
 */


int main(int argc, char *argv[])
{

	int J; /**<J is a variable for counting iterations*/
	int NumFiles; /**<NumFiles is the total number of files*/
	struct finsFrame rcvdFrame;


	char *fileName;

	fileName = argv[1];//file name...it can be changed

	PopulateFile(fileName); //generate control frames and store them within the file named after the string



	printf("\n\n \n Initializing and Reading from file\n\n");

	InitTestHarn(fileName); //open file


	printf("How many records to read from the file \n");
	scanf("%d", &NumFiles);


	for (J=0;J<NumFiles;J++)
	{

		{
			rcvdFrame = GetFrame();

			printf("Sender ID : %d\n", rcvdFrame.ctrlFrame.senderID);
			printf("Paramter ID : %d\n",rcvdFrame.ctrlFrame.paramterID);

			printf("Serial Number : %d\n",rcvdFrame.ctrlFrame.serialNum);
			printf("OpCode : %d\n",rcvdFrame.ctrlFrame.opcode);

			printf("Destination ID : %d\n\n", rcvdFrame.destinationID.id);
		}

	}

	TermTestHarn ();


	return 0;
}
