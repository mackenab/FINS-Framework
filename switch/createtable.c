#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "finstypes.h"


/** @brief sends back tableRecord based on its input parameters
@param senderId is the identity of the sending module
@param destinationID is the identity of the receiving module
@param vci
@param directionFlag is whether it is in or out
 */


struct tableRecord GenRecord(unsigned char sourceId, unsigned char destinationID, unsigned char VCI, unsigned char directionFlag);


/** @brief reads from a file which has stored a table of records

@param fileName is the name of the file
 */

struct tableRecord* ReadTableFile(char* fileName)
		{

	struct tableRecord *ptrCT;

	FILE *fp;



	int i,j;

	struct tableRecord *pCT, *p2CT, ptemp; /**<These variables are used to store
	the read struct data from the file*/


	if((fp=fopen(fileName, "r")) == NULL) {
		printf("Cannot open file.\n");
		exit(1);
	}


	j = 0;
	i = 0;


	while (!feof(fp))
	{

		//read line from file



		pCT = (struct tableRecord *) malloc (sizeof(struct tableRecord));



		fread(&ptemp,sizeof(struct tableRecord),1,fp);


		pCT->sourceID = ptemp.sourceID;
		pCT->destinationID = ptemp.destinationID;
		pCT->vci = ptemp.vci;
		pCT->directionFlag = ptemp.directionFlag;

		pCT->next = NULL;


		if (j==0)
		{ p2CT = pCT;
		ptrCT = pCT;
		}
		else
		{

			p2CT->next = pCT;
			p2CT = pCT;

		}


		j=j+1;


	}


	return ptrCT;
		}



/** @brief Populates a binary file with artificially generated table records, The function can be used to create randomly generated FINS control frame (inbound or outbound) for any module

@param FileName is the name of the file
 */

void ProduceTableFile(char *FileName)
{


	int recordsNum, J; /**< This is a variables for iterating through number of records <recordsNum>*/
	unsigned char SId, DId, Vci, InOut;

	struct tableRecord Rec;


	FILE *fp;

	fp=fopen(FileName,"w");
	if (!fp)                               //open file for writing , exit if it cannot open
	{
		printf("Unable to open file!");
		exit (0);
	}


	printf("How many records to create ?\n");

	scanf("%d", &recordsNum);

	srand ( (unsigned)time (0) );


	for (J=0;J<recordsNum-1;J++)
	{


		SId = (rand()%6+1)*11;                            //22 is the address of sourceID (i.e. IP module)
		DId = (rand()%6+1)*11; //random module IDs being generated

		if (SId==DId)   //this loop ensures that the destination and source ID are not the same
		{
			SId = (rand()%6+1)*11;

			while (SId==DId)
				SId = (rand()%6+1)*11;

		}


		Vci = (rand());
		InOut = (rand()%2);

		printf("\n");
		fflush(stdout);


		Rec= GenRecord((unsigned char) SId, (unsigned char) DId, (unsigned char) Vci, (unsigned char) InOut);



		fwrite(&Rec, sizeof(struct tableRecord), 1, fp);     //the FINS control frame is then written to the opened binary file as a structure


	}//generate for all the records (ends for loop)



	fclose(fp);    // closes the file

}


/** @brief sends back tableRecord based on its input parameters
@param senderId is the identity of the sending module
@param destinationID is the identity of the receiving module
@param vci
@param directionFlag is whether it is in or out
 */


struct tableRecord GenRecord(unsigned char sourceId, unsigned char destinationID, unsigned char vci, unsigned char directionFlag)
{

	struct tableRecord B;

	B.destinationID = destinationID;
	B.sourceID = sourceId;
	B.vci = vci;
	B.directionFlag = directionFlag;
	B.next = NULL;

	return B;

}


