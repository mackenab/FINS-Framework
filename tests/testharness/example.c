/*
 * @file <example1.c> example on how to use the full testharness
 *
 *  @date Aug 3, 2010
 *  @author Abdallah Abdallah
 */




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "IP_testharness.h"




int main(int argc, char *argv[])

{



int i=0;
unsigned int j=0;
char filename[100];
struct finsFrame *ff;


ff = (struct finsFrame *) malloc (sizeof(struct finsFrame ));


	if (argc !=3)
	{
	puts("Wrong Number of input arguments");
	exit(1);
	}


strcpy(filename,argv[1]);

IP_testharness_init(argc, argv);


for (i=1;i<=5;i++)
{

	printf("\n.... Fins Frame # %d ......\n",i);

	InputQueue_Read(ff);
/** Check if the received frame is not null */
	if (ff != NULL)
	{
		/** check if it contains FDF or FCF */
	if ((*ff).dataOrCtrl== DATA)
		/** Data Frame */
	{

/** print the PDU contents for checking purposes */
		j=0;
			printf("PDU length *%u*\n",(*ff).dataFrame.pduLength);
			while (j< (*ff).dataFrame.pduLength)
			{
			printf("%u",(*ff).dataFrame.pdu[j]);
			j=j+1;
			}
		printf("\n");
		unsigned int ipdest=0;
		char *recet;
		metadata_print(&(*ff).dataFrame.metaData);
		metadata_read2(&(*ff).dataFrame.metaData,"ipDest",&ipdest);
		metadata_read2(&(*ff).dataFrame.metaData,"ipSrc",&recet);

		PRINT_DEBUG("%d",ipdest);
		PRINT_DEBUG("%s",recet);

	}

	else				/** Control Frame */
	{

		printf("\n control Branch \n");
		printf("\n%u,%u,%u,%d\n",(*ff).dataOrCtrl,(*ff).destinationID.id ,(*ff).ctrlFrame.senderID,(*ff).ctrlFrame.opcode);
		printf("\n%d,%d\n",(*ff).ctrlFrame.paramterID,(*ff).ctrlFrame.serialNum );
	}
	}
	else
	{
		printf("the fins frame pointer has been assigned to null");

	} /** End if checking the finsframe incoming pointer */

} /** End of the for loop */

free(ff);
IP_testharness_terminate();

return (0);

}
