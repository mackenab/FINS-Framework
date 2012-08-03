
/**
 * @file IP_testharness.c
 *
 * @date Jun 14, 2010
 * @brief Testharness with both FCF and FDF
 * @author Abdallah Abdallah
 */


#include <stdio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include <netinet/in.h>

#include "htoi.h"
#include "myanalyzer.h"
#include "testcreator.h"
#include "finstypes.h"
#include "metadata.h"



FILE *fromEthernet, *fromTransport,*fromControl;




void collectIP(char *frame, unsigned char *meta);



void InputQueue_Read (struct finsFrame *ff)
{
	int iSecret;
	char *frame;
	frame=(char *)malloc(10000);
	unsigned int frame_length;
	unsigned int frame_counter,PDU_counter;
	char destID[3];
	char token[3];




	/** generate random number: */
	 iSecret = rand() % 100 + 1;
	 printf("\nGenerated Random Number #%d# \n",iSecret);
	 if ( iSecret < 40 )
	 {
		 fgets(frame, 10000,fromEthernet);
		 (*ff).dataOrCtrl =  DATA;
		 (*ff).dataFrame.directionFlag= UP;
		 strncpy(destID,frame + 2,2);
		 destID[2]= '\0';
		 (*ff).destinationID.id= htoi(destID);
		 (*ff).destinationID.next= NULL;


		 frame_length= strlen(frame+4)-1;
		 (*ff).dataFrame.pdu= (unsigned char *) malloc(frame_length/2 );
		 PDU_counter=0;
		 frame_counter=0;

		 while (frame_counter < frame_length)
		 {
			 strncpy(token,(frame+4)+frame_counter,2);
			 token[2]= '\0';
			 ((*ff).dataFrame.pdu[PDU_counter] ) = htoi(token);
			//printf("%u",(*ff).PDU[PDU_counter]);
			 frame_counter = frame_counter +2;
			 PDU_counter = PDU_counter +1;

		 }
		(*ff).dataFrame.pduLength = PDU_counter;

		metadata metaX;
		metadata_create(&metaX);
		metadata_create(&(ff->dataFrame).metaData);

		char *toBeWritten;
		toBeWritten = (char *)malloc(10);
		strcpy(toBeWritten,"ethermeta");


		metadata_write(&metaX, "metadata",toBeWritten, META_TYPE_STRING);
		metadata_copy(&(ff->dataFrame).metaData,&metaX);
		metadata_destroy(&metaX);

		 //strcpy((*ff).dataFrame.metaData,"metadata");

	 }
	 else if ( (iSecret <=80) && (iSecret >40) )
	 {
		 fgets(frame, 10000,fromTransport);
		 (*ff).dataOrCtrl =  (unsigned char)frame[0] -48;
				 (*ff).dataFrame.directionFlag = (unsigned char)frame[1] -48;
				 strncpy(destID,frame + 2,2);
				 destID[2]= '\0';
				 (*ff).destinationID.id= htoi(destID);
				struct in_addr *ipDest;
				ipDest= (struct in_addr *)malloc(sizeof(struct in_addr));
				unsigned char meta[5];
/** parsing the destination IP and insert it into the meta data */
				collectIP(frame,meta);


				ipDest = (struct in_addr *)meta;

		metadata metaX;
		metadata_create(&metaX);
		metadata_create(&(ff->dataFrame).metaData);


		PRINT_DEBUG("%d",(*ipDest).s_addr);
		metadata_write(&metaX, "ipDest",&(ipDest->s_addr), META_TYPE_INT);


		metadata_write(&metaX, "ipSrc","dsadasds", META_TYPE_STRING);

		metadata_copy(&(ff->dataFrame).metaData,&metaX);
		metadata_destroy(&metaX);

/** .................................................................*/

				 frame_length= strlen(frame+12)-1;
				 (*ff).dataFrame.pdu= (unsigned char *) malloc(frame_length/2 );
				 PDU_counter=0;
				 frame_counter=0;

				 while (frame_counter < frame_length)
				 {
					 strncpy(token,(frame+12)+frame_counter,2);
					 token[2]= '\0';
					 ((*ff).dataFrame.pdu[PDU_counter] ) = htoi(token);
					 frame_counter = frame_counter +2;
					 PDU_counter = PDU_counter +1;

				 }
				(*ff).dataFrame.pduLength = PDU_counter;




	 }
	 else  /** Get control frames from the control file */
	 {
		 /** fake control until Amaar gets done */
		 (*ff).dataOrCtrl =(unsigned char)CONTROL;
		 (*ff).destinationID.id = (unsigned char)IPID;
		 (*ff).ctrlFrame.senderID = 11;
		 (*ff).ctrlFrame.opcode =444;
		 (*ff).ctrlFrame.serialNum = 32234;
		 (*ff).ctrlFrame.paramterID=  234;
		 (*ff).ctrlFrame.paramterValue= NULL;
		 (*ff).ctrlFrame.replyRecord=NULL;

	 }  /** End of the if condition based on the random generated value  */


		 free(frame);

}



void IP_testharness_init(int argc, char *argv[])
/**
* initialize the random number generator
* open the testing files to read from (incoming direction file, outgoing, and control)
*/
{

	if (!myanalyzer(argc, argv) )
	{
		printf ("\n Analyzing the wireshark file failed \n");
		exit(1);
	}

	if(!testcreator(argc,argv))
	{
		printf ("\n Failed to creat the test files \n");
		exit(1);
		}


	/** initialize the random number generator with a random seed: */
	  srand ( time(NULL) );

	char arg_temp1[100];
	strcpy(arg_temp1,argv[1]);

        fromEthernet= fopen (strcat(arg_temp1,"_ethernet_switch_IP"),"r");
        if ( fromEthernet == NULL )
        {
               printf("could not open the ethernet_switch_IP file");
               exit(1);
        }

        strcpy(arg_temp1,argv[1]);

        fromTransport = fopen (strcat(arg_temp1,"_transport_switch_IP"),"r");
        if (  fromTransport == NULL )
        {
               printf( "Cannot open the transport_switch_IP file" );
               fclose (fromEthernet);
            //   fclose( fromTransport );
               exit(1);
        }
        strcpy(arg_temp1,argv[1]);
        fromControl = fopen (strcat(arg_temp1,"_control_IP"),"r");
        if (  fromControl == NULL )
                {
                       printf( "Cannot open the fake Control file" );
                       fclose (fromEthernet);
                       fclose( fromTransport );
              //         fclose(fromControl);
                       exit(1);
                }




}


void IP_testharness_terminate()
/** Close the opened files before exiting the testharness */
{

fclose (fromEthernet);
fclose (fromTransport);
fclose (fromControl);


}


void collectIP(char *frame, unsigned char *meta)
{
	char token[3];

 					strncpy(token,frame + 4,2);
						 		 token[2]= '\0';
						 meta[0] = htoi(token);
						 PRINT_DEBUG("%u",meta[0]);

						 strncpy(token,frame + 6,2);
						 		 token[2]= '\0';
						 meta[1] = htoi(token);
						 PRINT_DEBUG("%u",meta[1]);

						 strncpy(token,frame + 8,2);
						 		 token[2]= '\0';
						meta[2] = htoi(token);
						PRINT_DEBUG("%u",meta[2]);
						 strncpy(token,frame + 10,2);
						 		 token[2]= '\0';
						 meta[3] = htoi(token);
						 PRINT_DEBUG("%u",meta[3]);
						 meta[4]='\0';
//unsigned long x =IP4_ADR_P2N(meta[0],meta[1],meta[2],meta[3]);
//				 PRINT_DEBUG("%d",x);


return;
}

