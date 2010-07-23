
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
#include "htoi.h"
#include "finstypes.h"



FILE *fromEthernet, *fromTransport,*fromControl;







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
		 (*ff).dataOrCtrl =  (unsigned char)frame[0] -48;
		 (*ff).dataFrame.directionFlag= (unsigned char)frame[1] -48;
		 strncpy(destID,frame + 2,2);
		 destID[2]= '\0';
		 (*ff).destinationID= htoi(destID);


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


		 strcpy((*ff).dataFrame.metaData,"metadata");

	 }
	 else if ( (iSecret <=80) && (iSecret >40) )
	 {
		 fgets(frame, 10000,fromTransport);
		 (*ff).dataOrCtrl =  (unsigned char)frame[0] -48;
				 (*ff).dataFrame.directionFlag = (unsigned char)frame[1] -48;
				 strncpy(destID,frame + 2,2);
				 destID[2]= '\0';
				 (*ff).destinationID= htoi(destID);
/** parsing the destination IP and insert it into the meta data */
						 strncpy(token,frame + 4,2);
						 		 token[2]= '\0';
						 (*ff).dataFrame.metaData[0] = htoi(token);


						 strncpy(token,frame + 6,2);
						 		 token[2]= '\0';
						 (*ff).dataFrame.metaData[1] = htoi(token);

						 strncpy(token,frame + 8,2);
						 		 token[2]= '\0';
						 (*ff).dataFrame.metaData[2] = htoi(token);

						 strncpy(token,frame + 10,2);
						 		 token[2]= '\0';
						 (*ff).dataFrame.metaData[3] = htoi(token);

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
		 (*ff).destinationID = (unsigned char)IPID;
		 (*ff).ctrlFrame.senderID = 11;
		 (*ff).ctrlFrame.opcode =444;
		 (*ff).ctrlFrame.serialNum = 32234;
		 (*ff).ctrlFrame.paramterID=  234;
		 (*ff).ctrlFrame.paramterValue= NULL;
		 (*ff).ctrlFrame.replyRecord=NULL;

	 }  /** End of the if condition based on the random generated value  */


		 free(frame);

}



void IP_testharness_init(char *argv)
/**
* initialize the random number generator
* open the testing files to read from (incoming direction file, outgoing, and control)
*/
{

	/** initialize the random number generator with a random seed: */
	  srand ( time(NULL) );

	char arg_temp1[100];
    strcpy(arg_temp1,argv);

        fromEthernet= fopen (strcat(arg_temp1,"_ethernet_switch_IP"),"r");
        if ( fromEthernet == NULL )
        {
               printf("could not open the ethernet_switch_IP file");
               exit(1);
        }

        strcpy(arg_temp1,argv);

        fromTransport = fopen (strcat(arg_temp1,"_transport_switch_IP"),"r");
        if (  fromTransport == NULL )
        {
               printf( "Cannot open the transport_switch_IP file" );
               fclose (fromEthernet);
            //   fclose( fromTransport );
               exit(1);
        }
        strcpy(arg_temp1,argv);
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

