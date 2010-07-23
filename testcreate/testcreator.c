/**
 * @file testcreator.c
 *
 * @date Jun 13, 2010
 * @author: Abdallah Abdallah
 */





#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "finstypes.h"


#define	MAX_PDU_SIZE	3000
#define	MAX_metaData_SIZE	200





void main(int argc, char *argv[])

{
        FILE *ip_in, *transport_out;
        FILE *trans_in, *socket_out;
        FILE *ft;
        FILE *ft1;
        FILE *ft2;


        char buffer[10];
        int intermediate;
        unsigned char *frame;
        unsigned char metadata[]="metadata";
        metadata[9]='\0';
        unsigned char *network_protocol_type;
        unsigned char *stringToWrite;
        unsigned char arg_temp1[100];
        int protocol_is_ip;
        int counter= 0;


        strcpy(arg_temp1,argv[1]);

       if (argc != 2)
       {
           printf("Number of entered arguments are wrong \n");
           printf("%s <file name> <number of captured packets", argv[0]);

           exit(1);
       }

        ip_in = fopen (strcat(arg_temp1,"_IPIN"),"r");
        if ( ip_in == NULL )
        {
               printf("coud not open the file IPIN");
               exit(1);
        }


        strcpy(arg_temp1,argv[1]);
        ft = fopen (strcat(arg_temp1,"_ethernet_switch_IP"),"w");
        if (  ft == NULL )
        {
               printf( "Cannot open target file" );
               fclose (ip_in);
               fclose( ft );
               exit(1);
        }

        strcpy(arg_temp1,argv[1]);


        while( !feof(ip_in) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000,ip_in);
        			//puts("a7a fe kees1");


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) UP);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
        			sprintf(buffer,"%x",(unsigned char)IPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose ( ip_in );
        fclose (ft);
/** ...............................................................*/

        transport_out = fopen (strcat(arg_temp1,"_transportOUT"),"r");
            if ( transport_out== NULL )
            {
                   printf("coud not open the file transport out");
                   exit(1);
            }

            strcpy(arg_temp1,argv[1]);
            ft = fopen (strcat(arg_temp1,"_transport_switch_IP"),"w");
            if (  ft == NULL )
            {
                   printf( "Cannot open target file" );
                   fclose (transport_out);
                   fclose( ft );
                   exit(1);
            }


          counter= 0;


            while( !feof(transport_out) )
            {

		frame=  (unsigned char *) malloc(10000);

        stringToWrite = (unsigned char *) malloc(10000);

        fgets(frame,10000,transport_out);


		sprintf(buffer,"%d",(unsigned char)DATA);
		strcpy(stringToWrite,buffer);	// data/ctrl flag is data =0
		sprintf(buffer,"%d",(unsigned char)DOWN);
		strcat(stringToWrite,buffer);  // direction flag is down = 1
		sprintf(buffer,"%x",(unsigned char)IPID);
		strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)

        strcat(stringToWrite,frame);
        fputs(stringToWrite,ft);
        counter++;

            } // end of while loop reading the file packet by packet
            printf("\n %d \n",counter);

		fclose(transport_out);
		fclose(ft);

        free (frame);
        free (stringToWrite);

    /** .......................................................*/

	    strcpy(arg_temp1,argv[1]);
        ip_in = fopen (strcat(arg_temp1,"_IPIN"),"r");
                if ( trans_in == NULL )
                {
                       printf("coud not open the file _IN");
                       exit(1);
                }
  		strcpy(arg_temp1,argv[1]);
            ft = fopen (strcat(arg_temp1,"_IP_switch_UDP"),"w");
            if (  ft == NULL )
            {
                   printf( "Cannot open target file" );
                   fclose (udp_in);
                   fclose( ft );
                   exit(1);
            }

        counter=0;
        while( !feof(trans_in) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000,trans_in);
        			//puts("a7a fe kees1");


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) UP);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
/** Check if the datagram is UDP or TCP */


        			sprintf(buffer,"%x",(unsigned char)IPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose ( ip_in );
        fclose (ft);












        return;
} // end of the main function

