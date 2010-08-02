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







int testcreator(int argc, char *argv[])

{
        FILE *ip_in, *transport_out;
        FILE *udp_in, *udpsocket_out;
        FILE *tcp_in, *tcpsocket_out;
        FILE *tcp_out, *udp_out;

        FILE *ft;


        char buffer[10];
        int intermediate;
        unsigned char *frame;
        unsigned char metadata[]="metadata";
        metadata[9]='\0';
        unsigned char *stringToWrite;
        unsigned char arg_temp1[100];

        int counter= 0;




        if (argc != 3)
       {
           printf("Number of entered arguments are wrong \n");
           printf("%s <file name> <number of captured packets>", argv[0]);

           exit(1);
       }

/** ..............Prepare IP Incoming Direction ..........*/

		strcpy(arg_temp1,argv[1]);
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
/** ..............Prepare IP Outgoing Direction ..........*/
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
/** ..................................................................*/
/** .................Prepare UDP Incoming direction...............*/

	    strcpy(arg_temp1,argv[1]);
        udp_in = fopen (strcat(arg_temp1,"_UDPIN"),"r");
                if ( udp_in == NULL )
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

                   exit(1);
            }

        counter=0;
        while( !feof(udp_in) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000,udp_in);


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) UP);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
			/** Check if the datagram is UDP or TCP */


        			sprintf(buffer,"%x",(unsigned char)UDPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose ( udp_in );
        fclose (ft);
/** .......................................................*/
/** .................Prepare UDP Outgoing direction...............*/

	    strcpy(arg_temp1,argv[1]);
        udp_out = fopen (strcat(arg_temp1,"_UDPSOCKETOUT"),"r");
                if ( udp_out == NULL )
                {
                       printf("coud not open the file UDPIN");
                       exit(1);
                }
  		strcpy(arg_temp1,argv[1]);
            ft = fopen (strcat(arg_temp1,"_socket_switch_UDP"),"w");
            if (  ft == NULL )
            {
                   printf( "Cannot open target file" );
                   fclose (udp_out);

                   exit(1);
            }

        counter=0;
        while( !feof(udp_out) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000,udp_out);
        			//puts("a7a fe kees1");


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) DOWN);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
			/** Check if the datagram is UDP or TCP */


        			sprintf(buffer,"%x",(unsigned char)UDPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose ( udp_out );
        fclose (ft);
/** .......................................................*/



/** ..................................................................*/
/** .................Prepare TCP Incoming direction...............*/

	    strcpy(arg_temp1,argv[1]);
        tcp_in = fopen (strcat(arg_temp1,"_TCPIN"),"r");
                if ( tcp_in == NULL )
                {
                       printf("coud not open the file _IN");
                       exit(1);
                }
  		strcpy(arg_temp1,argv[1]);
            ft = fopen (strcat(arg_temp1,"_IP_switch_TCP"),"w");
            if (  ft == NULL )
            {
                   printf( "Cannot open target file" );
                   fclose (tcp_in);

                   exit(1);
            }

        counter=0;
        while( !feof(tcp_in) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000,tcp_in);


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) UP);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
			/** Check if the datagram is UDP or TCP */


        			sprintf(buffer,"%x",(unsigned char)TCPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose ( tcp_in );
        fclose (ft);
/** .......................................................*/
/** .................Prepare UDP Outgoing direction...............*/

	    strcpy(arg_temp1,argv[1]);
        tcp_out = fopen (strcat(arg_temp1,"_TCPSOCKETOUT"),"r");
                if (  tcp_out == NULL )
                {
                       printf("coud not open the file UDPIN");
                       exit(1);
                }
  		strcpy(arg_temp1,argv[1]);
            ft = fopen (strcat(arg_temp1,"_socket_switch_TCP"),"w");
            if (  ft == NULL )
            {
                   printf( "Cannot open target file" );
                   fclose ( tcp_out);

                   exit(1);
            }

        counter=0;
        while( !feof( tcp_out) )
        {

					frame=   malloc(10000);
					stringToWrite = (unsigned char *) malloc(10000);
        			fgets(frame,10000, tcp_out);
        			//puts("a7a fe kees1");


        			sprintf(buffer,"%d",(unsigned char)DATA);
        			strcpy(stringToWrite,buffer);	// data/ctrl flag is data=0
        			sprintf(buffer,"%d",(unsigned char) DOWN);
        			strcat(stringToWrite,buffer);  // direction flag is UP = 0
			/** Check if the datagram is UDP or TCP */


        			sprintf(buffer,"%x",(unsigned char)TCPID);
        			strcat(stringToWrite,buffer);	// Destination address is 22 (the IP module)
        			strcat(stringToWrite,frame);

        		fputs(stringToWrite,ft);

        		counter++;


        } // end of while loop reading the file frame by frame
        printf("\n %d \n",counter);
        free(stringToWrite);
        free(frame);

        fclose (  tcp_out);
        fclose (ft);
/** .......................................................*/




        return (1);
} // end of the main function

