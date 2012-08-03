/*
 * testrun.c
 *
 *  Created on: Aug 5, 2010
 *      Author: Abdallah Abdallah
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>

// Required for forking
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include <pthread.h>
#include <pcap.h>

#include "finstypes.h"
#include "finsdebug.h"
#include "udp.h"
#include "IP4.h"
#include "wifimod.h"

#define DEBUG
#define ERROR

IP4addr my_ip_addr = IP4_ADR_P2N(192,168,1,28);
IP4addr my_mask = IP4_ADR_P2N(255, 255, 255, 0);
struct ip4_routing_table* routing_table;
struct ip4_stats stats;

struct udp_statistics udpStat;



/* packet inject handle */
pcap_t *inject_handle;

/* packet capture handle */
pcap_t *capture_handle;


//void main(){
//	while(1){
//		udp_get_FF();
//	}
//}

/* checksum test */
//int main() {
//
//	struct udp_packet packet2;
//	struct udp_metadata_parsed pseudoheader2;
//	struct udp_packet* packet_ptr;
//	struct udp_metadata_parsed* pseudoheader_ptr;
//	unsigned short checksum = 0;
//
//
//	packet2.u_src = 1087;
//	packet2.u_dst = 13;
//	packet2.u_len = 15;
//	pseudoheader2.u_pslen = 15;
//	pseudoheader2.u_prcl = 17;
//	pseudoheader2.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
//	pseudoheader2.u_IPdst = IP4_ADR_P2N(171,2,14,10);
//	packet2.u_cksum = 0;
//	char str[10] = "TESTING";
//	strcpy(packet2.u_data, str);
//
//	printf("The packet's data is %s\n", packet2.u_data);
//
//	pseudoheader_ptr = &pseudoheader2;
//	packet_ptr = &packet2;
//
//
//	printf("Packet ptr's checksum is %i\n", packet_ptr->u_cksum);
//	printf("Packet2's checksum is %i\n", packet2.u_cksum);
//	printf("The checksums value is %i \n", checksum);
//
//	checksum = UDP_checksum(packet_ptr, pseudoheader_ptr);
//
//	printf("The checksums value is %i \n ", checksum);
//
//	return(0);
//	}

/* udp_in test */

//int main() {
//
//	struct udp_packet packet2;
//	struct udp_metadata_parsed pseudoheader2;
//	struct finsFrame* pff;
//	struct finsFrame ff;
//	unsigned short checksum = 26900;
//
//
//	packet2.u_src = 1087;
//	packet2.u_dst = 13;
//	packet2.u_len = 15;
//	pseudoheader2.u_pslen = 15;
//	pseudoheader2.u_prcl = 17;
//	pseudoheader2.u_IPsrc = IP4_ADR_P2N(153,18,8,105);
//	pseudoheader2.u_IPdst = IP4_ADR_P2N(171,2,14,10);
//	packet2.u_cksum = checksum;
//	char str[10] = "TESTING";
//	strcpy(packet2.u_data, str);
//
//	ff.dataFrame.pdu = &packet2;
//
//	memcpy(&ff.dataFrame.metaData, &pseudoheader2, 16);
//
//	ff.dataFrame.pduLength = packet2.u_len;
//	ff.dataOrCtrl = DATA;
//	ff.destinationID = UDPID;
//	ff.dataFrame.directionFlag = UP;
//
//
//	pff = &ff;
//
//	printf("The metadata's value for the length is %d\n", pseudoheader2.u_pslen);
//				printf("The UDP packet's value for the length is %d\n", packet2.u_len);
//	udp_in(pff);
//
//
//	return(0);
//	}

/* udp_out test */
int main(int argc, char *argv[]) {
	struct udp_metadata_parsed meta;
	struct finsFrame* pff;
	struct finsFrame ff;
	unsigned short checksum = 0;

	IP4_init(argc, argv);

	char str[20] = "TESTING";

	ff.dataFrame.pdu = &str[0];


	meta.u_IPdst = IP4_ADR_P2N(192,168,1,28);
	meta.u_IPsrc = IP4_ADR_P2N(192,168,1,28);
	meta.u_destPort = 13;
	meta.u_srcPort = 1087;



	ff.dataFrame.pduLength = 7;
	ff.dataOrCtrl = DATA;
	ff.destinationID = UDPID;
	ff.dataFrame.directionFlag = DOWN;


	memcpy(&ff.dataFrame.metaData, &meta, 16);
	pff = &ff;

//	printf("The metadata's value for the length is %d\n", pseudoheader2.u_pslen);
//	printf("The UDP packet's value for the length is %d\n", packet2.u_len);

/* Time to split into two processes
 *  1) the child Process is for capturing (incoming)
 *  2) the parent process is for injecting frames (outgoing)
 */

	/* inject handler is initialized earlier to make sure that forwarding
	 * feature is able to work even if the parent process did not start injecting yet
	 */
	inject_init();
	pid_t pID = fork();
	int status;
	   if (pID == 0)                // child
	   {
	      // Code only executed by child process
	/*	   PRINT_DEBUG("child started to capture");
		   capture_init();
		   pcap_close ( capture_handle );
*/



	    }
	    else if (pID < 0)            // failed to fork
	    {
	        PRINT_DEBUG("\n Error while forking, program will exit");
	        exit(1);
	        // Throw exception
	    }
	    else                                   // parent
	    {
	      // Code only executed by parent process
	    	PRINT_DEBUG("parent started to inject");

	    	int i=0;

	    	for ( i=0; i< 20; i++ )
	    	{
	    		sleep(1);
	    		PRINT_DEBUG("#%d",i);
	    		udp_out(pff);
	    		PRINT_DEBUG("UDP done");


	    	}

	    	/* terminate the wifi module */
	    	wifi_terminate();

	    	/* wait until the child return */
			wait(&status);
				if (WIFEXITED(status))
				{
					PRINT_DEBUG("Parent: child has exited normally with status %d", WEXITSTATUS(status));
				}

				else
				{
					PRINT_DEBUG("Parent: child has not terminated normally");
				}


	    }




	return (0);
}
