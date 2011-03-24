/*
 * ethermod.c
 *
 *  Created on: Nov 21, 2010
 *      Author: Abdallah Abdallah
 */


#include "wifistub.h"

#define DEBUG
#define ERROR



	/** packet inject handle */
	pcap_t *inject_handle;

	/** packet capture handle */
	pcap_t *capture_handle;

	/** Pipes Descriptors */
	int income_pipe_fd;
	int inject_pipe_fd;





/** @brief open the incoming and outgoing NAMED PIPES
 *
 * Forking
 * Child will handle Injecting
 * Parent will handle Capturing
 *
 * Initiate Capturing
 * Initiate Injecting
 *
 * Continue Forever
 * */


void  main()
{


	pid_t pID;
	char device[20];
	strcpy(device, "lo");
	//strcpy(device, "eth0");


	/** Time to split into two processes
	 *  1. the child Process is for capturing (incoming)
	 *  2. the parent process is for injecting frames (outgoing)
	 */
	pID = fork();

	if (pID == 0)  // child -- Capture process

	  {

		 // Code only executed by child process
		PRINT_DEBUG("child started to capture \n");
		//sleep(2);

		capture_init(device);

	   }

	   else if (pID < 0) // failed to fork

	   {

		   PRINT_DEBUG ("Failed to Fork \n");
		   exit(1);

	   }

	   else      // parent

	   {
		 // Code only executed by parent process

		   /** inject handler is supposed to be initialized earlier to make sure that forwarding
		   	 * feature is able to work even if the parent process did not start injecting yet
		   	 * we fix this by sleeping the capturing process for a while. To give the injection
		   	 * process a lead
		   	 */
			PRINT_DEBUG("parent started to Inject \n");
		   	inject_init(device);
		  // 	while (1);


	   }


		/**
			if (inject_handle != NULL);
				pcap_close(inject_handle);

			if (capture_handle != NULL);
				pcap_close(capture_handle);
		*/

		return;

}

// end of main function
