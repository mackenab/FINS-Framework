/*
 * wifistub.c
 *
 *  Created on: Nov 22, 2010
 *      Author: Abdallah Abdallah
 */

#include "wifistub.h"
#include <signal.h>

/** ONLY FOR DEBUGGING
 * TO BE REMOVED REMOVED REMOVED
 *
 */

/** Globally defined counters
 *
 */
extern int inject_count;
extern int capture_count;

/**
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000  sniff_udp 47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */

/**
 * print a captured frame
 */

/** ----------------------------------------------------------------------------------*/
/*int*/void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packetReceived) { //TODO: pcap_handlers must be of void type. This method of returning data will have to be amended
	//static int count = 1; /* packet counter */
	//u_char * packet; /* Packet Pointer */
	//struct data_to_pass data;
	if (header->caplen != header->len) {
		PRINT_ERROR("Snaplen not large enough for packet: caplen=%u, len=%u", header->caplen, header->len);
		exit(1);
	}
	//data.frameLength = header->caplen ;
	//data.frame = (u_char *) fins_malloc(header->caplen);
	//memcpy(data.frame,packetReceived,data.frameLength);

	/** Write the length of the received frame to the pipe, then write the frame contents
	 * This part is an atomic critical section. Need to be handled carefully
	 */
	uint32_t dataLength = header->caplen;

	//if (dataLength != 1512) {
	//return;
	//}

	++capture_count;
	//PRINT_IMPORTANT("Packet captured: count=%d, size=%d", ++capture_count, dataLength);

	//print_hex_block(packetReceived, dataLength);
	//fflush(stdout);

	uint32_t numBytes = write(capture_pipe_fd, &dataLength, sizeof(u_int));
	if (numBytes <= 0) {
		PRINT_ERROR("size write fail: numBytes=%u", numBytes);
		return;
	}

	numBytes = write(capture_pipe_fd, packetReceived, dataLength);
	if (numBytes <= 0) {
		PRINT_ERROR("frame write fail: numBytes=%u, frame_len=%u", numBytes, dataLength);
		return;
	}

	return;
} // end of the function got_packet

void capture_init(char *interface) {
	char device[20];

	strcpy(device, interface);
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	//unsigned char dev_macAddress[17];
	char *filter_exp;
	unsigned char *dev;
	filter_exp = (char *) malloc(200);
	if (filter_exp == NULL) {
		PRINT_ERROR("alloc error");
		exit(-1);
	}

	struct bpf_program fp; /* compiled filter program (expression) */
	bpf_u_int32 mask; /* subnet mask */
	bpf_u_int32 net; /* ip */
	//	int num_packets = 1000;			/* number of packets to capture */
	int num_packets = 0; /* INFINITY */
	int data_linkValue;
	//print_app_banner();

	dev = (unsigned char *) device;

	/*
	 if (mkfifo(CAPTURE_PIPE, 0777) !=0 )
	 {
	 PRINT_DEBUG("MKFIFO Failed");
	 exit(EXIT_FAILURE);
	 }
	 */

	/* has to run without return check to work as blocking call */
	/** It blocks until the other communication side opens the pipe */
	capture_pipe_fd = open(CAPTURE_PIPE, O_WRONLY);
	if (capture_pipe_fd == -1) {
		PRINT_DEBUG("Income Pipe failure");
		exit(EXIT_FAILURE);
	}

	//TODO recv MAC/ip address from Core?

	/* Build the filter expression based on the mac address of the passed
	 * device name
	 */
	//	strcat(filter_exp,"ether dst ");
	//char filter_exp[] = "ether src 00:1e:2a:52:ec:9c";		/* filter expression [3] */
	//	getDevice_MACAddress(dev_macAddress,dev);
	//	strcat(filter_exp,dev_macAddress);
	//strcat(filter_exp, ""); //everything

	//strcat(filter_exp, "dst host 127.0.0.1"); //local loopback - for internal testing, can't use external net
	//strcat(filter_exp, "(ether dst 080027445566) or (ether broadcast and (not ether src 080027445566))"); //Vbox eth2
	//strcat(filter_exp, "(ether dst 001d09b35512) or (ether broadcast and (not ether src 001d09b35512))"); //laptop eth0
	//strcat(filter_exp, "(ether dst 001cbf86d2da) or (ether broadcast and (not ether src 001cbf86d2da))"); //laptop wlan0
	strcat(filter_exp, "(ether dst 00184d8f2a32) or (ether broadcast and (not ether src 00184d8f2a32))"); //laptop wlan4 card


	/* get network number and mask associated with capture device */
	if (pcap_lookupnet((char *) dev, &net, &mask, errbuf) == -1) {
		PRINT_ERROR("Couldn't get netmask for device %s: %s", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* print capture info */
	PRINT_IMPORTANT("Device: %s", dev);
	PRINT_IMPORTANT("Number of packets: %d", num_packets);
	PRINT_IMPORTANT("Filter expression: %s", filter_exp);

	/* open capture device */
	capture_handle = pcap_open_live((char *) dev, SNAP_LEN, 1, 1000, errbuf);
	if (capture_handle == NULL) {
		PRINT_ERROR("Couldn't open device %s: %s", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	data_linkValue = pcap_datalink(capture_handle);
	if (data_linkValue != DLT_EN10MB) {
		PRINT_ERROR("%s is not an Ethernet", dev);
		exit(EXIT_FAILURE);
	}
	PRINT_IMPORTANT("Datalink layer Description: %s (%d) ", pcap_datalink_val_to_description(data_linkValue), data_linkValue);

	/* compile the filter expression */

	if (pcap_compile(capture_handle, &fp, filter_exp, 0, net) == -1) {
		PRINT_ERROR("Couldn't parse filter %s: %s", filter_exp, pcap_geterr(capture_handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(capture_handle, &fp) == -1) {
		PRINT_ERROR("Couldn't install filter %s: %s", filter_exp, pcap_geterr(capture_handle));
		exit(EXIT_FAILURE);
	}

	//CHANGED mrd015 !!!!! start pcap_can_set_rfmon(...) not in Bionic!
#ifndef BUILD_FOR_ANDROID
	int check_monitor_mode = pcap_can_set_rfmon(capture_handle);
	if (check_monitor_mode) {
		PRINT_DEBUG(" Monitor mode can be set");
	} else if (check_monitor_mode == 0) {
		PRINT_DEBUG(" Monitor mode could not be set");
	} else
		PRINT_DEBUG(" check_monior_mode value is %d ", check_monitor_mode);
#endif
	//CHANGE END !!!!!	

	/* now we can set our callback function */
	pcap_loop(capture_handle, num_packets, got_packet, (u_char *) NULL);
	/* cleanup */
	pcap_freecode(&fp);
	free(filter_exp);
	PRINT_DEBUG("END of capt init");
} // end of capture_init

/** -----------------------------------------------------------------*/

void inject_init(char *interface) {

	/*
	 if (mkfifo(INJECT_PIPE, 0777) !=0 )
	 {
	 PRINT_DEBUG("MKFIFO of INJECT Failed ");
	 exit(EXIT_FAILURE);
	 } */
	//	static int count = 1;
	unsigned char device[20];
	//unsigned char dev_macAddress[17];
	strcpy((char *) device, interface);

	int framelen;
	//char *frame;
	int numBytes;
	unsigned char *dev;
	dev = (unsigned char *) device;
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	char frame[SNAP_LEN];

	//getDevice_MACAddress(dev_macAddress,dev);

	/** has to run without return check to work as blocking call
	 * It blocks until the other communication side opens the pipe
	 * */
	//	mkfifo(INJECT_PIPE, 0777);
	inject_pipe_fd = open(INJECT_PIPE, O_RDONLY);
	if (inject_pipe_fd == -1) {
		PRINT_DEBUG("Inject Pipe failure");
		exit(EXIT_FAILURE);
	}

	/** Setup the Injection Interface */
	if ((inject_handle = pcap_open_live((char *) dev, BUFSIZ, 1, -1, errbuf)) == NULL) {
		PRINT_DEBUG( "Error: %s", errbuf);
		exit(1);
	}

	/** --------------------------------------------------------------------------*/
	while (1) {
		numBytes = read(inject_pipe_fd, &framelen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_ERROR("size read fail: numBytes=%u", numBytes);
			break;
		}

		//frame = (char *) fins_malloc (framelen);
		numBytes = read(inject_pipe_fd, frame, framelen);
		if (numBytes <= 0) {
			PRINT_ERROR("frame read fail: numBytes=%u, frame_len=%u", numBytes, framelen);
			break;
		}

		//PRINT_IMPORTANT("A frame of length %d will be injected-----", framelen);
		//print_hex_block((u_char *) frame, framelen);
		//fflush(stdout);

		/**
		 * Inject the Ethernet Frame into the Device
		 */

		numBytes = pcap_inject(inject_handle, frame, framelen);
		if (numBytes == -1) {
			PRINT_DEBUG("Failed to inject the packet");
		} else {
			PRINT_DEBUG("Message injected: count=%d, size=%d ", inject_count, numBytes);
			inject_count++;
		}
	} // end of while loop

	PRINT_IMPORTANT("**Number of captured frames = %d", capture_count);
	PRINT_IMPORTANT("****Number of Injected frames = %d", inject_count);
} // inject_init()

/** ------------------------------------------------------------------*/

void wifi_terminate() {

	pcap_close(inject_handle);
	pcap_close(capture_handle);

} // end of wifi_terminate

/** -------------------------------------------------------------*/

void close_pipes() {
	unlink(CAPTURE_PIPE);
	unlink(INJECT_PIPE);
	close(capture_pipe_fd);
	close(inject_pipe_fd);

}
