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
 * print a captured frame
 */

void print_frame(const u_char *payload, int len) {

	PRINT_DEBUG("passed len = %d", len);
	int len_rem = len;
	int line_width = 16; /* number of bytes per line */
	int line_len;
	int offset = 0; /* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		PRINT_DEBUG("calling hex_ascii_line");
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
} // end of print_frame


/**
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000  sniff_udp 47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
} //end of print_hex_ascii_line()


/** ----------------------------------------------------------------------------------*/
int got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packetReceived) {
	static int count = 1; /* packet counter */
	u_char *packet; /* Packet Pointer */
	struct data_to_pass data;
	u_int numBytes;
	u_int dataLength;
	PRINT_DEBUG("Packet number %d: has been captured \n", count);

	if (header->caplen != header->len) {
		PRINT_DEBUG("Snaplen value is not enough to capture the whole packet as it is on wire \n");
		exit(1);
	}
	//data.frameLength = header->caplen ;
	//data.frame = (u_char *) malloc(header->caplen);
	//memcpy(data.frame,packetReceived,data.frameLength);

	/** Write the length of the received frame to the pipe, then write the frame contents
	 * This part is an atomic critical section. Need to be handled carefully
	 */
	dataLength = header->caplen;

	print_frame(packetReceived, dataLength);
	fflush(stdout);
	numBytes = write(income_pipe_fd, &dataLength, sizeof(u_int));
	if (numBytes <= 0) {
		PRINT_DEBUG("numBytes written %d\n", numBytes);
		return (0);
	}

	numBytes = write(income_pipe_fd, packetReceived, dataLength);

	if (numBytes <= 0) {
		PRINT_DEBUG("numBytes written %d\n", numBytes);
		return (0);
	}
	PRINT_DEBUG("A frame of length %d has been captured \n", numBytes);

	capture_count++;
	return (1);

} // end of the function got_packet

void capture_init(char *interface) {

	char device[20];
	//char device[]="wlan0";
	strcpy(device, interface);
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	unsigned char dev_macAddress[17];
	char *filter_exp;
	unsigned char *dev;
	filter_exp = (char *) malloc(200);
	int check_monitor_mode;

	struct bpf_program fp; /* compiled filter program (expression) */
	bpf_u_int32 mask; /* subnet mask */
	bpf_u_int32 net; /* ip */
	//	int num_packets = 1000;			/* number of packets to capture */
	int num_packets = 0; /* INFINITY */
	int data_linkValue;
	//print_app_banner();

	dev = (unsigned char *) device;

	/*
	 if (mkfifo(INCOME_PIPE, 0777) !=0 )
	 {
	 PRINT_DEBUG("MKFIFO Failed \n");
	 exit(EXIT_FAILURE);
	 }
	 */

	/* has to run without return check to work as blocking call */
	/** It blocks until the other communication side opens the pipe */

	income_pipe_fd = open(INCOME_PIPE, O_WRONLY);

	if (income_pipe_fd == -1) {
		PRINT_DEBUG("Income Pipe failure \n");
		exit(EXIT_FAILURE);
	}

	/* Build the filter expression based on the mac address of the passed
	 * device name
	 */
	//	strcat(filter_exp,"ether dst ");

	//char filter_exp[] = "ether src 00:1e:2a:52:ec:9c";		/* filter expression [3] */

	//	getDevice_MACAddress(dev_macAddress,dev);
	//	strcat(filter_exp,dev_macAddress);
	//strcat(filter_exp," not arp and not tcp");
	//strcat(filter_exp," and udp and");
	//strcat(filter_exp,"dst host 127.0.0.1 and udp and port 5001");
	strcat(filter_exp, "udp and port 5001");

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	capture_handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (capture_handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	data_linkValue = pcap_datalink(capture_handle);
	if (data_linkValue != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	printf("Datalink layer Description: %s \n",
			pcap_datalink_val_to_description(data_linkValue));

	/* compile the filter expression */

	if (pcap_compile(capture_handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
				pcap_geterr(capture_handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(capture_handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
				pcap_geterr(capture_handle));
		exit(EXIT_FAILURE);
	}

	check_monitor_mode = pcap_can_set_rfmon(capture_handle);
	if (check_monitor_mode) {
		PRINT_DEBUG("\n Monitor mode can be set\n");
	} else if (check_monitor_mode == 0) {
		PRINT_DEBUG("\n Monitor mode could not be set\n");
	} else
		PRINT_DEBUG("\n check_monior_mode value is %d \n",check_monitor_mode);

	/* now we can set our callback function */
	pcap_loop(capture_handle, num_packets, got_packet, (u_char *) NULL);

	/* cleanup */
	pcap_freecode(&fp);
	free(filter_exp);

} // end of capture_init

/** -----------------------------------------------------------------*/

void inject_init(char *interface) {

	/*
	 if (mkfifo(INJECT_PIPE, 0777) !=0 )
	 {
	 PRINT_DEBUG("MKFIFO of INJECT Failed \n");
	 exit(EXIT_FAILURE);
	 } */
//	static int count = 1;
	unsigned char device[20];
	unsigned char dev_macAddress[17];
	strcpy(device, interface);

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
		PRINT_DEBUG("Inject Pipe failure \n");
		exit(EXIT_FAILURE);
	}

	/** Setup the Injection Interface */
	if ((inject_handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf)) == NULL) {
		PRINT_DEBUG( "\nError: %s\n", errbuf );
		exit(1);
	}

	/** --------------------------------------------------------------------------*/

	while (1) {

		numBytes = read(inject_pipe_fd, &framelen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			break;
		}

		//frame = (char *) malloc (framelen);
		numBytes = read(inject_pipe_fd, &frame, framelen);

		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			break;
		}

		PRINT_DEBUG("A frame of length %d wil be injected-----", framelen);

		print_frame(&frame, framelen);
		/** TODO
		 * Inject the Ethernet Frame into the Device
		 */

		numBytes = pcap_inject(inject_handle, &frame, framelen);
		if (numBytes == -1)
			PRINT_DEBUG("Failed to inject the packet");

		PRINT_DEBUG("\n Message #%d has been injected whose size is %d  ",inject_count,numBytes);
		inject_count++;

	} // end of while loop


} // inject_init()

/** ------------------------------------------------------------------*/

void wifi_terminate() {

	pcap_close(inject_handle);
	pcap_close(capture_handle);

} // end of wifi_terminate

/** -------------------------------------------------------------*/

void close_pipes() {
	unlink(INCOME_PIPE);
	unlink(INJECT_PIPE);
	close(income_pipe_fd);
	close(inject_pipe_fd);

}
