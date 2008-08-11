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
extern int server_inject_count;
extern int server_capture_count;

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
	//u_char *packet; /* Packet Pointer */
	//struct data_to_pass data;
	if (header->caplen != header->len) {
		PRINT_ERROR("Snaplen not large enough for packet: caplen=%u, len=%u", header->caplen, header->len);
		exit(1);
	}

	/** Write the length of the received frame to the pipe, then write the frame contents
	 * This part is an atomic critical section. Need to be handled carefully
	 */
	uint32_t dataLength = header->caplen;

	//if (dataLength != 1512) {
	//return;
	//}

	++server_capture_count;
	PRINT_IMPORTANT("Packet captured: count=%d, size=%d", server_capture_count, dataLength);

	//print_hex_block(packetReceived, dataLength);
	//fflush(stdout);
	//return;

	uint32_t numBytes = write(server_capture_fd, &dataLength, sizeof(u_int));
	if (numBytes <= 0) {
		PRINT_ERROR("size write fail: numBytes=%u", numBytes);
		return;
	}

	numBytes = write(server_capture_fd, packetReceived, dataLength);
	if (numBytes <= 0) {
		PRINT_ERROR("frame write fail: numBytes=%u, frame_len=%u", numBytes, dataLength);
		return;
	}

	return;
} // end of the function got_packet

void capture_init(char *device, int argc, char *argv[]) {
	PRINT_IMPORTANT("Entered: device='%s'", device);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, CAPTURE_PATH);
	unlink(addr.sun_path);

	int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd < 0) {
		PRINT_ERROR("socket error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}

	PRINT_DEBUG("binding to: addr='%s'", CAPTURE_PATH);
	if (bind(server_fd, (struct sockaddr *) &addr, size) < 0) {
		PRINT_ERROR("bind error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}
	if (listen(server_fd, 1) < 0) {
		PRINT_ERROR("listen error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}

	if (1) {
		server_capture_fd = accept(server_fd, (struct sockaddr *) &addr, (socklen_t *) &size);
		close(server_fd);
		if (server_capture_fd < 0) {
			PRINT_ERROR("accept error: capture_fd=%d, errno=%u, str='%s'", server_capture_fd, errno, strerror(errno));
			return;
		}
		PRINT_DEBUG("accepted at: capture_fd=%d, addr='%s'", server_capture_fd, addr.sun_path);
	}

	sleep(2);

	//TODO recv MAC/ip address from Core?
	char *filter_exp = (char *) malloc(MAX_FILTER_LEN);
	if (filter_exp == NULL) {
		PRINT_ERROR("alloc error");
		exit(-1);
	}
	memset(filter_exp, 0, MAX_FILTER_LEN);
	char *pt = filter_exp;

	//uint8_t dev_mac[] = "00234d1a4dcc";
	//	getDevice_MACAddress(dev_macAddress,dev);
	//	strcat(filter_exp,dev_macAddress);

	int ret;
	int total = 0;

	int i;
	for (i = 1; i < argc - 2 && total < MAX_FILTER_LEN; i += 2) {
		ret = sprintf(pt, "(ether dst %c%c:%c%c:%c%c:%c%c:%c%c:%c%c) or (ether broadcast and (not ether src %c%c:%c%c:%c%c:%c%c:%c%c:%c%c)) or ",
				argv[i + 1][0], argv[i + 1][1], argv[i + 1][2], argv[i + 1][3], argv[i + 1][4], argv[i + 1][5], argv[i + 1][6], argv[i + 1][7], argv[i + 1][8],
				argv[i + 1][9], argv[i + 1][10], argv[i + 1][11], argv[i + 1][0], argv[i + 1][1], argv[i + 1][2], argv[i + 1][3], argv[i + 1][4],
				argv[i + 1][5], argv[i + 1][6], argv[i + 1][7], argv[i + 1][8], argv[i + 1][9], argv[i + 1][10], argv[i + 1][11]);
		if (ret > 0) {
			total += ret;
			pt += ret;
		}
	}
	sprintf(pt, "(ether dst %c%c:%c%c:%c%c:%c%c:%c%c:%c%c) or (ether broadcast and (not ether src %c%c:%c%c:%c%c:%c%c:%c%c:%c%c))", argv[i + 1][0],
			argv[i + 1][1], argv[i + 1][2], argv[i + 1][3], argv[i + 1][4], argv[i + 1][5], argv[i + 1][6], argv[i + 1][7], argv[i + 1][8], argv[i + 1][9],
			argv[i + 1][10], argv[i + 1][11], argv[i + 1][0], argv[i + 1][1], argv[i + 1][2], argv[i + 1][3], argv[i + 1][4], argv[i + 1][5], argv[i + 1][6],
			argv[i + 1][7], argv[i + 1][8], argv[i + 1][9], argv[i + 1][10], argv[i + 1][11]);

	//strcat(filter_exp, "dst host 127.0.0.1"); //local loopback - for internal testing, can't use external net
	//strcat(filter_exp, "(ether dst 50:46:5d:14:e0:7f) or (ether broadcast and (not ether src 50:46:5d:14:e0:7f))"); //tablet1 wlan0
	//strcat(filter_exp, "(ether dst 00:23:4d:1a:4d:cc) or (ether broadcast and (not ether src 00:23:4d:1a:4d:cc))"); //laptop15 wlan0

	uint8_t *dev = (uint8_t *) device;
	bpf_u_int32 net; /* ip */
	bpf_u_int32 mask; /* subnet mask */
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet((char *) dev, &net, &mask, errbuf) == -1) {
		PRINT_ERROR("Couldn't get netmask for device '%s': '%s'", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* print capture info */
	PRINT_IMPORTANT("Device='%s'", dev);
	PRINT_IMPORTANT("Filter expression='%s'", filter_exp);

	/* open capture device */
	capture_handle = pcap_open_live((char *) dev, SNAP_LEN, 0, 1000, errbuf);
	if (capture_handle == NULL) {
		PRINT_ERROR("Couldn't open device: dev='%s', err='%s', errno=%u, str='%s'", dev, errbuf, errno, strerror(errno));
		while (1)
			;
		exit(EXIT_FAILURE);
	}
	PRINT_IMPORTANT("capture_handle=%p", capture_handle);

	/* make sure we're capturing on an Ethernet device [2] */
	int data_linkValue = pcap_datalink(capture_handle);
	if (data_linkValue != DLT_EN10MB) {
		PRINT_ERROR("'%s' is not an Ethernet", dev);
		while (1)
			;
		exit(EXIT_FAILURE);
	}
	PRINT_IMPORTANT("Datalink layer Description: '%s' (%d) ", pcap_datalink_val_to_description(data_linkValue), data_linkValue);

	/* compile the filter expression */

	struct bpf_program fp; /* compiled filter program (expression) */
	if (pcap_compile(capture_handle, &fp, filter_exp, 0, net) == -1) {
		PRINT_ERROR("Couldn't parse filter '%s': '%s'", filter_exp, pcap_geterr(capture_handle));
		while (1)
			;
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(capture_handle, &fp) == -1) {
		PRINT_ERROR("Couldn't install filter '%s': '%s'", filter_exp, pcap_geterr(capture_handle));
		while (1)
			;
		exit(EXIT_FAILURE);
	}

#ifndef BUILD_FOR_ANDROID
	int check_monitor_mode = pcap_can_set_rfmon(capture_handle); //Not supported in Bionic
	if (check_monitor_mode) {
		PRINT_DEBUG(" Monitor mode can be set");
	} else if (check_monitor_mode == 0) {
		PRINT_DEBUG(" Monitor mode could not be set");
	}
#endif

	//while(1);

	//	int num_packets = 1000;			/* number of packets to capture */
	int num_packets = 0; /* INFINITY */
	/* now we can set our callback function */
	pcap_loop(capture_handle, num_packets, got_packet, (u_char *) NULL);
	/* cleanup */
	pcap_freecode(&fp);
	free(filter_exp);
	PRINT_DEBUG("END of capt init");
} // end of capture_init

/** -----------------------------------------------------------------*/

void inject_init(char *device) {
	PRINT_IMPORTANT("Entered: device='%s'", device);

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	int32_t size = sizeof(addr);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, INJECT_PATH);
	unlink(addr.sun_path);

	int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (server_fd < 0) {
		PRINT_ERROR("socket error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}

	PRINT_DEBUG("binding to: addr='%s'", INJECT_PATH);
	if (bind(server_fd, (struct sockaddr *) &addr, size) < 0) {
		PRINT_ERROR("bind error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}
	if (listen(server_fd, 1) < 0) {
		PRINT_ERROR("listen error: server_fd=%d, errno=%u, str='%s'", server_fd, errno, strerror(errno));
		return;
	}

	server_inject_fd = accept(server_fd, (struct sockaddr *) &addr, (socklen_t *) &size);
	close(server_fd);
	if (server_inject_fd < 0) {
		PRINT_ERROR("accept error: inject_fd=%d, errno=%u, str='%s'", server_inject_fd, errno, strerror(errno));
		return;
	}
	PRINT_DEBUG("accepted at: inject_fd=%d, addr='%s'", server_inject_fd, addr.sun_path);

	sleep(2);

	//getDevice_MACAddress(dev_macAddress,dev);

	uint8_t *dev = (uint8_t *) device;
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

	/** Setup the Injection Interface */
	if ((inject_handle = pcap_open_live((char *) dev, BUFSIZ, 1, -1, errbuf)) == NULL) {
		PRINT_ERROR( "Error: '%s'", errbuf);
		exit(1);
	}

	//	static int count = 1;
	//uint8_t dev_macAddress[17];

	int framelen;
	//char *frame;
	int numBytes;
	char frame[SNAP_LEN];

	/** --------------------------------------------------------------------------*/
	while (1) {
		numBytes = read(server_inject_fd, &framelen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_ERROR("size read fail: numBytes=%u", numBytes);
			break;
		}

		numBytes = read(server_inject_fd, frame, framelen);
		if (numBytes <= 0) {
			PRINT_ERROR("frame read fail: numBytes=%u, frame_len=%u", numBytes, framelen);
			break;
		}

		//PRINT_IMPORTANT("A frame of length %d will be injected-----", framelen);
		//print_hex_block((u_char *) frame, framelen);
		//fflush(stdout);

		if (framelen > 0) {
			numBytes = pcap_inject(inject_handle, frame, framelen);
			if (numBytes == -1) {
				PRINT_ERROR("Injection failed: framelen=%d, errno=%u, str='%s'", framelen, errno, strerror(errno));
			} else {
				++server_inject_count;
				PRINT_IMPORTANT("Packet injected: count=%d, size=%d ", server_inject_count, numBytes);
			}
		}
	} // end of while loop

	PRINT_IMPORTANT("*****************");
	PRINT_IMPORTANT("Inject: capture count=%d", server_capture_count);
	PRINT_IMPORTANT("Inject: inject count=%d", server_inject_count);
} // inject_init()

/** ------------------------------------------------------------------*/

void wifi_terminate() {

	pcap_close(inject_handle);
	pcap_close(capture_handle);

} // end of wifi_terminate

/** -------------------------------------------------------------*/

void close_pipes() {
	unlink(CAPTURE_PATH);
	unlink(INJECT_PATH);
	close(server_capture_fd);
	close(server_inject_fd);
}
