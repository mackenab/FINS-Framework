/*
 * wifistub.c
 *
 *  Created on: Nov 22, 2010
 *      Author: Abdallah Abdallah
 */

#include "wifistub.h"
#include <signal.h>

/** ----------------------------------------------------------------------------------*/

int wifistub_setNonblocking(int fd) { //TODO move to common file?
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	return ioctl(fd, FIOBIO, &flags);
#endif
}

int wifistub_setBlocking(int fd) {
	int flags;

	/* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
	/* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
	if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0; //TODO verify is right?
	return ioctl(fd, FIOBIO, &flags);
#endif
}

void capture_init(struct interface_to_inject_hdr *hdr, struct processes_shared *shared) {
	PRINT_IMPORTANT("Entered: hdr=%p, ii_num=%u, shared=%p", hdr, hdr->ii_num, shared);

	char filter_exp[MAX_FILTER_LEN];
	memset(filter_exp, 0, MAX_FILTER_LEN);
	char *pt = filter_exp;

	int total = 0;

	int ret;
	uint8_t mac_str[MAC_STR_LEN];
	int i;
	for (i = 0; i < hdr->ii_num && total < MAX_FILTER_LEN; i++) {
		/*
		 ret = sprintf((char *) mac_str, "%02llx:%02llx:%02llx:%02llx:%02llx:%02llx", (hdr->iis[i].mac & (0x0000FF0000000000ull)) >> 40,
		 (hdr->iis[i].mac & (0x000000FF00000000ull)) >> 32, (hdr->iis[i].mac & (0x00000000FF000000ull)) >> 24,
		 (hdr->iis[i].mac & (0x0000000000FF0000ull)) >> 16, (hdr->iis[i].mac & (0x000000000000FF00ull)) >> 8,
		 (hdr->iis[i].mac & (0x00000000000000FFull)));
		 */
		ret = sprintf((char *) mac_str, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c", hdr->iis[i].mac[0], hdr->iis[i].mac[1], hdr->iis[i].mac[2], hdr->iis[i].mac[3],
				hdr->iis[i].mac[4], hdr->iis[i].mac[5], hdr->iis[i].mac[6], hdr->iis[i].mac[7], hdr->iis[i].mac[8], hdr->iis[i].mac[9], hdr->iis[i].mac[10],
				hdr->iis[i].mac[11]);

		if (i == 0) {
			ret = sprintf(pt, "(ether dst %s) or (ether broadcast and (not ether src %s))", mac_str, mac_str);
		} else {
			ret = sprintf(pt, " or (ether dst %s) or (ether broadcast and (not ether src %s))", mac_str, mac_str);
		}
		if (ret > 0) {
			total += ret;
			pt += ret;
		}
	}

	if (total > MAX_FILTER_LEN) {
		PRINT_ERROR("todo error");
		close_pipes(shared);
		return;
	}

	uint8_t *dev = hdr->iis[0].name; //TODO Fix/replace this!
	bpf_u_int32 net; /* ip */
	bpf_u_int32 mask; /* subnet mask */
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet((char *) dev, &net, &mask, errbuf) == -1) {
		PRINT_WARN("Couldn't get netmask for device '%s': '%s'", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* print capture info */
	PRINT_IMPORTANT("Device='%s'", dev);
	PRINT_IMPORTANT("Filter expression='%s'", filter_exp);

	/* open capture device */
	shared->capture_handle = pcap_open_live((char *) dev, SNAP_LEN, 0, 1000, errbuf);
	if (shared->capture_handle == NULL) {
		PRINT_ERROR("Couldn't open device: dev='%s', err='%s', errno=%u, str='%s'", dev, errbuf, errno, strerror(errno));
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}
	PRINT_IMPORTANT("capture_handle=%p", shared->capture_handle);

	/* make sure we're capturing on an Ethernet device [2] */
	int data_linkValue = pcap_datalink(shared->capture_handle);
	if (data_linkValue != DLT_EN10MB) {
		PRINT_ERROR("'%s' is not an Ethernet", dev);
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}
	PRINT_IMPORTANT("Datalink layer Description: '%s' (%d) ", pcap_datalink_val_to_description(data_linkValue), data_linkValue);

	/* compile the filter expression */

	struct bpf_program fp; /* compiled filter program (expression) */
	if (pcap_compile(shared->capture_handle, &fp, filter_exp, 0, net) == -1) {
		PRINT_ERROR("Couldn't parse filter '%s': '%s'", filter_exp, pcap_geterr(shared->capture_handle));
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(shared->capture_handle, &fp) == -1) {
		PRINT_ERROR("Couldn't install filter '%s': '%s'", filter_exp, pcap_geterr(shared->capture_handle));
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

#ifndef BUILD_FOR_ANDROID
	int check_monitor_mode = pcap_can_set_rfmon(shared->capture_handle); //Not supported in Bionic
	if (check_monitor_mode) {
		PRINT_DEBUG(" Monitor mode can be set");
	} else if (check_monitor_mode == 0) {
		PRINT_DEBUG(" Monitor mode could not be set");
	}
#endif

	//while(1);

	//	int num_packets = 1000;			/* number of packets to capture */
	int num_packets = 1; /* INFINITY */

	shared->capture_count = 0;
	PRINT_IMPORTANT("Capturer setup complete");

	/* now we can set our callback function */
	while (shared->running_flag) {
		pcap_loop(shared->capture_handle, num_packets, got_packet, (u_char *) shared); //blocks forever
	}

	PRINT_IMPORTANT("Shutting Down");
	/* cleanup */
	pcap_freecode(&fp);

	PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
	if (shared->capture_handle) {
		pcap_breakloop(shared->capture_handle);
		pcap_close(shared->capture_handle);
		shared->capture_handle = NULL;
	}
	close_pipes(shared);
} // end of capture_init

//TODO: pcap_handlers must be of void type. This method of returning data will have to be amended
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packetReceived) {
	struct processes_shared *shared = (struct processes_shared *) args;

	if (shared->capture_fd == 0) {
		PRINT_ERROR("capture_fd==0");
		return;
	}

	if (header->caplen != header->len) {
		PRINT_ERROR("Snaplen not large enough for packet: caplen=%u, len=%u", header->caplen, header->len);
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

	/** Write the length of the received frame to the pipe, then write the frame contents
	 * This part is an atomic critical section. Need to be handled carefully
	 */
	uint32_t dataLength = header->caplen;

//if (dataLength != 1512) {
//return;
//}

	++shared->capture_count;
	if (shared->capture_count % 1000 == 0) {
		PRINT_DEBUG("Packet captured: count=%d, size=%d", shared->capture_count, dataLength);
	}

//print_hex_block(packetReceived, dataLength);
//fflush(stdout);
//return;

	uint32_t numBytes = write(shared->capture_fd, &dataLength, sizeof(u_int));
	if (numBytes <= 0) {
		PRINT_ERROR("size write fail: numBytes=%u", numBytes);
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

	numBytes = write(shared->capture_fd, packetReceived, dataLength);
	if (numBytes <= 0) {
		PRINT_ERROR("frame write fail: numBytes=%u, frame_len=%u", numBytes, dataLength);
		PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
		if (shared->capture_handle) {
			pcap_breakloop(shared->capture_handle);
			pcap_close(shared->capture_handle);
			shared->capture_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

	return;
} // end of the function got_packet

/** -----------------------------------------------------------------*/

void inject_init(struct interface_to_inject_hdr *hdr, struct processes_shared *shared) {
	PRINT_IMPORTANT("Entered: hdr=%p, ii_num=%u, shared=%p", hdr, hdr->ii_num, shared);

	uint8_t *dev = hdr->iis[0].name; //TODO remove/fix!
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

	int i;
	for (i = 0; i < hdr->ii_num; i++) {
		//PRINT_IMPORTANT("iis[%d]: name='%s', mac=0x%012llx", i, hdr->iis[i].name, hdr->iis[i].mac);
		PRINT_IMPORTANT("iis[%d]: name='%s', mac='%s'", i, hdr->iis[i].name, hdr->iis[i].mac);
	}

	/** Setup the Injection Interface */
	shared->inject_handle = pcap_open_live((char *) dev, BUFSIZ, 0, -1, errbuf);
	if (shared->inject_handle == NULL) {
		PRINT_ERROR("Couldn't open device: dev='%s', err='%s', errno=%u, str='%s'", dev, errbuf, errno, strerror(errno));
		PRINT_DEBUG("Closing inject: handle=%p", shared->inject_handle);
		if (shared->inject_handle) {
			pcap_close(shared->inject_handle);
			shared->inject_handle = NULL;
		}
		close_pipes(shared);
		return;
	}

	int framelen;
	int numBytes;
	char frame[SNAP_LEN];
	shared->inject_count = 0;

	/** --------------------------------------------------------------------------*/
	while (shared->running_flag) {
		numBytes = read(shared->inject_fd, &framelen, sizeof(int));
		if (numBytes <= 0) {
			PRINT_ERROR("size read fail: numBytes=%u", numBytes);
			break;
		}

		numBytes = read(shared->inject_fd, frame, framelen);
		if (numBytes <= 0) {
			PRINT_ERROR("frame read fail: numBytes=%u, frame_len=%u", numBytes, framelen);
			break;
		}

		//PRINT_IMPORTANT("A frame of length %d will be injected-----", framelen);
		//print_hex_block((u_char *) frame, framelen);
		//fflush(stdout);

		if (framelen > 0) {
			numBytes = pcap_inject(shared->inject_handle, frame, framelen);
			if (numBytes == -1) {
				PRINT_ERROR("Injection failed: framelen=%d, errno=%u, str='%s'", framelen, errno, strerror(errno));
			} else {
				++shared->inject_count;
				if (shared->inject_count % 1000 == 0) {
					PRINT_DEBUG("Packet injected: count=%d, size=%d ", shared->inject_count, numBytes);
				}
			}
		}
	} // end of while loop

	PRINT_IMPORTANT("Shutting Down");
	PRINT_DEBUG("Closing inject: handle=%p", shared->inject_handle);
	if (shared->inject_handle) {
		pcap_close(shared->inject_handle);
		shared->inject_handle = NULL;
	}
	close_pipes(shared);
} // inject_init()

/** ------------------------------------------------------------------*/

void wifi_terminate() {

	//pcap_close(shared->inject_handle);
	//pcap_close(shared->capture_handle);

} // end of wifi_terminate

/** -------------------------------------------------------------*/

void close_pipes(struct processes_shared *shared) {
	PRINT_DEBUG("Entered: shared=%p", shared);
	shared->running_flag = 0;

	PRINT_DEBUG("Closing capture: fd=%d", shared->capture_fd);
	if (shared->capture_fd) {
		shutdown(shared->capture_fd, SHUT_RDWR);
		close(shared->capture_fd);
		shared->capture_fd = 0;
	}

	PRINT_DEBUG("Closing inject: fd=%d", shared->inject_fd);
	if (shared->inject_fd) {
		shutdown(shared->inject_fd, SHUT_RDWR);
		close(shared->inject_fd);
		shared->inject_fd = 0;
	}

	PRINT_DEBUG("Unlinking capture='%s'", CAPTURE_PATH);
	unlink(CAPTURE_PATH);
}
