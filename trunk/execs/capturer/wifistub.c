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

	//while(1);

	//	int num_packets = 1000;			/* number of packets to capture */
	int num_packets = 1; /* INFINITY */

	shared->capture_count = 0;
	PRINT_IMPORTANT("Capturer setup complete");

	int ret;
	/* now we can set our callback function */
	while (shared->running_flag) {
		ret = pcap_loop(shared->capture_handle, num_packets, got_packet, (u_char *) shared); //blocks forever
		if (ret) {
			break;
		}
	}

	PRINT_IMPORTANT("Shutting Down");
	close_handles(shared);
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
		close_handles(shared);
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
#ifdef DEBUG
	if (shared->capture_count % 1000 == 0) {
		PRINT_DEBUG("Packet captured: count=%llu, size=%d", shared->capture_count, dataLength);
	}
#endif

//print_hex_block(packetReceived, dataLength);
//fflush(stdout);
//return;

	uint32_t numBytes = write(shared->capture_fd, &dataLength, sizeof(u_int));
	if (numBytes <= 0) {
		PRINT_ERROR("size write fail: numBytes=%u", numBytes);
		close_handles(shared);
		close_pipes(shared);
		return;
	}

	numBytes = write(shared->capture_fd, packetReceived, dataLength);
	if (numBytes <= 0) {
		PRINT_ERROR("frame write fail: numBytes=%u, frame_len=%u", numBytes, dataLength);
		close_handles(shared);
		close_pipes(shared);
		return;
	}

	return;
} // end of the function got_packet

/** -----------------------------------------------------------------*/

void inject_init(struct interface_to_inject_hdr *hdr, struct processes_shared *shared) {
	PRINT_IMPORTANT("Entered: hdr=%p, ii_num=%u, shared=%p", hdr, hdr->ii_num, shared);

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
#ifdef DEBUG
				if (shared->inject_count % 1000 == 0) {
					PRINT_DEBUG("Packet injected: count=%llu, size=%d ", shared->inject_count, numBytes);
				}
#endif
			}
		}
	} // end of while loop

	PRINT_IMPORTANT("Shutting Down");
	close_handles(shared);
	close_pipes(shared);
} // inject_init()

/** ------------------------------------------------------------------*/

void wifi_terminate() {

	//pcap_close(shared->inject_handle);
	//pcap_close(shared->capture_handle);

} // end of wifi_terminate

/** -------------------------------------------------------------*/
void close_handles(struct processes_shared *shared) {
	PRINT_DEBUG("Entered: shared=%p", shared);
	pcap_t *handle;
	PRINT_IMPORTANT("Closing handles: capture=%p, inject=%p", shared->capture_handle, shared->inject_handle);

	PRINT_DEBUG("Closing capture: handle=%p", shared->capture_handle);
	if ((handle = shared->capture_handle)) {
		shared->capture_handle = NULL;
		pcap_breakloop(handle);
		pcap_close(handle);
	}

	PRINT_DEBUG("Closing inject: handle=%p", shared->capture_handle);
	if ((handle = shared->inject_handle)) {
		shared->inject_handle = NULL;
		pcap_close(handle);
	}
}

void close_pipes(struct processes_shared *shared) {
	PRINT_DEBUG("Entered: shared=%p", shared);
	shared->running_flag = 0;
	PRINT_IMPORTANT("fds: capture=%d, inject=%d", shared->capture_fd, shared->inject_fd);

	int fd;
	PRINT_DEBUG("Closing capture: fd=%d", shared->capture_fd);
	if ((fd = shared->capture_fd)) {
		shared->capture_fd = 0;
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	PRINT_DEBUG("Closing inject: fd=%d", shared->inject_fd);
	if ((fd = shared->inject_fd)) {
		shared->inject_fd = 0;
		shutdown(fd, SHUT_RDWR);
		close(fd);
	}

	PRINT_DEBUG("Unlinking capture='%s'", CAPTURE_PATH);
	unlink(CAPTURE_PATH);
}
