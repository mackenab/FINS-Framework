#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
//#include <errno.h>
#include <fcntl.h>
//#include <limits.h>
//#include <sys/stat.h>
//#include <linux/if_ether.h>
#include <pthread.h>
//#include <finstypes.h>
//#include <queueModule.h>
#include <sys/time.h>
#include <finsdebug.h>

#include "interface.h"

#include <switch.h>
static struct fins_proto_module interface_proto = { .module_id = INTERFACE_ID, .name = "interface", .running_flag = 1, };

pthread_t switch_to_interface_thread;
pthread_t capturer_to_interface_thread;

int capture_pipe_fd; /** capture file descriptor to read from capturer */
int inject_pipe_fd; /** inject file descriptor to read from capturer */

/** special functions to print the data within a frame for testing*/
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
#ifndef BUILD_FOR_ANDROID
	/* ascii (if printable)*/
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
	printf("\n");
#endif
	return;

} //end of print_hex_ascii_line()

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
/** ---------------------------------------------------------*/

int interface_setNonblocking(int fd) { //TODO move to common file?
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

int interface_setBlocking(int fd) {
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

void *capturer_to_interface(void *local) {
	PRINT_CRITICAL("Entered");

	int numBytes;
	int frame_len;
	uint8_t frame[ETH_FRAME_LEN_MAX];
	struct sniff_ethernet *hdr = (struct sniff_ethernet *) frame;

	uint64_t dst_mac;
	uint64_t src_mac;
	uint32_t ether_type;
	struct timeval current;

	metadata *params;
	struct finsFrame *ff;

	while (interface_proto.running_flag) {
		/*
		 if (0) { //works, allows for terminating, though creates unbound while(1) loop
		 interface_setNonblocking(capture_pipe_fd);
		 do {
		 numBytes = read(capture_pipe_fd, &frame_len, sizeof(int));
		 } while (interface_proto.running_flag && numBytes <= 0);

		 if (!interface_proto.running_flag) {
		 break;
		 }

		 interface_setBlocking(capture_pipe_fd);
		 }
		 */
		//if (1) { //works but blocks, so can't shutdown properly, have to double ^C, kill, or wait for frame/kill capturer
		do {
			numBytes = read(capture_pipe_fd, &frame_len, sizeof(int));
		} while (interface_proto.running_flag && numBytes <= 0);

		if (!interface_proto.running_flag) {
			break;
		}
		//}

		if (numBytes <= 0) {
			PRINT_ERROR("error reading size: numBytes=%d", numBytes);
			break;
		}

		if (frame_len > ETH_FRAME_LEN_MAX) {
			PRINT_ERROR("len too large: frame_len=%d", frame_len);
			continue;
		}

		if (frame_len < SIZE_ETHERNET) {
			PRINT_ERROR("frame too small: frame_len=%d, min=%d", frame_len, SIZE_ETHERNET);
			continue;
		}

		numBytes = read(capture_pipe_fd, frame, frame_len);
		if (numBytes <= 0) {
			PRINT_ERROR("error reading frame: numBytes=%d", numBytes);
			break;
		}

		if (numBytes != frame_len) {
			PRINT_ERROR("lengths not equal: frame_len=%d, numBytes=%d", frame_len, numBytes);
			continue;
		}

		PRINT_DEBUG("frame read: frame_len=%d", frame_len);
		//print_frame(data,datalen);

		dst_mac = ((uint64_t) hdr->ether_dhost[0] << 40) + ((uint64_t) hdr->ether_dhost[1] << 32) + ((uint64_t) hdr->ether_dhost[2] << 24)
				+ ((uint64_t) hdr->ether_dhost[3] << 16) + ((uint64_t) hdr->ether_dhost[4] << 8) + (uint64_t) hdr->ether_dhost[5];
		src_mac = ((uint64_t) hdr->ether_shost[0] << 40) + ((uint64_t) hdr->ether_shost[1] << 32) + ((uint64_t) hdr->ether_shost[2] << 24)
				+ ((uint64_t) hdr->ether_shost[3] << 16) + ((uint64_t) hdr->ether_shost[4] << 8) + (uint64_t) hdr->ether_shost[5];
		ether_type = ntohs(hdr->ether_type);
		gettimeofday(&current, 0);

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x, stamp=%u.%u",
				dst_mac, src_mac, ether_type, (uint32_t)current.tv_sec, (uint32_t)current.tv_usec);

		params = (metadata *) secure_malloc(sizeof(metadata));
		metadata_create(params);

		secure_metadata_writeToElement(params, "recv_dst_mac", &dst_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(params, "recv_src_mac", &src_mac, META_TYPE_INT64);
		secure_metadata_writeToElement(params, "recv_ether_type", &ether_type, META_TYPE_INT32);
		secure_metadata_writeToElement(params, "recv_stamp", &current, META_TYPE_INT64);

		ff = (struct finsFrame *) secure_malloc(sizeof(struct finsFrame));
		ff->dataOrCtrl = DATA;
		ff->metaData = params;

		if (ether_type == ETH_TYPE_IP4) { //0x0800 == 2048, IPv4
			PRINT_DEBUG("IPv4: proto=0x%x (%u)", ether_type, ether_type);
			ff->destinationID.id = IPV4_ID;
			ff->destinationID.next = NULL;
		} else if (ether_type == ETH_TYPE_ARP) { //0x0806 == 2054, ARP
			PRINT_DEBUG("ARP: proto=0x%x (%u)", ether_type, ether_type);
			ff->destinationID.id = ARP_ID;
			ff->destinationID.next = NULL;
		} else if (ether_type == ETH_TYPE_IP6) { //0x86dd == 34525, IPv6
			PRINT_DEBUG("IPv6: proto=0x%x (%u)", ether_type, ether_type);
			//drop, don't handle & don't catch sys calls, change after do catch
			ff->dataFrame.pdu = NULL;
			freeFinsFrame(ff);
			continue;
		} else {
			PRINT_ERROR("default: proto=0x%x (%u)", ether_type, ether_type);
			//drop
			ff->dataFrame.pdu = NULL;
			freeFinsFrame(ff);
			continue;
		}

		ff->dataFrame.directionFlag = UP;
		ff->dataFrame.pduLength = frame_len - SIZE_ETHERNET;
		ff->dataFrame.pdu = (uint8_t *) secure_malloc(ff->dataFrame.pduLength);
		memcpy(ff->dataFrame.pdu, frame + SIZE_ETHERNET, ff->dataFrame.pduLength);

		//freeFinsFrame(ff);
		//continue;

		if (!interface_to_switch(ff)) {
			PRINT_ERROR ("send to switch error, ff=%p", ff);
			freeFinsFrame(ff);
		}
	}

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
}

void *switch_to_interface(void *local) {
	PRINT_CRITICAL("Entered");

	while (interface_proto.running_flag) {
		interface_get_ff();
		PRINT_DEBUG("");
	}

	PRINT_CRITICAL("Exited");
	pthread_exit(NULL);
} // end of Inject Function

void interface_get_ff(void) {
	struct finsFrame *ff;

	do {
		secure_sem_wait(interface_proto.event_sem);
		secure_sem_wait(interface_proto.input_sem);
		ff = read_queue(interface_proto.input_queue);
		sem_post(interface_proto.input_sem);
	} while (interface_proto.running_flag && ff == NULL);

	if (!interface_proto.running_flag) {
		if (ff != NULL) {
			freeFinsFrame(ff);
		}
		return;
	}

	if (ff->metaData == NULL) {
		PRINT_ERROR("Error fcf.metadata==NULL");
		exit(-1);
	}

	PRINT_DEBUG(" At least one frame has been read from the Switch to Etherstub ff=%p", ff);

	if (ff->dataOrCtrl == CONTROL) {
		interface_fcf(ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		//ff->dataFrame is an IPv4 packet
		if (ff->dataFrame.directionFlag == UP) {
			//interface_in_fdf(ff); //TODO remove?
			PRINT_ERROR("todo error");
		} else { //directionFlag==DOWN
			interface_out_fdf(ff);
			PRINT_DEBUG("");
		}
	} else {
		PRINT_ERROR("todo error");
	}
}

void interface_out_fdf(struct finsFrame *ff) {

	uint64_t dst_mac;
	uint64_t src_mac;
	uint32_t ether_type;

	char *frame;
	struct sniff_ethernet *hdr;
	int framelen;
	int numBytes;

	metadata *params = ff->metaData;
	secure_metadata_readFromElement(params, "send_dst_mac", &dst_mac);
	secure_metadata_readFromElement(params, "send_src_mac", &src_mac);
	secure_metadata_readFromElement(params, "send_ether_type", &ether_type);

	PRINT_DEBUG("send frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

	framelen = ff->dataFrame.pduLength + SIZE_ETHERNET;
	PRINT_DEBUG("framelen=%d", framelen);

	frame = (char *) secure_malloc(framelen);
	hdr = (struct sniff_ethernet *) frame;

	hdr->ether_dhost[0] = (dst_mac >> 40) & 0xff;
	hdr->ether_dhost[1] = (dst_mac >> 32) & 0xff;
	hdr->ether_dhost[2] = (dst_mac >> 24) & 0xff;
	hdr->ether_dhost[3] = (dst_mac >> 16) & 0xff;
	hdr->ether_dhost[4] = (dst_mac >> 8) & 0xff;
	hdr->ether_dhost[5] = dst_mac & 0xff;

	hdr->ether_shost[0] = (src_mac >> 40) & 0xff;
	hdr->ether_shost[1] = (src_mac >> 32) & 0xff;
	hdr->ether_shost[2] = (src_mac >> 24) & 0xff;
	hdr->ether_shost[3] = (src_mac >> 16) & 0xff;
	hdr->ether_shost[4] = (src_mac >> 8) & 0xff;
	hdr->ether_shost[5] = src_mac & 0xff;

	if (ether_type == ETH_TYPE_ARP) {
		hdr->ether_type = htons(ETH_TYPE_ARP);
	} else if (ether_type == ETH_TYPE_IP4) {
		hdr->ether_type = htons(ETH_TYPE_IP4);
	} else {
		PRINT_ERROR("todo error");
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	//memcpy(frame + SIZE_ETHERNET, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	memcpy(hdr->data, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	//	print_finsFrame(ff);
	PRINT_DEBUG("daemon inject to ethernet stub ");

	numBytes = write(inject_pipe_fd, &framelen, sizeof(int));
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	numBytes = write(inject_pipe_fd, frame, framelen);
	if (numBytes <= 0) {
		PRINT_ERROR("numBytes written %d", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	freeFinsFrame(ff);
	free(frame);
}

void interface_in_fdf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

}

void interface_fcf(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);
	PRINT_ERROR("todo");
	freeFinsFrame(ff);
}

void interface_exec(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p, meta=%p", ff, ff->metaData);

}

int interface_to_switch(struct finsFrame *ff) {
	return module_to_switch(&interface_proto, ff);
}

void interface_init(void) {
	PRINT_CRITICAL("Entered");
	interface_proto.running_flag = 1;

	module_create_ops(&interface_proto);
	module_register(&interface_proto);

	inject_pipe_fd = open(INJECT_PIPE, O_WRONLY);
	if (inject_pipe_fd == -1) {
		PRINT_ERROR("opening inject_pipe did not work");
		exit(-1);
	}

	capture_pipe_fd = open(CAPTURE_PIPE, O_RDONLY); //responsible for socket/ioctl call
	if (capture_pipe_fd == -1) {
		PRINT_ERROR("opening capture_pipe did not work");
		exit(-1); //exit(EXIT_FAILURE);
	}

	PRINT_CRITICAL("PCAP processes connected");
}

void interface_run(pthread_attr_t *fins_pthread_attr) {
	PRINT_CRITICAL("Entered");

	secure_pthread_create(&switch_to_interface_thread, fins_pthread_attr, switch_to_interface, fins_pthread_attr);
	secure_pthread_create(&capturer_to_interface_thread, fins_pthread_attr, capturer_to_interface, fins_pthread_attr);
}

void interface_shutdown(void) {
	PRINT_CRITICAL("Entered");
	interface_proto.running_flag = 0;
	sem_post(interface_proto.event_sem);

	//TODO expand this

	PRINT_CRITICAL("Joining switch_to_interface_thread");
	pthread_join(switch_to_interface_thread, NULL);
	PRINT_CRITICAL("Joining capturer_to_interface_thread");
	pthread_join(capturer_to_interface_thread, NULL);
}

void interface_release(void) {
	PRINT_CRITICAL("Entered");
	//TODO free all module related mem

	module_unregister(interface_proto.module_id);
	module_destroy_ops(&interface_proto);
}
