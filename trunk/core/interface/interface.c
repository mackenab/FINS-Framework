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
#include <finsdebug.h>

#include "interface.h"

int interface_running;
extern sem_t Interface_to_Switch_Qsem;
extern finsQueue Interface_to_Switch_Queue;

extern sem_t Switch_to_Interface_Qsem;
extern finsQueue Switch_to_Interface_Queue;

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

void *Capturer_to_Interface(void *local) {

	u_char *frame;
	int frame_len;
	struct sniff_ethernet *hdr;
	int numBytes;
	int capture_pipe_fd;
	struct finsFrame *ff = NULL;

	metadata *meta;

	//struct sniff_ethernet *ethernet_header;
	uint64_t dst_mac;
	uint64_t src_mac;
	u_short ether_type;

	capture_pipe_fd = open(CAPTURE_PIPE, O_RDONLY); //responsible for socket/ioctl call
	if (capture_pipe_fd == -1) {
		PRINT_DEBUG("opening capture_pipe did not work");
		exit(EXIT_FAILURE);
	}

	while (interface_running) {
		numBytes = read(capture_pipe_fd, &frame_len, sizeof(int));
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			break;
		}
		frame = (u_char *) malloc(frame_len);
		if (frame == NULL) {
			PRINT_ERROR("allocation fail");
			exit(1);
		}

		numBytes = read(capture_pipe_fd, frame, frame_len);
		if (numBytes <= 0) {
			PRINT_DEBUG("numBytes written %d\n", numBytes);
			free(frame);
			break;
		}

		if (numBytes != frame_len) {
			PRINT_DEBUG("bytes read not equal to datalen,  numBytes=%d\n", numBytes);
			free(frame);
			continue;
		}

		if (numBytes < sizeof(struct sniff_ethernet)) {
			PRINT_DEBUG("todo error");
		}

		PRINT_DEBUG("A frame of length %d has been written-----", frame_len);

		//print_frame(data,datalen);
		hdr = (struct sniff_ethernet *) frame;
		ether_type = ntohs(hdr->ether_type);

		PRINT_DEBUG("recv frame: dst=%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x, src=%2.2x-%2.2x-%2.2x-%2.2x-%2.2x-%2.2x, type=0x%x",
				(uint8_t) hdr->ether_dhost[0], (uint8_t) hdr->ether_dhost[1], (uint8_t) hdr->ether_dhost[2], (uint8_t) hdr->ether_dhost[3], (uint8_t) hdr->ether_dhost[4], (uint8_t) hdr->ether_dhost[5], (uint8_t) hdr->ether_shost[0], (uint8_t) hdr->ether_shost[1], (uint8_t) hdr->ether_shost[2], (uint8_t) hdr->ether_shost[3], (uint8_t) hdr->ether_shost[4], (uint8_t) hdr->ether_shost[5], ether_type);

		dst_mac = ((uint64_t) hdr->ether_dhost[0] << 40) + ((uint64_t) hdr->ether_dhost[1] << 32) + ((uint64_t) hdr->ether_dhost[2] << 24)
				+ ((uint64_t) hdr->ether_dhost[3] << 16) + ((uint64_t) hdr->ether_dhost[4] << 8) + (uint64_t) hdr->ether_dhost[5];
		src_mac = ((uint64_t) hdr->ether_shost[0] << 40) + ((uint64_t) hdr->ether_shost[1] << 32) + ((uint64_t) hdr->ether_shost[2] << 24)
				+ ((uint64_t) hdr->ether_shost[3] << 16) + ((uint64_t) hdr->ether_shost[4] << 8) + (uint64_t) hdr->ether_shost[5];

		PRINT_DEBUG("recv frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

		ff = (struct finsFrame *) malloc(sizeof(struct finsFrame));
		if (ff == NULL) {
			PRINT_ERROR("ff creation failed, dropping frame");
			free(frame);
			continue;
		}

		PRINT_DEBUG("ff=%p", ff);

		/** TODO
		 * 1. extract the Ethernet Frame
		 * 2. pre-process the frame in order to extract the metadata
		 * 3. build a finsFrame and insert it into EtherStub_to_Switch_Queue
		 */
		meta = (metadata *) malloc(sizeof(metadata));
		if (meta == NULL) {
			PRINT_ERROR("metadata creation failed");
			free(ff);
			free(frame);
			continue;
		}
		metadata_create(meta);

		ff->dataOrCtrl = DATA;
		ff->metaData = meta;

		if (ether_type == ETH_TYPE_IP4) { //0x0800 == 2048, IPv4
			PRINT_DEBUG("IPv4: proto=0x%x (%u)", ether_type, ether_type);
			ff->destinationID.id = IPV4ID;
			ff->destinationID.next = NULL;
		} else if (ether_type == ETH_TYPE_ARP) { //0x0806 == 2054, ARP
			PRINT_DEBUG("ARP: proto=0x%x (%u)", ether_type, ether_type);
			ff->destinationID.id = ARPID;
			ff->destinationID.next = NULL;
		} else if (ether_type == ETH_TYPE_IP6) { //0x86dd == 34525, IPv6
			PRINT_DEBUG("IPv6: proto=0x%x (%u)", ether_type, ether_type);
			//drop, don't handle & don't catch sys calls
			freeFinsFrame(ff);
			free(frame);
			continue;
		} else {
			PRINT_DEBUG("default: proto=%x (%u)", ether_type, ether_type);
			//drop
			freeFinsFrame(ff);
			free(frame);
			continue;
		}

		ff->dataFrame.directionFlag = UP;
		ff->dataFrame.pduLength = frame_len - SIZE_ETHERNET;
		ff->dataFrame.pdu = (u_char *) malloc(ff->dataFrame.pduLength);
		memcpy(ff->dataFrame.pdu, frame + SIZE_ETHERNET, ff->dataFrame.pduLength);

		metadata_writeToElement(meta, "dst_mac", &dst_mac, META_TYPE_INT64);
		metadata_writeToElement(meta, "src_mac", &src_mac, META_TYPE_INT64);
		metadata_writeToElement(meta, "ether_type", &ether_type, META_TYPE_INT);

		if (!interface_to_switch(ff)) {
			free(ff->dataFrame.pdu);
			freeFinsFrame(ff);
		}

		free(frame);
	} // end of while loop

	pthread_exit(NULL);
}

int inject_pipe_fd;

void *Switch_to_Interface(void *local) {

	//char data[]="loloa7aa7a";
	//struct ipv4_packet *packet;
	//IP4addr destination;
	//struct hostent *loop_host;
	//uint32_t dstip;

	inject_pipe_fd = open(INJECT_PIPE, O_WRONLY);
	if (inject_pipe_fd == -1) {
		PRINT_DEBUG("opening inject_pipe did not work");
		exit(EXIT_FAILURE);
	}

	PRINT_DEBUG("");

	while (interface_running) {
		interface_get_ff();
		//PRINT_DEBUG("");
	}

	pthread_exit(NULL);
} // end of Inject Function

void interface_get_ff() {
	struct finsFrame *ff;

	do {
		sem_wait(&Switch_to_Interface_Qsem);
		ff = read_queue(Switch_to_Interface_Queue);
		sem_post(&Switch_to_Interface_Qsem);
	} while (interface_running && ff == NULL);

	if (!interface_running) {
		return;
	}

	PRINT_DEBUG("\n At least one frame has been read from the Switch to Etherstub ff=%p", ff);

	if (ff->dataOrCtrl == CONTROL) {
		interface_fcf(ff);
		PRINT_DEBUG("");
	} else if (ff->dataOrCtrl == DATA) {
		//ff->dataFrame is an IPv4 packet
		if (ff->dataFrame.directionFlag == UP) {
			//interface_in_fdf(ff); //TODO remove?
			PRINT_DEBUG("todo error");
		} else { //directionFlag==DOWN
			interface_out_fdf(ff);
			PRINT_DEBUG("");
		}
	} else {
		PRINT_DEBUG("todo error");
	}
}

void interface_out_fdf(struct finsFrame *ff) {

	uint64_t dst_mac;
	uint64_t src_mac;
	int ether_type = 0;

	char *frame;
	struct sniff_ethernet *hdr;
	int framelen;
	int numBytes;

	metadata* meta = ff->metaData;

	int ret = 0;
	ret += metadata_readFromElement(meta, "dst_mac", &dst_mac) == CONFIG_FALSE;
	ret += metadata_readFromElement(meta, "src_mac", &src_mac) == CONFIG_FALSE;
	ret += metadata_readFromElement(meta, "ether_type", &ether_type) == CONFIG_FALSE;

	if (ret) {
		//TODO error
		PRINT_DEBUG("todo error");
		//TODO create error fcf?
		return;
	}

	PRINT_DEBUG("send frame: dst=0x%12.12llx, src=0x%12.12llx, type=0x%x", dst_mac, src_mac, ether_type);

	framelen = ff->dataFrame.pduLength + SIZE_ETHERNET;
	PRINT_DEBUG("framelen=%d", framelen);

	frame = (char *) malloc(framelen);
	if (frame == NULL) {
		PRINT_DEBUG("frame creation failed");
		exit(-1);
	}

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
		PRINT_DEBUG("todo error");
		//TODO create error fcf?
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	//memcpy(frame + SIZE_ETHERNET, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	memcpy(hdr->data, ff->dataFrame.pdu, ff->dataFrame.pduLength);
	//	print_finsFrame(ff);
	PRINT_DEBUG("daemon inject to ethernet stub \n");

	numBytes = write(inject_pipe_fd, &framelen, sizeof(int));
	if (numBytes <= 0) {
		PRINT_DEBUG("numBytes written %d\n", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	numBytes = write(inject_pipe_fd, frame, framelen);
	if (numBytes <= 0) {
		PRINT_DEBUG("numBytes written %d\n", numBytes);
		freeFinsFrame(ff);
		free(frame);
		return;
	}

	freeFinsFrame(ff);
	free(frame);
}

void interface_in_fdf(struct finsFrame *ff) {

}

void interface_fcf(struct finsFrame *ff) {

}

void interface_exec(struct finsFrame *ff) {

}

int interface_to_switch(struct finsFrame *ff) {
	PRINT_DEBUG("Entered: ff=%p meta=%p", ff, ff->metaData);
	if (sem_wait(&Interface_to_Switch_Qsem)) {
		PRINT_ERROR("Interface_to_Switch_Qsem wait prob");
		exit(-1);
	}
	if (write_queue(ff, Interface_to_Switch_Queue)) {
		/*#*/PRINT_DEBUG("");
		sem_post(&Interface_to_Switch_Qsem);
		return 1;
	}

	PRINT_DEBUG("");
	sem_post(&Interface_to_Switch_Qsem);

	return 0;
}

void interface_init(pthread_attr_t *fins_pthread_attr) {
	PRINT_DEBUG("Interface Started");
	interface_running = 1;

	pthread_t capturer_to_interface_thread;
	//pthread_t switch_to_interface_thread;

	pthread_create(&capturer_to_interface_thread, fins_pthread_attr, Capturer_to_Interface, fins_pthread_attr);
	//pthread_create(&switch_to_interface_thread, fins_pthread_attr, Switch_to_Interface, fins_pthread_attr);

	inject_pipe_fd = open(INJECT_PIPE, O_WRONLY);
	if (inject_pipe_fd == -1) {
		PRINT_DEBUG("opening inject_pipe did not work");
		exit(EXIT_FAILURE);
	}

	PRINT_DEBUG("");

	while (interface_running) {
		interface_get_ff();
		PRINT_DEBUG("");
	}

	pthread_join(capturer_to_interface_thread, NULL);
	//pthread_join(switch_to_interface_thread, NULL);

	PRINT_DEBUG("Interface Terminating");
}

void interface_shutdown() {
	interface_running = 0;

	//TODO expand this
}

void interface_free() {
	//TODO free all module related mem
}
