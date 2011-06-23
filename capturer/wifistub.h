/*
 * wifistub.h
 *
 *  Created on: Nov 22, 2010
 *      Author: Abdallah Abdallah
 */

#ifndef WIFISTUB_H_
#define WIFISTUB_H_

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/if_ether.h>
#include <pthread.h>
#include "getMAC_Address.h"
#include "finsdebug.h"

/* default snap length (maximum bytes per packet to capture) */
//#define SNAP_LEN 1518
#define SNAP_LEN 4096

/* packet inject handle */
extern pcap_t *inject_handle;

/* packet capture handle */
extern pcap_t *capture_handle;

/** The structure of the data to be written to the INCOME_PIPE */
struct data_to_pass {
	u_int frameLength;
	unsigned char *frame;
};

/** The Buffering pipes between the Incoming Handlers and FINS Space */
extern int income_pipe_fd;

extern int inject_pipe_fd;

#define INCOME_PIPE "/tmp/fins/fins_capture"
#define INJECT_PIPE "/tmp/fins/fins_inject"

/** Functions prototypes fully defined in wifistub.c */

void capture_init(char *device);
void inject_init(char *device);
void wifi_terminate();
void close_pipes();
int got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packetReceived);
int wifi_inject(char *frameToSend, int frameLength);

#endif /* WIFISTUB_H_ */
