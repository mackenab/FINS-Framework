/*
 * wifistub.h
 *
 *  Created on: Nov 22, 2010
 *      Author: Abdallah Abdallah
 */

#ifndef WIFISTUB_H_
#define WIFISTUB_H_

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>


#ifdef BUILD_FOR_ANDROID
#include <stdio.h>

//#define DEBUG
#define IMPORTANT
#define ERROR

#ifdef DEBUG
#define PRINT_DEBUG(format, args...) printf("DEBUG(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef IMPORTANT
#define PRINT_IMPORTANT(format, args...) printf("IMPORTANT(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
#define PRINT_ERROR(format, args...) printf("ERROR(%s, %s, %d):"format"\n",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_ERROR(format, args...)
#endif

#else /* if not BUILD_FOR_ANDROID */

#include <finsdebug.h>
#endif
//#include <getMAC_Address.h>

/* default snap length (maximum bytes per packet to capture) */
//#define SNAP_LEN 1518
#define SNAP_LEN 8192//4096
/* packet inject handle */
extern pcap_t *inject_handle;

/* packet capture handle */
extern pcap_t *capture_handle;

/** The structure of the data to be written to the CAPTURE_PIPE */
struct data_to_pass {
	u_int frameLength;
	uint8_t *frame;
};

/** The Buffering pipes between the Incoming Handlers and FINS Space */
extern int server_capture_fd;
extern int server_inject_fd;

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define MAX_FILTER_LEN 500

//TODO these definitions need to be gathered
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS/files"
//#define FINS_TMP_ROOT "/data/data/com.BU_VT.FINS"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

//"com.whoever.xfer/fins_capture"
#define CAPTURE_PATH FINS_TMP_ROOT "/fins_capture"
#define INJECT_PATH FINS_TMP_ROOT "/fins_inject"

/** Functions prototypes fully defined in wifistub.c */

void capture_init(char *device, int argc, char *argv[]);
void inject_init(char *device);
void wifi_terminate();
void close_pipes();
void /*int*/got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packetReceived);
int wifi_inject(char *frameToSend, int frameLength);

#endif /* WIFISTUB_H_ */
