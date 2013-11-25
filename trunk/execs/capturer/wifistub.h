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
#include <net/if.h>
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

#define DEBUG
#define INFO
#define WARN
#define IMPORTANT
#define ERROR

#include <stdio.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/time.h>
#include <unistd.h>

struct timeval global_print_tv;

#ifdef DEBUG
//#define PRINT_DEBUG(format, args...) printf("\033[01;37mDEBUG(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_DEBUG(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;37m%12u.%06u:DEBUG(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_DEBUG(format, args...)
#endif

#ifdef INFO
//#define PRINT_INFO(format, args...) printf("\033[01;34mINFO(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_INFO(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;34m%12u.%06u:INFO(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_INFO(format, args...)
#endif

#ifdef WARN
//#define PRINT_WARN(format, args...) printf("\033[01;33mWARN(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_WARN(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;33m%12u.%06u:WARN(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_WARN(format, args...)
#endif

#ifdef IMPORTANT
//#define PRINT_IMPORTANT(format, args...) printf("\033[01;32mIMPORTANT(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_IMPORTANT(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;32m%12u.%06u:IMPORTANT(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_IMPORTANT(format, args...)
#endif

#ifdef ERROR
//#define PRINT_ERROR(format, args...) printf("\033[01;31mERROR(%s, %s, %d):"format"\n\033[01;37m",__FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#define PRINT_ERROR(format, args...) gettimeofday(&global_print_tv, NULL);printf("\033[01;31m%12u.%06u:ERROR(%s, %s, %d):"format"\n\033[01;37m", (uint32_t)global_print_tv.tv_sec, (uint32_t)global_print_tv.tv_usec, __FILE__, __FUNCTION__, __LINE__, ##args);fflush(stdout)
#else
#define PRINT_ERROR(format, args...)
#endif

#else //!BUILD_FOR_ANDROID

#include <finsdebug.h>
#endif

#ifndef ALLPERMS
# define ALLPERMS (S_ISUID|S_ISGID|S_ISVTX|S_IRWXU|S_IRWXG|S_IRWXO)/* 07777 */
#endif

/* default snap length (maximum bytes per packet to capture) */
//#define SNAP_LEN 1518
#define SNAP_LEN 8192//4096
/** The structure of the data to be written to the CAPTURE_PIPE */
struct data_to_pass {
	u_int frameLength;
	uint8_t *frame;
};

struct processes_shared {
	uint8_t running_flag;

	int capture_fd;
	pcap_t *capture_handle;
	uint64_t capture_count;

	int inject_fd;
	pcap_t *inject_handle;
	uint64_t inject_count;
};

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define MAX_FILTER_LEN 500

//TODO these definitions need to be gathered
#ifdef BUILD_FOR_ANDROID
#define FINS_TMP_ROOT "/data/local/fins"
#else
#define FINS_TMP_ROOT "/tmp/fins"
#endif

#define CAPTURE_PATH FINS_TMP_ROOT "/fins_capture"
#define INJECT_PATH FINS_TMP_ROOT "/fins_inject"

#define MAC_ADDR_LEN (6)
#define MAC_STR_LEN (6*2+5)

#define ETH_FRAME_LEN_MAX 10000 //1538
struct interface_interface_info {
	uint8_t name[IFNAMSIZ];
	uint8_t mac[2 * MAC_ADDR_LEN];
//uint64_t mac; //should work but doesn't
};

#define INTERFACE_INFO_MIN_SIZE sizeof(uint32_t)
#define INTERFACE_INFO_SIZE(ii_num) (sizeof(uint32_t) + ii_num * sizeof(struct interface_interface_info))
#define INTERFACE_IF_LIST_MAX 256

struct interface_to_inject_hdr {
	uint32_t ii_num;
	struct interface_interface_info iis[INTERFACE_IF_LIST_MAX];
};

void capture_init(struct interface_to_inject_hdr *hdr, struct processes_shared *shared);
void /*int*/got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packetReceived);

void inject_init(struct interface_to_inject_hdr *hdr, struct processes_shared *shared);

void close_handles(struct processes_shared *shared);
void close_pipes(struct processes_shared *shared);

void wifi_terminate();
int wifi_inject(char *frameToSend, int frameLength);

#endif /* WIFISTUB_H_ */
