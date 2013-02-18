/*
 * Main.c
 * This is code that is called from the java part of android cellphones (the dalvik vm)
 * Author: Alexander Meijer
 * Date: Jul 15, 2012
 */

#include <jni.h>
#include <android/log.h>
#include <android_native_app_glue.h>
#include <android/native_activity.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <pcap.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#define SNAP_LEN 8192//4096
#include "wifistub.h"

#include <ethermod.h>
#include <core.h>

#define FINSBOOT_MSG "The writable directory used for the capturer/injector fifo is: "

#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>

void android_main(struct android_app *state) {
	app_dummy();

	//TODO-Have this update a variable, and use that to establish the pipes, sockets for improved compatibility with future android versions
	char *writeLocation = (char *) state->activity->internalDataPath;
	char *bootmsg = FINSBOOT_MSG;
	pid_t pid = 0;

	__android_log_print(ANDROID_LOG_INFO, "FINS", bootmsg);
	__android_log_print(ANDROID_LOG_INFO, "FINS", writeLocation);
	__android_log_print(ANDROID_LOG_INFO, "FINS", "Forking into capturermain() and main()");

	int ret;
	__android_log_print(ANDROID_LOG_INFO, "FINS", "Gaining su status");
	if ((ret = system("su"))) {
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	}

	int fd1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	__android_log_print(ANDROID_LOG_ERROR, "FINS", "fd1=%d, errno=%u, str='%s'", fd1, errno, strerror(errno));
	int fd2 = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	__android_log_print(ANDROID_LOG_ERROR, "FINS", "fd2=%d, errno=%u, str='%s'", fd2, errno, strerror(errno));
    int fd3 = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd3=%d, errno=%u, str='%s'", fd3, errno, strerror(errno));
    int fd4 = socket(PF_UNIX, SOCK_STREAM, 0);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd4=%d, errno=%u, str='%s'", fd4, errno, strerror(errno));
    int fd5 = socket(PF_INET, SOCK_DGRAM, 0);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd5=%d, errno=%u, str='%s'", fd5, errno, strerror(errno));
    int fd6 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd6=%d, errno=%u, str='%s'", fd6, errno, strerror(errno));
    int fd7 = socket(PF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd7=%d, errno=%u, str='%s'", fd7, errno, strerror(errno));
    int fd8 = socket(PF_INET, SOCK_STREAM, 0);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd8=%d, errno=%u, str='%s'", fd8, errno, strerror(errno));
    int fd9 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd9=%d, errno=%u, str='%s'", fd9, errno, strerror(errno));
    int fd10 = socket(PF_INET, SOCK_STREAM | O_NONBLOCK, IPPROTO_TCP);
    __android_log_print(ANDROID_LOG_ERROR, "FINS", "fd10=%d, errno=%u, str='%s'", fd10, errno, strerror(errno));
	//if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
	//if ((sock = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1) {
	//if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
    //if ((sock = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
    //if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {



	//####################################
	if (1) {
		sleep(10);
		char *filter_exp = (char *) malloc(200);
		if (filter_exp == NULL) {
			PRINT_ERROR("alloc error");
			exit(-1);
		}
		memset(filter_exp, 0, 200);

		strcat(filter_exp, "(ether dst 001cbf86d2da) or (ether broadcast and (not ether src 001cbf86d2da))"); //laptop wlan0

		uint8_t *dev = (uint8_t *) malloc(200);
		if (dev == NULL) {
			PRINT_ERROR("alloc error");
			exit(-1);
		}
		memset(dev, 0, 200);
		strcpy((char *)dev, "wlan0");

		bpf_u_int32 net; /* ip */
		bpf_u_int32 mask; /* subnet mask */
		char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */

		/* get network number and mask associated with capture device */
		if (pcap_lookupnet((char *) dev, &net, &mask, errbuf) == -1) {
			PRINT_ERROR("Couldn't get netmask for device %s: %s", dev, errbuf);
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
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		int data_linkValue = pcap_datalink(capture_handle);
		if (data_linkValue != DLT_EN10MB) {
			PRINT_ERROR("%s is not an Ethernet", dev);
			exit(EXIT_FAILURE);
		}
		PRINT_IMPORTANT("Datalink layer Description: %s (%d) ", pcap_datalink_val_to_description(data_linkValue), data_linkValue);

		/* compile the filter expression */

		struct bpf_program fp; /* compiled filter program (expression) */
		if (pcap_compile(capture_handle, &fp, filter_exp, 0, net) == -1) {
			PRINT_ERROR("Couldn't parse filter %s: %s", filter_exp, pcap_geterr(capture_handle));
			exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(capture_handle, &fp) == -1) {
			PRINT_ERROR("Couldn't install filter %s: %s", filter_exp, pcap_geterr(capture_handle));
			exit(EXIT_FAILURE);
		}

#ifndef BUILD_FOR_ANDROID
		int check_monitor_mode = pcap_can_set_rfmon(capture_handle); //Not supported in Bionic
		if (check_monitor_mode) {
			PRINT_DEBUG(" Monitor mode can be set");
		} else if (check_monitor_mode == 0) {
			PRINT_DEBUG(" Monitor mode could not be set");
		} else
			PRINT_DEBUG(" check_monior_mode value is %d ", check_monitor_mode);
#endif

		//while(1);

		//	int num_packets = 1000;			/* number of packets to capture */
		int num_packets = 0; /* INFINITY */
		/* now we can set our callback function */
		pcap_loop(capture_handle, num_packets, got_packet, (u_char *) NULL);
	}
	//####################################

	while (1)
		;

	pid = fork();
	if (pid < 0) {
		__android_log_print(ANDROID_LOG_ERROR, "FINS", "FORKING ERROR");
	} else if (pid == 0) { /* child */
		prctl(PR_SET_PDEATHSIG, SIGHUP); //kill the child when the parent is stopped
		sleep(5);
		__android_log_print(ANDROID_LOG_INFO, "FINS", "Starting FINS: core_main()");
		core_dummy();
		//core_main();
		while (1)
			; //sleep(1);
		__android_log_print(ANDROID_LOG_INFO, "FINS", "Exiting FINS: core_main()");
	} else { /* parent */
		__android_log_print(ANDROID_LOG_INFO, "FINS", "Starting FINS: capturer_main()");
		capturer_dummy();
		//capturer_main();
		while (1)
			; //sleep(1);
		//sleep(5);
		__android_log_print(ANDROID_LOG_INFO, "FINS", "Exiting FINS: capturer_main()");
	}
}
