/*
 *  *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 *
 * @file ethermod.c This code is based on the modified version mentioned above
 * which is provided by the Tcpdump group
 *
 * @date Nov 21, 2010
 * @author: Abdallah Abdallah
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include "ethermod.h"

#include <signal.h>
#include <stddef.h>
#include <sys/prctl.h>

#include "wifistub.h"

pcap_t *inject_handle = NULL;
pcap_t *capture_handle = NULL;

int server_capture_fd;
int server_capture_count = 0;

int server_inject_fd;
int server_inject_count = 0;

/*
 * app name/banner
 */
void print_app_banner(void) {

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
	printf("\n The message printed above is a part of ");
	printf("\n the redistribution conditions requested by the Tcpdump group \n");

	return;
}

/** handling termination ctrl+c signal
 * */
void capturer_termination_handler(int sig) {
	PRINT_IMPORTANT("*****************");
	PRINT_IMPORTANT("Capture: capture count=%d", server_capture_count);
	PRINT_IMPORTANT("Capture: inject count=%d", server_inject_count);

	if (inject_handle != NULL) {
		pcap_close(inject_handle);
	}

	if (capture_handle != NULL) {
		pcap_close(capture_handle);
	}
	exit(2);
}

void capturer_dummy(void) {

}

#include <sys/ioctl.h>
#include <net/if.h>

void capturer_main(void) {
	PRINT_IMPORTANT("Entered");

	print_app_banner();
	int ret;

	/*
	 if (0) { //tests socket creation
	 //char recv_data[4000];
	 while (0) {
	 //gets(recv_data);
	 //sleep(15);
	 errno = 0;
	 int fd1 = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	 PRINT_IMPORTANT("fd1=%d, errno=%u, str='%s'", fd1, errno, strerror(errno));
	 int fd2 = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	 PRINT_IMPORTANT("fd2=%d, errno=%u, str='%s'", fd2, errno, strerror(errno));
	 int fd3 = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	 PRINT_IMPORTANT("fd3=%d, errno=%u, str='%s'", fd3, errno, strerror(errno));
	 int fd4 = socket(PF_UNIX, SOCK_STREAM, 0);
	 PRINT_IMPORTANT("fd4=%d, errno=%u, str='%s'", fd4, errno, strerror(errno));
	 int fd5 = socket(PF_INET, SOCK_DGRAM, 0);
	 PRINT_IMPORTANT("fd5=%d, errno=%u, str='%s'", fd5, errno, strerror(errno));
	 int fd6 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	 PRINT_IMPORTANT("fd6=%d, errno=%u, str='%s'", fd6, errno, strerror(errno));
	 int fd7 = socket(PF_INET, SOCK_DGRAM | O_NONBLOCK, IPPROTO_UDP);
	 PRINT_IMPORTANT("fd7=%d, errno=%u, str='%s'", fd7, errno, strerror(errno));
	 int fd8 = socket(PF_INET, SOCK_STREAM, 0);
	 PRINT_IMPORTANT("fd8=%d, errno=%u, str='%s'", fd8, errno, strerror(errno));
	 int fd9 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	 PRINT_IMPORTANT("fd9=%d, errno=%u, str='%s'", fd9, errno, strerror(errno));
	 int fd10 = socket(PF_INET, SOCK_STREAM | O_NONBLOCK, IPPROTO_TCP);
	 PRINT_IMPORTANT("fd10=%d, errno=%u, str='%s'", fd10, errno, strerror(errno));
	 int fd11 = socket(PF_INET, SOCK_RAW, 0);
	 PRINT_IMPORTANT("fd11=%d, errno=%u, str='%s'", fd11, errno, strerror(errno));
	 int fd12 = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	 PRINT_IMPORTANT("fd12=%d, errno=%u, str='%s'", fd12, errno, strerror(errno));
	 int fd13 = socket(PF_INET, SOCK_RAW | O_NONBLOCK, IPPROTO_ICMP);
	 PRINT_IMPORTANT("fd13=%d, errno=%u, str='%s'", fd13, errno, strerror(errno));
	 }
	 }

	 if (0) { //test assembly instructions (replaced in glue.h)
	 uint32_t test1 = 7;
	 uint32_t test2 = 2;
	 PRINT_IMPORTANT("test1=%d", test1/test2);
	 test1 = 9;
	 test2 = 3;
	 PRINT_IMPORTANT("test2=%d", test1/test2);
	 test1 = 4;
	 test2 = 5;
	 PRINT_IMPORTANT("test3=%d", test1/test2);

	 int32_t test3 = 7;
	 int32_t test4 = 2;
	 PRINT_IMPORTANT("test4=%d", test3/test4);
	 test3 = 9;
	 test4 = 3;
	 PRINT_IMPORTANT("test5=%d", test3/test4);
	 test3 = 4;
	 test4 = 5;
	 PRINT_IMPORTANT("test6=%d", test3/test4);

	 double test5 = 7;
	 double test6 = 2;
	 PRINT_IMPORTANT("test7=%f", test5/test6);
	 test5 = 9;
	 test6 = 3;
	 PRINT_IMPORTANT("test8=%f", test5/test6);
	 test5 = 4;
	 test6 = 5;
	 PRINT_IMPORTANT("test9=%f", test5/test6);
	 }

	if (0) { //test interfaces
		int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

		struct ifreq ifr;
		int num;
		for (num = 0; num < 20; num++) {
			ifr.ifr_ifindex = num;
			ret = ioctl(fd, SIOCGIFNAME, &ifr);
			PRINT_IMPORTANT("ifr_ifindex=%d, ifr_name='%s'", ifr.ifr_ifindex, ifr.ifr_name);
			//printf("ifr_ifindex=%d, ifr_name='%s'\n", ifr.ifr_ifindex, ifr.ifr_name);
		}

		close(fd);
		printf("FIN, waiting\n");
		while (1)
			;
		return;
	}

	 PRINT_IMPORTANT("Gaining su status");
	 if ((ret = system("su"))) {
	 PRINT_ERROR("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	 }
	 */

	(void) signal(SIGINT, capturer_termination_handler);

	PRINT_IMPORTANT("Attempting to make " FINS_TMP_ROOT "");
	if ((ret = system("mkdir " FINS_TMP_ROOT))) {
		PRINT_IMPORTANT(FINS_TMP_ROOT " already exists! Cleaning...");
		// if cannot create directory, assume it contains files and try to delete them
	}
	fflush(stdout);

	char device[20];
	device[19] = '\0';
	//strcpy(device, "lo");
	//strcpy(device, "eth0");
	//strcpy(device, "eth1");
	//strcpy(device, "eth2");
	strcpy(device, "wlan0");
	//strcpy(device, "wlan4");

	pid_t pID = 0;
	pID = fork();
	if (pID < 0) { // failed to fork
		PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
		exit(1);
	} else if (pID == 0) { // child -- Capture process
		PRINT_DEBUG("capture: pID=%d", (int)pID);
		prctl(PR_SET_PDEATHSIG, SIGHUP);

		char device_capture[20];
		strcpy(device_capture, device);
		capture_init(device_capture);
		while (1)
			;
	} else { // parent
		PRINT_DEBUG("inject: pID=%d", (int)pID);
		char device_inject[20];
		strcpy(device_inject, device);
		inject_init(device_inject);
	}

	if (inject_handle != NULL) {
		pcap_close(inject_handle);
		inject_handle = NULL;
	}

	if (capture_handle != NULL) {
		pcap_close(capture_handle);
		capture_handle = NULL;
	}
	exit(0);
}

#ifdef BUILD_FOR_ANDROID
int main(int argc, char **argv) {
	capturer_main();
	return 0;
}
#else
int main() {
	capturer_main();
	return 0;
}
#endif

// end of main function
