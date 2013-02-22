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
	PRINT_IMPORTANT("**Number of captured frames = %d", server_capture_count);
	PRINT_IMPORTANT("****Number of Injected frames = %d", server_inject_count);
	
	if (inject_handle != NULL) {
	  pcap_close(inject_handle);
	}

	if (capture_handle != NULL){
	  pcap_close(capture_handle);
	}
	exit(2);
}

void capturer_dummy(void) {

}

void capturer_main(void) {
	PRINT_IMPORTANT("Entered");

	print_app_banner();

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

  //while(1);

	(void) signal(SIGINT, capturer_termination_handler);

	int ret;
	/*
	PRINT_IMPORTANT("Gaining su status");
	if ((ret = system("su"))) {
		PRINT_ERROR("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	}
	*/

	PRINT_IMPORTANT("Attempting to make " FINS_TMP_ROOT "");
	if ((ret = system("mkdir " FINS_TMP_ROOT))) {
		PRINT_IMPORTANT(FINS_TMP_ROOT " already exists! Cleaning...");
		// if cannot create directory, assume it contains files and try to delete them
		if ((ret = system("cd " FINS_TMP_ROOT ";rm *"))) {
			PRINT_ERROR("File removal fail: ret=%d, errno=%u, str='%s', path='%s'", ret, errno, strerror(errno), FINS_TMP_ROOT);
		} else {
			PRINT_IMPORTANT(FINS_TMP_ROOT " was cleaned successfully.");
		}
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
	//pID = fork();
	if (pID < 0) { // failed to fork
		PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
		exit(1);
	} else if (pID == 0) { // child -- Capture process
		prctl(PR_SET_PDEATHSIG, SIGHUP);

		char device_capture[20];
		strcpy(device_capture, device);
		capture_init(device_capture);
		while (1);
	} else { // parent
		char device_inject[20];
		strcpy(device_inject, device);
		inject_init(device_inject);
		while (1);
	}

  if (inject_handle != NULL) {
    pcap_close(inject_handle);
	  inject_handle = NULL;
	}

	if (capture_handle != NULL) {
	  pcap_close(capture_handle);
	  capture_handle = NULL;
	}
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
