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

pcap_t *inject_handle;
pcap_t *capture_handle;

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
	exit(2);
}

void capturer_dummy(void) {

}

void capturer_main(void) {
	PRINT_IMPORTANT("Entered");

	print_app_banner();

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
	device[20] = '\0';
	//strcpy(device, "lo");
	//strcpy(device, "eth0");
	//strcpy(device, "eth1");
	//strcpy(device, "eth2");
	strcpy(device, "wlan0");
	//strcpy(device, "wlan4");

	pid_t pID = fork();
	if (pID < 0) { // failed to fork
		PRINT_ERROR("Fork error: pid=%d, errno=%u, str='%s'", pID, errno, strerror(errno));
		exit(1);
	} else if (pID == 0) { // child -- Capture process
		prctl(PR_SET_PDEATHSIG, SIGHUP);

		char device_capture[20];
		strcpy(device_capture, device);
		capture_init(device_capture);
		//while (1);
	} else { // parent
		char device_inject[20];
		strcpy(device_inject, device);
		inject_init(device_inject);
		//while (1);
	}

	/**
	 if (inject_handle != NULL);
	 pcap_close(inject_handle);

	 if (capture_handle != NULL);
	 pcap_close(capture_handle);
	 */
}

#ifndef BUILD_FOR_ANDROID
int main() {
	capturer_main();
	return 0;
}
#endif

// end of main function
