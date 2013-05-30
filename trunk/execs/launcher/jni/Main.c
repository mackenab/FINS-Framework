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
//#include <pcap.h>
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

//#define SNAP_LEN 8192//4096
//#include "wifistub.h"
//#include <ethermod.h>

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

	__android_log_print(ANDROID_LOG_INFO, "FINS", bootmsg);
	__android_log_print(ANDROID_LOG_INFO, "FINS", writeLocation);
	__android_log_print(ANDROID_LOG_INFO, "FINS", "Forking into capturermain() and main()");

	/*
	 int ret;
	 __android_log_print(ANDROID_LOG_INFO, "FINS", "Gaining su status");
	 if ((ret = system("su"))) {
	 __android_log_print(ANDROID_LOG_ERROR, "FINS", "SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
	 }
	 */
	if (0) {
		int i = 0;
		while (i < 1000) {
			__android_log_print(ANDROID_LOG_INFO, "FINS", "i=%d", i++);
			sleep(2);
		}
		return;
	}

	__android_log_print(ANDROID_LOG_INFO, "FINS", "Starting FINS: core_main()");
	core_dummy();
	core_main("envi.cfg", "stack.cfg");
	while (1)
		;
	//sleep(1);
	__android_log_print(ANDROID_LOG_INFO, "FINS", "Exiting FINS: core_main()");
}
