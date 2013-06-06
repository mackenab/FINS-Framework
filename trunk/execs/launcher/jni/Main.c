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

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "FINS", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "FINS", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "FINS", __VA_ARGS__))

void android_main(struct android_app *state) {
	app_dummy();

	/*
	 core_dummy();
	 switch_dummy();
	 interface_dummy();
	 arp_dummy();
	 ipv4_dummy();
	 icmp_dummy();
	 tcp_dummy();
	 udp_dummy();
	 daemon_dummy();
	 logger_dummy();
	 rtm_dummy();
	 */

	//TODO-Have this update a variable, and use that to establish the pipes, sockets for improved compatibility with future android versions
	char *writeLocation = (char *) state->activity->internalDataPath;
	char *bootmsg = FINSBOOT_MSG;

	LOGI(bootmsg);
	LOGI("internalDataPath='%s'", writeLocation);

	int ret;

	if (0) {
		LOGI("Gaining su status");
		if ((ret = system("su"))) {
			LOGE("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}
	if (0) {
		if ((ret = system("su -c mkdir test_mkdir"))) {
			LOGE("SU mkdir failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}
	if (0) {
		if ((ret = setenv("LD_LIBRARY_PATH", "/data/data/com.BU_VT.FINS/files/", 1))) {
			LOGE("set env failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}
	if (0) {
		if ((ret = system("/data/local/fins/test"))) {
			LOGE("test failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}

	if (0) {
		int i = 0;
		while (i < 1000) {
			LOGI("i=%d", i++);
			sleep(2);
		}
		return;
	}

	LOGI("Starting FINS: core_main() ############################################################");
	//apk can access files in /data as well but can't write to anything
	core_dummy();
	core_main((uint8_t *) (FINS_TMP_ROOT "/envi.cfg"), (uint8_t *) (FINS_TMP_ROOT "/stack.cfg"));
	while (1)
		;
	//sleep(1);
	LOGI("Exiting FINS: core_main() ############################################################");
}
