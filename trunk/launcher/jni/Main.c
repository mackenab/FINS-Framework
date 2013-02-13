/*
 * Main.c
 * This is code that is called from the java part of android cellphones (the dalvik vm)
 * Author: Alexander Meijer
 * Date: Jul 15, 2012
 */



#include <android_native_app_glue.h>
#include <android/log.h>
#include <android/native_activity.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <ethermod.h>
#include <core.h>

#define FINSBOOT_MSG "The writable directory used for the capturer/injector fifo is: "

void android_main(struct android_app* pApplication ) {

	//TODO-Have this update a variable, and use that to establish the pipes, sockets for improved compatibility with future android versions
	char *writeLocation = (char *) pApplication->activity->internalDataPath;
	char * bootmsg = FINSBOOT_MSG;
	app_dummy();
	va_list lVarArgs;
	pid_t pid;

	__android_log_vprint(ANDROID_LOG_DEBUG, "FINSBOOT", bootmsg , lVarArgs);
	__android_log_vprint(ANDROID_LOG_DEBUG, "FINSBOOT", writeLocation ,lVarArgs);
	__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "Forking into capturermain() and main()", lVarArgs);

	//fork the process so that the capturer code and the core code can run in tandem
	if ((pid = fork()) < 0){
		__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "FORKING ERROR", lVarArgs);
	} else if (pid == 0){ /* child */
		prctl(PR_SET_PDEATHSIG, SIGHUP); //kill the child when the parent is stopped
		sleep(1);
		__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "Starting FINS: core_main()", lVarArgs);
		core_main();
		__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "Exiting FINS: core_main()", lVarArgs);
	} else { /* parent */
		__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "Starting FINS: capturer_main()", lVarArgs);
		capturer_main();
		__android_log_vprint(ANDROID_LOG_DEBUG, "FINS", "Exiting FINS: capturer_main()", lVarArgs);
	}
}
