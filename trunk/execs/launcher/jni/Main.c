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

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "FINS", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "FINS", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "FINS", __VA_ARGS__))

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <core.h>
#define FINSBOOT_MSG "The writable directory used for the capturer/injector fifo is: "

/**
 * Our saved state data.
 */
struct saved_state {
	float angle;
	int32_t x; //replace
	int32_t y; //replace
};

/**
 * Shared state for our app.
 */
struct engine {
	struct android_app* app;

	int animating;
	int running;
	struct saved_state state;
};

/**
 * Process the next input event.
 */
static int32_t engine_handle_input(struct android_app* app, AInputEvent* event) {
	//struct engine* engine = (struct engine*) app->userData;
	return 0;
}

/**
 * Process the next main command.
 */
static void engine_handle_cmd(struct android_app* app, int32_t cmd) {
	struct engine* engine = (struct engine*) app->userData;
	switch (cmd) {
	case APP_CMD_INPUT_CHANGED:
		LOGI("APP_CMD_INPUT_CHANGED");
		break;
	case APP_CMD_INIT_WINDOW:
		LOGI("APP_CMD_INIT_WINDOW");
		// The window is being shown, get it ready.
		if (engine->app->window != NULL) {
			LOGI("init display");
			LOGI("draw frame");
			//engine_init_display(engine);
			//engine_draw_frame(engine);
		}
		break;
	case APP_CMD_TERM_WINDOW:
		LOGI("APP_CMD_TERM_WINDOW");
		// The window is being hidden or closed, clean it up.
		//engine_term_display(engine);
		engine->animating = 0;
		LOGI("term display");
		break;
	case APP_CMD_WINDOW_RESIZED:
		LOGI("APP_CMD_WINDOW_RESIZED");
		break;
	case APP_CMD_WINDOW_REDRAW_NEEDED:
		LOGI("APP_CMD_WINDOW_REDRAW_NEEDED");
		break;
	case APP_CMD_CONTENT_RECT_CHANGED:
		LOGI("APP_CMD_CONTENT_RECT_CHANGED");
		break;
	case APP_CMD_GAINED_FOCUS:
		LOGI("APP_CMD_GAINED_FOCUS");
		// When our app gains focus, we start monitoring the accelerometer.
		break;
	case APP_CMD_LOST_FOCUS:
		LOGI("APP_CMD_LOST_FOCUS");
		// When our app loses focus, we stop monitoring the accelerometer.
		// This is to avoid consuming battery while not being used.
		// Also stop animating.
		engine->animating = 0;
		//engine_draw_frame(engine);
		LOGI("draw frame");
		break;
	case APP_CMD_CONFIG_CHANGED:
		LOGI("APP_CMD_CONFIG_CHANGED");
		break;
	case APP_CMD_LOW_MEMORY:
		LOGI("APP_CMD_LOW_MEMORY");
		break;
	case APP_CMD_START:
		LOGI("APP_CMD_START");
		break;
	case APP_CMD_RESUME:
		LOGI("APP_CMD_RESUME");
		break;
	case APP_CMD_SAVE_STATE:
		LOGI("APP_CMD_SAVE_STATE");
		// The system has asked us to save our current state.  Do so.
		engine->app->savedStateSize = sizeof(struct saved_state);
		engine->app->savedState = malloc(engine->app->savedStateSize);
		struct saved_state *state = (struct saved_state *) engine->app->savedState;
		*state = engine->state;
		break;
	case APP_CMD_PAUSE:
		LOGI("APP_CMD_PAUSE");
		break;
	case APP_CMD_STOP:
		LOGI("APP_CMD_STOP");
		break;
	case APP_CMD_DESTROY:
		LOGI("APP_CMD_DESTROY");
		break;
	default:
		LOGI("default: cmd=%d", cmd);
		break;
	}
}

void android_main(struct android_app *state) {
	app_dummy();

	//TODO-Have this update a variable, and use that to establish the pipes, sockets for improved compatibility with future android versions
	char *writeLocation = (char *) state->activity->internalDataPath;
	char *bootmsg = FINSBOOT_MSG;

	LOGI(bootmsg);
	LOGI("internalDataPath='%s'", writeLocation);

	struct engine engine;
	memset(&engine, 0, sizeof(engine));

	state->userData = &engine;
	state->onAppCmd = engine_handle_cmd;
	state->onInputEvent = engine_handle_input;
	engine.app = state;

	if (state->savedState != NULL) {
		// We are starting with a previous saved state; restore from it.
		engine.state = *(struct saved_state*) state->savedState;
	}

	int ret;
	if (0) {
		LOGI("Gaining su status");
		if ((ret = system("su"))) {
			LOGE("SU failure: ret=%d, errno=%u, str='%s'", ret, errno, strerror(errno));
		}
	}

	//apk can access files in /data as well but can't write to anything
	core_dummy();
	core_main((uint8_t *) (FINS_TMP_ROOT "/envi.cfg"), (uint8_t *) (FINS_TMP_ROOT "/stack.cfg"));

	core_tests(); //For random testing purposes
	//core_termination_handler(0); //############ terminating

	// loop waiting for stuff to do.
	while (1) {
		// Read all pending events.
		int ident;
		int events;
		struct android_poll_source* source;

		// If not animating, we will block forever waiting for events.
		// If animating, we loop until all events are read, then continue
		// to draw the next frame of animation.
		while ((ident = ALooper_pollAll(engine.animating ? 0 : -1, NULL, &events, (void**) &source)) >= 0) {

			// Process this event.
			if (source != NULL) {
				source->process(state, source);
			}

			// If a sensor has data, process it now.
			if (ident == LOOPER_ID_USER) {
			}

			// Check if we are exiting.
			if (state->destroyRequested != 0) {
				//engine_term_display(&engine);
				engine.animating = 0;
				LOGE("exiting main return");
				//return;
			}
		}

		if (engine.animating) {
			// Done with events; draw next animation frame.
			//engine.state.angle += .01f; //change state?

			// Drawing is throttled to the screen update rate, so there
			// is no need to do timing here.
			//engine_draw_frame(&engine);
			//LOGI("draw frame");
		}
	}
}
