LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_launcher
#LOCAL_SRC_FILES := Main.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES :=  android_native_app_glue fins_capturer fins_core
LOCAL_LDLIBS := -landroid -llog
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O0 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS := -landroid -llog
include $(BUILD_SHARED_LIBRARY)

#include $(LOCAL_PATH)/FINS-Framework/libs/libpcap/Android.mk
#NDK_MODULE_PATH := $(LOCAL_PATH):$(LOCAL_PATH)/../..
$(call import-add-path,$(LOCAL_PATH))
$(call import-add-path,$(LOCAL_PATH)/../..)

#import the native app glue module. This allows us to use all C code, contains JNI wrappers
$(call import-module,android/native_app_glue)
$(call import-module,capturer)
$(call import-module,core)
#$(call import-module,wedge)