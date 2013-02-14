LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_launcher
#LOCAL_SRC_FILES := Main.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES :=  android_native_app_glue fins_capturer fins_core
LOCAL_LDLIBS := -landroid -llog #-lc -ldl -lm #-lpthread -lconfig -lpcap -lrt
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS := -landroid -llog
#top makefile level must build a shared library, only 1 shared library per app
include $(BUILD_SHARED_LIBRARY)

#include $(LOCAL_PATH)/FINS-Framework/libs/libpcap/Android.mk
#NDK_MODULE_PATH := $(LOCAL_PATH):$(LOCAL_PATH)/../..
$(call import-add-path,$(LOCAL_PATH))
$(call import-add-path,$(LOCAL_PATH)/../..)

#import the native app glue module. This allows us to use all C code, contains JNI wrappers
$(call import-module,android/native_app_glue)

$(call import-module,libs/libpcap)
$(call import-module,libs/libconfig/lib)
$(call import-module,common)
$(call import-module,core/data_structure)
$(call import-module,core/switch)

$(call import-module,capturer)
$(call import-module,core)
#$(call import-module,wedge)