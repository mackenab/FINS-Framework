LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

#NDK_MODULE_PATH := $(LOCAL_PATH)/FINS-Framework/libs

LOCAL_MODULE := fins_launcher
LOCAL_SRC_FILES := Main.c
LOCAL_STATIC_LIBRARIES :=  android_native_app_glue fins_capturer fins_core
LOCAL_LDLIBS := -landroid -llog
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
include $(BUILD_SHARED_LIBRARY)
#top makefile level must build a shared library, only 1 shared library per app

#include $(LOCAL_PATH)/FINS-Framework/libs/libpcap/Android.mk
$(call import-add-path,$(LOCAL_PATH))
$(call import-add-path,$(LOCAL_PATH)/../..)

#import the native app glue module. This allows us to use all C code, contains JNI wrappers
$(call import-module,android/native_app_glue)

#build & include libconfig, libpcap
#$(call import-module,libs/libconfig/lib) 
#$(call import-module,libs/libpcap)

#build capturer
$(call import-module,capturer)

#build the core
$(call import-module,core)

#build wedge
#$(call import-module,wedge)

#build all the modules
#$(call import-module,common)
#$(call import-module,FINS-Framework/trunk/core/data_structure)
#$(call import-module,FINS-Framework/trunk/core/ipv4)
#$(call import-module,FINS-Framework/trunk/core/udp)
#$(call import-module,FINS-Framework/trunk/core/tcp)
#$(call import-module,FINS-Framework/trunk/core/arp)
#$(call import-module,FINS-Framework/trunk/core/rtm)
#$(call import-module,FINS-Framework/trunk/core/icmp)
#$(call import-module,FINS-Framework/trunk/core/switch)
#$(call import-module,FINS-Framework/trunk/core/daemon)