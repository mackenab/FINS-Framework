#set local path 
LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

#the core.c file needs functions from the following static libraries
LOCAL_STATIC_LIBRARIES := types_meta libconfig queue_queMod ipv4 udp tcp arpModule switch RTM ICMP daemon capturer
LOCAL_MODULE := finsUspace
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
#LOCAL_SRC_FILES := core.c

#all the Android.mk files have this flag, since all the code must be built for android if this ndk-build system is used
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID

#export headers
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)
