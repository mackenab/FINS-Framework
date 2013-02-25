LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_capturer
#LOCAL_SRC_FILES := ethermod.c wifistub.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES :=  libpcap fins_common
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,trunk/libs/libpcap)
$(call import-module,trunk/libs/common)