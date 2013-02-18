LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_daemon
#LOCAL_SRC_FILES := daemon.c icmpHandling.c tcpHandling.c udpHandling.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_switch
#LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../launcher/jni/libs/libconfig/lib $(LOCAL_PATH)/../../common $(LOCAL_PATH)/../data_structure $(LOCAL_PATH)/../switch
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O0 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)
$(call import-module,core/switch)