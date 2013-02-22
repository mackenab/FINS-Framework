#set local path 
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_core
#LOCAL_SRC_FILES := core.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_switch fins_daemon fins_arp fins_interface fins_ipv4 fins_icmp fins_tcp fins_udp fins_rtm fins_logger
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)
$(call import-module,core/switch)
$(call import-module,core/daemon)
$(call import-module,core/arp)
$(call import-module,core/interface)
$(call import-module,core/ipv4)
$(call import-module,core/icmp)
$(call import-module,core/tcp)
$(call import-module,core/udp)
#$(call import-module,core/rtm)
$(call import-module,core/logger)