#set local path 
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_core
#LOCAL_SRC_FILES := core.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure fins_switch fins_daemon fins_arp fins_interface fins_ipv4 fins_icmp fins_tcp fins_udp fins_rtm fins_logger fins_logger_iperf
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,trunk/libs/common)
$(call import-module,trunk/libs/data_structure)
$(call import-module,trunk/modules/switch)
$(call import-module,trunk/modules/daemon)
$(call import-module,trunk/modules/arp)
$(call import-module,trunk/modules/interface)
$(call import-module,trunk/modules/ipv4)
$(call import-module,trunk/modules/icmp)
$(call import-module,trunk/modules/tcp)
$(call import-module,trunk/modules/udp)
$(call import-module,trunk/modules/rtm)
$(call import-module,trunk/modules/logger)
$(call import-module,trunk/modules/logger_iperf)