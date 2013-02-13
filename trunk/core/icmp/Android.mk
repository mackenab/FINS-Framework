LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_icmp
#LOCAL_SRC_FILES := icmp.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure fins_switch fins_ipv4
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)
$(call import-module,core/data_structure)
$(call import-module,core/switch)
$(call import-module,core/ipv4)