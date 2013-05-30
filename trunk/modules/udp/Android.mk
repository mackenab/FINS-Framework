LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_udp
#LOCAL_SRC_FILES := create_ff.c InputQueue_Read_local.c udp.c UDP_checksum.c udp_get_FF.c udp_in.c udp_out.c
#LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LS_C := create_ff.c udp.c UDP_checksum.c udp_in.c udp_out.c
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,trunk/libs/common)
$(call import-module,trunk/libs/data_structure)