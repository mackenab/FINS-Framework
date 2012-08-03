LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_STATIC_LIBRARIES := types_meta queue_queMod
LOCAL_MODULE := ipv4
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
#LOCAL_SRC_FILES := IP4_checksum.c IP4_const_header.c IP4_dest_check.c IP4_exit.c IP4_forward.c IP4_fragment_data.c IP4_in.c IP4_init.c IP4_next_hop.c IP4_out.c IP4_reass.c IP4_receive_fdf.c IP4_route_info.c IP4_send_fdf.c ipv4.c
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)

include $(BUILD_STATIC_LIBRARY)
