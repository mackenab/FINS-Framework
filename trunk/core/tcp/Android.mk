LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_STATIC_LIBRARIES := types_meta queue_queMod
LOCAL_MODULE := tcp
#LOCAL_SRC_FILES := tcp.c tcp_in.c tcp_out.c tcp_queue.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)
