LOCAL_PATH:=$(call my-dir)
include $(CLEAR_VARS)

LOCAL_STATIC_LIBRARIES := types_meta
LOCAL_MODULE := queue_queMod
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
#LOCAL_C_INCLUDES := data_structure
#LOCAL_SRC_FILES := queue.c queueModule.c
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)

include $(BUILD_STATIC_LIBRARY)
