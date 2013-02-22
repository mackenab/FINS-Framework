LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_STATIC_LIBRARIES := types_meta queue_queMod
LOCAL_MODULE := RTM
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
#LOCAL_SRC_FILES := rtm.c finstypes.c
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)
