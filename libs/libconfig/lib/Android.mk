LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))

LOCAL_MODULE := libconfig
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS := -lz

include $(BUILD_STATIC_LIBRARY)
