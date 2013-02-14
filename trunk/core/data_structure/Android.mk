LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_data_structure
#LOCAL_SRC_FILES := queue.c queueModule.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../common $(LOCAL_PATH)
#LOCAL_LDLIBS :=
#LOCAL_EXPORT_LDLIBS := 
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)