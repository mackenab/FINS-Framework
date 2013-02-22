LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_common
#LOCAL_SRC_FILES := finstypes.c finstime.c finsthreads.c getMAC_Address.c metadata.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := libconfig
LOCAL_LDLIBS := -llog
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_EXPORT_LDLIBS := -llog
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,libs/libconfig/lib)