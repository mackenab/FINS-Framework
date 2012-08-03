LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)


LOCAL_STATIC_LIBRARIES := types_meta queue_queMod
TEST_FILES := test_arp.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_MODULE := arpModule
#LOCAL_SRC_FILES := arp.c arp_in_out.c init_term_arp.c
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_EXPORT_LDLIBS := -lz
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID

include $(BUILD_STATIC_LIBRARY)
