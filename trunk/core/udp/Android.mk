LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_udp
#LOCAL_SRC_FILES := create_ff.c InputQueue_Read_local.c udp.c UDP_checksum.c udp_get_FF.c udp_in.c udp_out.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))

#need to filter out the syntactically incorrect file
$(info Note: UDP test code currently being excluded from build)
LOCAL_SRC_FILES := $(filter-out udp_test.c, $(LOCAL_SRC_FILES))

LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure fins_switch
LOCAL_LDLIBS := -landroid -llog -lc -ldl -lm
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

$(call import-module,common)
$(call import-module,core/data_structure)
$(call import-module,core/switch)