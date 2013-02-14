LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := fins_switch
#LOCAL_SRC_FILES := switch.c
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_PATH))
LOCAL_STATIC_LIBRARIES := fins_common fins_data_structure
#LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_C_INCLUDES := $(LOCAL_PATH) $(LOCAL_PATH)/.. $(LOCAL_PATH)/../data_structure $(LOCAL_PATH)/../switch $(LOCAL_PATH)/../../common

#LDOPTS = -g -O0 -Wall #flags for valgrind
#LIBS = -lpthread -lconfig -lpcap -lc -ldl -lm -lrt
#LOCAL_LDLIBS := #libs c,m,pthread,rt are automatic
#LOCAL_LDLIBS := -lconfig -lpcap
LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O0 -Wall $(LOCAL_C_INCLUDES:%=-I%)

LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
$(info switch LOCAL_C_INCLUDES='$(LOCAL_C_INCLUDES)')
$(info switch LOCAL_CFLAGS='$(LOCAL_CFLAGS)')
include $(BUILD_STATIC_LIBRARY)

#$(call import-module,common)
#$(call import-module,core/data_structure)
