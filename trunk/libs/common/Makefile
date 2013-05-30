LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#This is the Module name. This MUST be that same as the current directory!!!
LOCAL_NAME := common
LOCAL_OBJS := getMAC_Address.o metadata.o finstypes.o finstime.o finsthreads.o
LOCAL_CFLAGS := -fpic

ifdef BUILD_FOR_ANDROID_ARM
LOCAL_LIBS := config
LOCAL_INCS := . ../config/lib
LOCAL_LDFLAGS := -lc -lm
else
LOCAL_LIBS := 
LOCAL_INCS := .
LOCAL_LDFLAGS := -lc -lm -lrt -lpthread -lconfig
endif

include $(LIBS_DIR)/make_library.finsmk