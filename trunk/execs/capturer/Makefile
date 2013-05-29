LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := capturer
ifndef BUILD_FOR_ANDROID_ARM
LOCAL_LIBS := 
else
LOCAL_LIBS := pcap
endif
LOCAL_MODS := 
LOCAL_OBJS := ethermod.o htoi.o wifistub.o
LOCAL_INCS := . ../../libs/common
LOCAL_CFLAGS :=
LOCAL_LDFLAGS := -lc -lpcap

include $(EXECS_DIR)/make_executable.finsmk