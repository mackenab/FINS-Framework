LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := udp
LOCAL_LIBS := common data_structure 
LOCAL_OBJS := create_ff.o udp.o UDP_checksum.o udp_in.o udp_out.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
ifdef BUILD_FOR_ANDROID_ARM
LOCAL_LDFLAGS := -lc
else
LOCAL_LDFLAGS := -lc -lpthread
endif

include $(MODULES_DIR)/make_module.finsmk