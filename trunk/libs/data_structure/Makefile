LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := data_structure
LOCAL_LIBS := common
LOCAL_OBJS := queue.o finsqueue.o finsmodule.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
LOCAL_LDFLAGS := -lc

include $(LIBS_DIR)/make_library.finsmk