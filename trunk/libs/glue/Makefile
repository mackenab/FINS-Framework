LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#This is the Module name. This MUST be that same as the current directory!!!
LOCAL_NAME := glue
LOCAL_LIBS := 
LOCAL_OBJS := glue.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
LOCAL_LDFLAGS := -lc

include $(LIBS_DIR)/make_library.finsmk