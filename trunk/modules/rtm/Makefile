LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module, must be equal to folder
LOCAL_NAME := rtm
LOCAL_LIBS := common data_structure 
LOCAL_OBJS := rtm.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
LOCAL_LDFLAGS := -lc -lpthread

include $(MODULES_DIR)/make_module.finsmk