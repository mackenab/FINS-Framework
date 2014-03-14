LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := console
LOCAL_LIBS := #common #data_structure
LOCAL_MODS := #rtm
LOCAL_OBJS := console.o
LOCAL_INCS := . ../../libs/common
LOCAL_CFLAGS :=
ifdef BUILD_FOR_ANDROID_ARM
LOCAL_LDFLAGS := -lc -lm #-ldl -lpthread
else
LOCAL_LDFLAGS := -lc -lm -lrt #-ldl -lpthread
endif

include $(EXECS_DIR)/make_executable.finsmk