LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#This is the Module name. This MUST be that same as the current directory!!!
LOCAL_NAME := config
LOCAL_LIBS := 
LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))
LOCAL_SRC_FILES := $(call LS_C,$(LOCAL_DIR)/lib)
#LOCAL_OBJS := $(subst .c,.o,$(LOCAL_SRC_FILES))
LOCAL_OBJS := lib/grammar.o lib/libconfig.o lib/scanctx.o lib/scanner.o lib/strbuf.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
LOCAL_LDFLAGS := -lc -lz

include $(LIBS_DIR)/make_library.finsmk