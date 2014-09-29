LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := core
LOCAL_MODS := switch interface ipv4 arp icmp tcp udp daemon logger rtm template logger_iperf
#LOCAL_MODS := $(subst /,,$(subst $(MODULES_DIR)/,,$(wildcard $(MODULES_DIR)/*/)))
#this code breaks if anything besides folders containing modules are in MODULES_DIR
LOCAL_OBJS := core.o
LOCAL_INCS := .
LOCAL_CFLAGS :=

ifdef BUILD_FOR_ANDROID_ARM
LOCAL_LIBS := config common data_structure #problem is data_structure not including common, & common not config, etc
LOCAL_LDFLAGS := -lc
else
LOCAL_LIBS := common data_structure
LOCAL_LDFLAGS := -lc -lpthread -lconfig -lrt -ldl -lm
endif

include $(EXECS_DIR)/make_executable.finsmk