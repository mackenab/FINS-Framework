LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := core
LOCAL_LIBS := common data_structure #$(CORE_LIBS)
LOCAL_MODS := switch interface ipv4 arp udp rtm logger icmp
#LOCAL_MODS := $(subst /,,$(subst $(MODULES_DIR)/,,$(wildcard $(MODULES_DIR)/*/)))
#this code breaks if anything besides folders containing modules are in MODULES_DIR
LOCAL_OBJS := core.o test/test.o
LOCAL_INCS := .
LOCAL_CFLAGS :=
LOCAL_LDFLAGS := -lc -ldl -lpthread

include $(EXECS_DIR)/make_executable.finsmk