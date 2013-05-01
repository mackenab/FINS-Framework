LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := ipv4
LOCAL_LIBS := common data_structure 
LOCAL_OBJS := IP4_checksum.o IP4_const_header.o IP4_dest_check.o IP4_exit.o IP4_forward.o IP4_fragment_data.o IP4_in.o IP4_init.o IP4_next_hop.o IP4_out.o IP4_reass.o IP4_receive_fdf.o IP4_route_info.o IP4_send_fdf.o ipv4.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic
LOCAL_LDFLAGS := -lc -lpthread

include $(MODULES_DIR)/make_module.finsmk