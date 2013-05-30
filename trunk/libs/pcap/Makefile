LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#This is the Module name. This MUST be that same as the current directory!!!
LOCAL_NAME := pcap
LOCAL_LIBS := glue
LOCAL_OBJS = bpf_dump.o bpf/net/bpf_filter.o bpf_image.o etherent.o fad-gifc.o gencode.o grammar.o\
	inet.o nametoaddr.o optimize.o pcap.o pcap-linux.o savefile.o scanner.o version.o
LOCAL_INCS := .
LOCAL_CFLAGS := -fpic -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -Dlinux -D__GLIBC__ -D_GNU_SOURCE
LOCAL_LDFLAGS := -lc

include $(LIBS_DIR)/make_library.finsmk