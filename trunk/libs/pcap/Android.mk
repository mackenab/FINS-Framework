LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	bpf_dump.c\
	bpf/net/bpf_filter.c\
	bpf_image.c\
	etherent.c\
	fad-gifc.c\
	gencode.c\
	grammar.c\
	inet.c\
	nametoaddr.c\
	optimize.c\
	pcap.c\
	pcap-linux.c\
	savefile.c\
	scanner.c\
	version.c

LOCAL_CFLAGS := -DBUILD_FOR_ANDROID -g -O2 -Wall
LOCAL_CFLAGS += -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -Dlinux -D__GLIBC__ -D_GNU_SOURCE

LOCAL_STATIC_LIBRARIES := #libglue
LOCAL_LDLIBS := -llog
LOCAL_MODULE := libpcap
LOCAL_EXPORT_LDLIBS := -llog
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)

#$(call import-module,trunk/libs/libglue)