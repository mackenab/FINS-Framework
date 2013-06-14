LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
#include $(FINS_ROOT_DIR)/settings.finsmk #can't be included because of CC/LD assignments

##### code from settings.finsmk that is relevant, since settings can't be included
BUILD_FOR_ANDROID_ARM = "If uncommented, the FINS source will build for android arch-ARM."

ifdef BUILD_FOR_ANDROID_ARM
NDK_PLATFORM_VER := 14
ANDROID_NDK_ROOT := /opt/android/android-ndk-r8e
PREBUILT_ROOT := /opt/android/prebuilt
USR := $(ANDROID_NDK_ROOT)/platforms/android-$(NDK_PLATFORM_VER)/arch-arm/usr
#BIN := $(PREBUILT_ROOT)/linux-x86/toolchain/arm-eabi-4.4.3/bin
BIN := $(ANDROID_NDK_ROOT)/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin
INSTALL_DIR := /data/local/fins
else
INSTALL_DIR := /lib/modules/$(shell uname -r)/kernel/fins 
endif
OBJ_DIR := $(FINS_ROOT_DIR)/obj
#####

#Name of the module
LOCAL_NAME = wedge
LOCAL_LIBS := 
LOCAL_MODS := 
LOCAL_OBJS := 
LOCAL_INCS := 
LOCAL_CFLAGS :=
LOCAL_LDFLAGS := 

obj-m += fins_stack_wedge.o

ifdef BUILD_FOR_ANDROID_ARM
#clears needed for module build system
#CC=cc #doesn't work
CFLAGS := 
#LD=ld #doesn't work
LDFLAGS :=
#tried combos of = & :=, and just empty

#apparently non-affective: NDK_PLATFORM_VER, ANDROID_NDK_ROOT, USR, BIN, CCOPTS, INCLS, LDOPTS, LIBPATHS, LIBS 
#undefine LDFLAGS

ARCH = arm
COMPILER = $(PREBUILT_ROOT)/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
#COMPILER = $(ANDROID_NDK_ROOT)/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/arm-linux-androideabi-
KERNEL_DIR =  /home/fins1/FINS/android_source/tegra
else
#clears needed for module build system
CC := gcc
CFLAGS :=
LD := ld
LDFLAGS :=

ARCH = x86
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
endif


.PHONY:all
all:$(LOCAL_NAME)
	@echo "compiled[$(MAKELEVEL)]:'$(LOCAL_NAME)'\n"

$(LOCAL_NAME):
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules
else
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) modules
endif
	@cp fins_stack_wedge.ko $(OBJ_DIR)

.PHONY:clean
clean:
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) clean
else
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) clean
endif
	@rm -f $(OBJ_DIR)/fins_stack_wedge.ko

.PHONY:clean_full
clean_full:
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) clean
else
	@make -I . -C $(KERNEL_DIR) M=$(PWD) ARCH=$(ARCH) clean
endif
	@rm -f $(OBJ_DIR)/fins_stack_wedge.ko

.PHONY:install
install: $(INSTALL_DIR)
ifdef BUILD_FOR_ANDROID_ARM
	@adb push fins_stack_wedge.ko $(INSTALL_DIR)
else
	@sudo cp -f fins_stack_wedge.ko $(INSTALL_DIR)
	@sudo depmod
endif

$(INSTALL_DIR):
ifdef BUILD_FOR_ANDROID_ARM
else
	@sudo mkdir $(INSTALL_DIR)
endif

test:
	@echo "CC='$(CC)'"
	@echo "CFLAGS='$(CFLAGS)'"
	@echo "LD='$(LD)'"
	@echo "LDFLAGS='$(LDFLAGS)'"