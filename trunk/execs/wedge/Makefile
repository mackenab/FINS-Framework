LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
#include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME = wedge

INSTALL_DIR := /data/local/fins

obj-m += fins_stack_wedge.o

#BUILD_FOR_ANDROID_ARM = "If uncommented, the FINS source will build for android arch-ARM."
ifdef BUILD_FOR_ANDROID_ARM
##important ones options:
#stated to be these values, but doesn't work with them
#tried combos of = & :=, and just empty 
#CC=cc
#LD=ld
#clears needed
CFLAGS := 
LDFLAGS :=


##apparently non-affective
#NDK_PLATFORM_VER := 
#ANDROID_NDK_ROOT := 
#USR := 
#BIN := 
#CCOPTS := 
#INCLS :=
#LDOPTS := 
#LIBPATHS := 
#LIBS := 

#undefine LDFLAGS
ARCH = arm

COMPILER = /opt/android/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
#COMPILER = /opt/android/android-ndk-r8d/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/arm-linux-androideabi-

#KERNELDIR = /home/alex/jreed/android_source/omap #phone0
#KERNELDIR = /home/alex/jreed/android_source/msm #phone1
KERNELDIR =  /home/fins1/FINS/android_source/tegra #tablet1
else
CC := gcc
LD := ld
CFLAGS :=
LDFLAGS :=
endif


.PHONY:all
all:$(LOCAL_NAME)
	@echo "compiled[$(MAKELEVEL)]:'$(LOCAL_NAME)'\n"

$(LOCAL_NAME):
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules
else
	@make -I . -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
endif
	@cp -f fins_stack_wedge.ko ../../../obj/fins_stack_wedge.ko

.PHONY:clean
clean:
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) clean
else
	@make -I . -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif
	@rm -f ../../../obj/fins_stack_wedge.ko

.PHONY:install
install:
ifdef BUILD_FOR_ANDROID_ARM
	@adb push fins_stack_wedge.ko $(INSTALL_DIR)
else
endif

test:
	@echo "CC='$(CC)'"
	@echo "CFLAGS='$(CFLAGS)'"
	@echo "LD='$(LD)'"
	@echo "LDFLAGS='$(LDFLAGS)'"