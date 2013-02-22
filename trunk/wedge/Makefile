LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
#include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
PROJECT_NAME = wedge

obj-m += fins_stack_wedge.o

#BUILD_FOR_ANDROID_ARM = "If uncommented, the FINS source will build for android arch-ARM."
ifdef BUILD_FOR_ANDROID_ARM
CFLAGS :=
LDFLAGS :=
#undefine LDFLAGS
COMPILER = /home/alex/jreed/android_source/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
ARCH =arm
KERNELDIR = /home/alex/jreed/android_source/omap
else
CC := gcc
LD := ld
CFLAGS :=
LDFLAGS :=
endif


.PHONY:all
all:$(PROJECT_NAME)
	@echo "$(PROJECT_NAME) is compiled\n"

$(PROJECT_NAME):
ifdef BUILD_FOR_ANDROID_ARM
	make -I . -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) modules
else
	make -I . -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
endif

.PHONY:clean
clean:
ifdef BUILD_FOR_ANDROID_ARM
	@make -I . -C $(KERNELDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(COMPILER) clean
else
	@make -I . -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
endif

.PHONY:install
install:
ifdef BUILD_FOR_ANDROID_ARM
	@adb push fins_stack_wedge.ko /data/local/tmp
else
endif
		