LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

#signals setttings.finsmk, not to set the values of CC, LD, CFLAGS, LDFLAGS
ALTERNATIVE_BUILD := "lkm"
# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

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
COMPILER = $(PREBUILT_ROOT)/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
#COMPILER = $(ANDROID_NDK_ROOT)/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86/bin/arm-linux-androideabi-
KERNEL_DIR =  /home/fins1/FINS/android_source/tegra
else
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
endif

##### TARGETS #####
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
	@echo "PREBUILT_ROOT='$(PREBUILT_ROOT)'"
	@echo "COMPILER='$(COMPILER)'"
	@echo "CC='$(CC)'"
	@echo "CFLAGS='$(CFLAGS)'"
	@echo "LD='$(LD)'"
	@echo "LDFLAGS='$(LDFLAGS)'"