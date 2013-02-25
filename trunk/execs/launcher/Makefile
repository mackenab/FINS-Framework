LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := launcher
LOCAL_LIBS := 
LOCAL_MODS := 
LOCAL_OBJS := 
LOCAL_INCS := 
LOCAL_TYPE := reference #exec



#### TARGETS #####
.PHONY:all
all:$(LOCAL_NAME)
	@echo "$(LOCAL_NAME) is compiled\n"

.PHONY:update
update:
	@android update project -p . -t android-17 --subprojects

$(LOCAL_NAME):
	@ndk-build all
	@ant debug

.PHONY:clean
clean:
	@ndk-build clean

.PHONY:install
install: $(LOCAL_NAME)
	@adb install -r bin/fins_launcher-debug.apk
	
.PHONY:test
test:
	@echo "TEST='$(TEST)'"