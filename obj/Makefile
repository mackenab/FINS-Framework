LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

##### TARGETS #####
#.PHONY:all
all:
	@cd $(FINS_ROOT_DIR); make $@; cd $(LOCAL_DIR);

%:
	@cd $(FINS_ROOT_DIR); make $@; cd $(LOCAL_DIR);