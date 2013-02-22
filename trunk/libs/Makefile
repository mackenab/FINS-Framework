LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk


#### TARGETS ####
.PHONY:all
all:
	@$(foreach library,$(LIBRARY_LIST), cd $(library); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:common
common:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:libpcap
libpcap:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:libglue
libglue:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach library,$(LIBRARY_LIST), cd $(library); $(MAKE) clean; cd $(LOCAL_DIR);)
