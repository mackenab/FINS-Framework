LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#ifndef FINS_ROOT_DIR
#	TEMP := $(shell cd ../; make fins_root; cd $(LOCAL_DIR))
#endif
#.PHONY:fin_root
#fins_root:
#$(shell cd ../; make fins_root)
#echo "FINS_ROOT_DIR2='$(FINS_ROOT_DIR)'"
#FINS_ROOT_DIR='$(FINS_ROOT_DIR)'"
#ifeq ($(wildcard settings.finsmk),)
#@cd ../; $(MAKE) root; cd $(LOCAL_DIR);
#else 
#FINS_ROOT_DIR := $(LOCAL_DIR)
#export FINS_ROOT_DIR
#endif

#### TARGETS ####
.PHONY:all
all:
	@$(foreach project,$(PROJECT_LIST), cd $(project); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:capturer
capturer:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:common
common:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:core
core:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:launcher
launcher:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:libs
libs:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:wedge
wedge:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach project,$(PROJECT_LIST), cd $(project); $(MAKE) clean; cd $(LOCAL_DIR);)
