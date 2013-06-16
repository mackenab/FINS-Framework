LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/..)
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
	@$(foreach exec,$(strip $(EXECS_LIST)), cd execs/$(exec); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:execs
execs:	
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:libs
libs:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:modules
modules:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:install
install:
	@$(foreach exec,$(strip $(EXECS_LIST)), cd execs/$(exec); $(MAKE) install; cd $(LOCAL_DIR);)

%:
	@cd execs; $(MAKE) $@; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach exec,$(EXECS_LIST), cd execs/$(exec); $(MAKE) clean; cd $(LOCAL_DIR);)

.PHONY:clean_full
clean_full:
	@cd $(EXECS_DIR); $(MAKE) clean_full; cd $(LOCAL_DIR);
	@cd $(LIBS_DIR); $(MAKE) clean_full; cd $(LOCAL_DIR);
	@cd $(MODULES_DIR); $(MAKE) clean_full; cd $(LOCAL_DIR);
