LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#### TARGETS ####
.PHONY:all
all:
	@$(foreach exec,$(strip $(EXECS_LIST)), cd $(exec); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:capturer
capturer:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:core
core:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:launcher
launcher:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:scraper
scraper:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:wedge
wedge:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

%:
	@cd core; $(MAKE) $@; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach exec,$(EXECS_LIST), cd $(exec); $(MAKE) clean; cd $(LOCAL_DIR);)
