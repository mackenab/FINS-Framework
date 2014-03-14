LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../..)
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#FULL_LIBRARY_LIST = $(sort $(dir $(shell find . -type d -print -maxdepth0)))
#DIRS := ${sort ${dir ${wildcard ./*/}}}
#DIRS := $(dir $(wildcard ./*/))
#TEST = $(wildcard $(FULL_LIBRARY_LIST))
#DIRS := $(foreach dir,$(dirs),$(wildcard $(dir)/*))

MODULES_LIST_ALL = arp daemon icmp interface ipv4 logger rtm switch tcp udp template
#TEST := $(subst /,,$(subst $(LIBS_DIR)/,,$(wildcard $(LIBS_DIR)/*/)))
#TEST := $(wildcard $(LIBS_DIR)/*/)

#### TARGETS ####
.PHONY:all
all:
	@$(foreach lib,$(MODULES_LIST_ALL), cd $(lib); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:clean
clean:
	@$(foreach lib,$(MODULES_LIST_ALL), cd $(lib); $(MAKE) clean; cd $(LOCAL_DIR);)

.PHONY:clean_full
clean_full:
	@$(foreach lib,$(MODULES_LIST_ALL), cd $(lib); $(MAKE) clean_full; cd $(LOCAL_DIR);)
	
test:
	@echo "TEST='$(TEST)'"
	
#.PHONY:%
%:
	@echo "test"; cd $@; $(MAKE) all; cd $(LOCAL_DIR);
	