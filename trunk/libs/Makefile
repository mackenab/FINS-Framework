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

FULL_LIBRARY_LIST = common data_structure libconfig libglue libpcap
#TEST := $(subst /,,$(subst $(LIBS_DIR)/,,$(wildcard $(LIBS_DIR)/*/)))
#TEST := $(wildcard $(LIBS_DIR)/*/)

#### TARGETS ####
.PHONY:all
all:
	@$(foreach lib,$(FULL_LIBRARY_LIST), cd $(lib); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:clean
clean:
	@$(foreach lib,$(FULL_LIBRARY_LIST), cd $(lib); $(MAKE) clean; cd $(LOCAL_DIR);)
	
test:
	@echo "TEST='$(TEST)'"
	
#.PHONY:%
%:
	@echo "test"; cd $@; $(MAKE) all; cd $(LOCAL_DIR);
	