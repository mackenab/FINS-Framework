LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#FULL_LIBRARY_LIST = $(sort $(dir $(shell find . -type d -print -maxdepth0)))
#DIRS := ${sort ${dir ${wildcard ./*/}}}
#DIRS := $(dir $(wildcard ./*/))
TEST = $(wildcard $(FULL_LIBRARY_LIST))
#DIRS := $(foreach dir,$(dirs),$(wildcard $(dir)/*))

FULL_LIBRARY_LIST = common data_structure libconfig libglue libpcap

#### TARGETS ####
.PHONY:all
all:
	@$(foreach lib,$(FULL_LIBRARY_LIST), cd $(lib); $(MAKE) all; cd $(LOCAL_DIR);)

#.PHONY:%
%:
	@echo "test"; cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach lib,$(FULL_LIBRARY_LIST), cd $(lib); $(MAKE) clean; cd $(LOCAL_DIR);)
	
test:
	@echo "FULL_LIBRARY_LIST='$(FULL_LIBRARY_LIST)'"
	@echo "TEST='$(TEST)'"
	@echo "DIRS='$(DIRS)'"