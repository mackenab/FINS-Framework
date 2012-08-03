#export the FINS_ROOT_DIR
FINS_ROOT_DIR = $(shell pwd)
export FINS_ROOT_DIR 

# fins.mk contains the compiler and linker options for each target platform
include settings.finsmk


#### TARGETS ####
.PHONY:all
all:
	@$(foreach folder,$(FOLDER_LIST), cd $(folder); $(MAKE) all; cd ../;)

.PHONY:trunk
trunk:
	@cd $@; $(MAKE) all

.PHONY:prototypes
prototypes:
	@cd $@; $(MAKE) all

.PHONY:examples
examples:
	@cd $@; $(MAKE) all

.PHONY:tests
tests:
	@cd $@; $(MAKE) all

.PHONY:clean
clean:
	@$(foreach folder,$(FOLDER_LIST), cd $(folder); $(MAKE) clean; cd ../;)
