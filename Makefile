#export the FINS_ROOT_DIR
FINS_ROOT_DIR = $(shell pwd)
export FINS_ROOT_DIR 

# fins.mk contains the compiler and linker options for each target platform
include settings.finsmk


#### TARGETS ####
.PHONY:all
all:
	@$(foreach project,$(PROJECT_LIST), cd $(project); $(MAKE) all; cd ../;)

.PHONY:capturer
capturer:
	@cd $@; $(MAKE) all

.PHONY:common
common:
	@cd $@; $(MAKE) all

.PHONY:socketdaemon
socketdaemon:
	@cd $@; $(MAKE) all

.PHONY:interceptor
interceptor:
	@cd $@; $(MAKE) all

.PHONY:clean
clean:
	@$(foreach project,$(PROJECT_LIST), cd $(project); $(MAKE) clean; cd ../;)
