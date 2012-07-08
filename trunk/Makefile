# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk


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

.PHONY:core
core:
	@cd $@; $(MAKE) all

.PHONY:wedge
wedge:
	@cd $@; $(MAKE) all

.PHONY:clean
clean:
	@$(foreach project,$(PROJECT_LIST), cd $(project); $(MAKE) clean; cd ../;)
