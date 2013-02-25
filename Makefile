LOCAL_DIR := $(PWD)

export FINS_ROOT_DIR := $(LOCAL_DIR)

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#.PHONY:fin_root
#fins_root:
#	@echo $(PWD)
#echo "test"
#export FINS_ROOT_DIR

#### TARGETS ####
.PHONY:all
all:
	@$(foreach folder,$(FOLDER_LIST), cd $(folder); $(MAKE) all; cd $(LOCAL_DIR);)

.PHONY:trunk
trunk:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:prototypes
prototypes:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:examples
examples:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:tests
tests:
	@cd $@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:install
install:
	@$(foreach folder,$(FOLDER_LIST), cd $(folder); $(MAKE) install; cd $(LOCAL_DIR)/;)

.PHONY:%
%:
	@cd trunk; $(MAKE) $@; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach folder,$(FOLDER_LIST), cd $(folder); $(MAKE) clean; cd ../;)
