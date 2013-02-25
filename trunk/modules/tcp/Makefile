LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
export FINS_ROOT_DIR := $(abspath $(LOCAL_DIR)/../../..)
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME := tcp
LOCAL_LIBS := common
LOCAL_MODS := switch
LOCAL_OBJS := tcp.o tcp_in.o tcp_out.o
LOCAL_INCS := .
LOCAL_TYPE := reference #exec

STRIP_NAME := $(strip $(LOCAL_NAME))
STRIP_LIBS := $(strip $(LOCAL_LIBS))
STRIP_MODS := $(strip $(LOCAL_MODS))
STRIP_OBJS := $(strip $(LOCAL_OBJS))
STRIP_INCS := $(strip $(LOCAL_INCS))
STRIP_TYPE := $(strip $(LOCAL_TYPE))

LOCAL_MAKE_FILE := $(LOCAL_DIR)/Makefile
LOCAL_INCS_FILE := $(LOCAL_DIR)/INCS.finsmk
LOCAL_OBJS_FILE := $(LOCAL_DIR)/OBJS.finsmk

LIB_DIRS := $(addprefix $(LIBS_DIR)/,$(STRIP_LIBS))
MOD_DIRS := $(addprefix $(MODULES_DIR)/,$(STRIP_MODS))
INCS_DIRS := $(strip $(LIB_DIRS) $(MOD_DIRS))
INCS_FILES := $(addsuffix /INCS.finsmk,$(INCS_DIRS))

FULL_INCS_FILES := $(LOCAL_INCS_FILE) $(INCS_FILES)
LOCAL_INCS_DIRS := $(abspath $(addprefix $(LOCAL_DIR)/,$(STRIP_INCS)))

FULL_INCS = $(sort $(LOCAL_INCS_DIRS) $(shell cat $(FULL_INCS_FILES) 2> /dev/null))
CURR_INCS = $(shell cat $(LOCAL_INCS_FILE) 2> /dev/null)
OTHER_INCS = $(filter-out $(LOCAL_DIR),$(CURR_INCS))

INCLUDES = $(call filter_headers,$(CURR_INCS))
CFLAGS += $(addprefix -I,$(CURR_INCS))
#TCFLAGS = $(CFLAGS) $(addprefix -I,$(CURR_INCS))

LOCAL_OBJS_PATHS := $(addprefix $(LOCAL_DIR)/,$(STRIP_OBJS))
CURR_OBJS_FILES = $(addsuffix /OBJS.finsmk,$(CURR_INCS))
#OTHER_OBJS_FILES = $(addsuffix /OBJS.finsmk,$(OTHER_INCS))
CURR_OBJS = $(sort $(shell cat $(LOCAL_OBJS_FILE) $(CURR_OBJS_FILES) 2> /dev/null))

#	@ar rvs lib$(STRIP_NAME).a $(OBJS)
#TEST = $(shell cat TEST2 2> out.txt)

##### TARGETS #####
#.PHONY:all
all:setup build
	@echo "compiled[$(MAKELEVEL)]:'$(STRIP_NAME)'\n"	

.PHONY:setup
setup:$(LOCAL_INCS_FILE)
	@echo "setup[$(MAKELEVEL)]:'$(STRIP_NAME)'\n"

$(LOCAL_INCS_FILE):$(LOCAL_MAKE_FILE) $(INCS_FILES)
	@echo $(FULL_INCS) > $(LOCAL_INCS_FILE)

$(LIBS_DIR)/%/INCS.finsmk:$(LIBS_DIR)/%/Makefile
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@cd $(dir $@); $(MAKE) $@; cd $(LOCAL_DIR);
endif

$(MODULES_DIR)/%/INCS.finsmk:$(MODULES_DIR)/%/Makefile
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@cd $(dir $@); $(MAKE) $@; cd $(LOCAL_DIR);
endif

.PHONY:build
build:setup build_local build_others $(STRIP_TYPE)
	@echo "built[$(MAKELEVEL)]:'$(STRIP_NAME)'\n"

.PHONY:build_local
build_local:$(STRIP_OBJS) $(LOCAL_OBJS_FILE)
	@echo "local built[$(MAKELEVEL)]:'$(STRIP_NAME)'\n"

#%.o:%.c $(INCLUDES)
#	@echo "test1=$(LOCAL_DIR)"
#	@$(CC) $(CFLAGS) -c $< -o $@

$(LOCAL_DIR)/%.o:%.c $(INCLUDES)
#	@echo "test2=$(LOCAL_DIR)"
	@$(CC) $(CFLAGS) -c $< -o $@

$(LOCAL_OBJS_FILE):$(LOCAL_MAKE_FILE)
	@echo $(LOCAL_OBJS_PATHS) > $(LOCAL_OBJS_FILE)

.PHONY:build_others
build_others:
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@$(foreach DIR,$(OTHER_INCS),cd $(DIR); $(MAKE) build_local; cd $(LOCAL_DIR);)
endif

#.PHONY:reference
reference:
	@echo "reference"
	@echo "CURR_OBJS='$(CURR_OBJS)'"

#.PHONY:exec
exec:$(CURR_OBJS)
#	@echo "CURR_OBJS='$(CURR_OBJS)'"
	@$(LD) $(LDFLAGS) $(CURR_OBJS) -o $(OBJ_DIR)/$(STRIP_NAME)/$(STRIP_NAME) 

.PHONY:clean
clean:clean_local clean_$(STRIP_TYPE)
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@$(foreach DIR,$(INCS_DIRS),cd $(DIR); $(MAKE) clean; cd $(LOCAL_DIR);)
endif

clean_local:
	@rm -f *.o *.a
	@rm -f INCS.finsmk OBJS.finsmk
	@echo "cleaned[$(MAKELEVEL)]:$(STRIP_NAME)\n";

clean_reference:
#	@echo "clean"

clean_exec:
	@rm -f $(OBJ_DIR)/$(STRIP_NAME)/$(STRIP_NAME)
	
.PHONY:temp
temp:
	@echo "CFLAGS='$(CFLAGS)'"
	@echo "INCLUDES='$(INCLUDES)'"
	@echo "STRIP_OBJS='$(STRIP_OBJS)'"
	@echo "LOCAL_OBJS_PATHS='$(LOCAL_OBJS_PATHS)'\n"
#	@echo "CURR_INCS='$(CURR_INCS)'"
#	echo $(sort $(shell cat INCS.finsmk)) > $(LOCAL_DIR)/INCS.finsmk

.PHONY:test
test:
	@echo "TEST='$(TEST)'"