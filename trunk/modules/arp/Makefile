LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME = arp
LOCAL_LIBS = common
LOCAL_MODULES = switch
LOCAL_OBJS = arp.o arp_in_out.o
LOCAL_INCS = .

FULL_LOCAL_INCS = $(addprefix $(LOCAL_DIR)/,$(LOCAL_INC))
LOCAL_HEADERS = $(call filter_headers, $(FULL_LOCAL_INCS))
LOCAL_INCLUDES = $(add_prefix -I,$(LOCAL_HEADERS))

FULL_OBJS = $(addprefix $(LOCAL_DIR)/,$(LOCAL_OBJS))
FULL_OBJS += $(call lib_objs, $(LOCAL_LIBS))
FULL_OBJS += $(call module_objs, $(LOCAL_MODULES))
OBJS = $(sort $(FULL_OBJS))

FULL_INCS = $(addprefix $(LOCAL_DIR)/,$(LOCAL_INC))
FULL_INCS += $(call lib_incs,$(LOCAL_LIBS))
FULL_INCS += $(call module_incs,$(LOCAL_MODULES))
INCS = $(sort $(FULL_INCS)) 

INCLUDES = $(call filter_headers, $(INCS))
CFLAGS += $(add_prefix -I,$(INCS))
TEST = switch



##### TARGETS #####
#	@ar rvs lib$(LOCAL_NAME).a $(OBJS)
.PHONY:all
#all:$(LOCAL_LIBS) $(LOCAL_MODULES) $(LOCAL_NAME) reference
all:create_incs collect_incs create_objs collect_incs reference
	echo "$(LOCAL_NAME) is compiled\n"

create_incs:
	echo $(LOCAL_INCLUDES) > LOCAL_INCS.finsmk
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) create_incs; cd $(LOCAL_DIR);)
	$(foreach MODULE, $(strip $(LOCAL_MODULES)), cd $(MODULES_DIR)/$(MODULE); $(MAKE) create_incs; cd $(LOCAL_DIR);)
else

collect_incs:
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) create_incs collect_incs; cd $(LOCAL_DIR);)
	@$(foreach MODULE, $(strip $(LOCAL_MODULES)), cd $(MODULES_DIR)/$(MODULE); $(MAKE) create_incs collect_incs; cd $(LOCAL_DIR);)
else

endif

create_objs:

collect_incs:

.PHONY:$(LOCAL_NAME)
$(LOCAL_NAME):$(LOCAL_OBJS)
	echo "local compiled"

.PHONY:reference
reference:
	echo $(OBJS) > OBJS.finsmk
	echo $(INCLUDES) > INCLUDES.finsmk 

.PHONY:link
link:$(OBJS)
	@$(LD) $(LDFLAGS) $(OBJS) -o $(OBJ_DIR)/$(LOCAL_NAME)/$(LOCAL_NAME) 

.PHONY:clean
clean:
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) clean; cd $(LOCAL_DIR);)
	@$(foreach MODULE, $(strip $(LOCAL_MODULES)), cd $(MODULES_DIR)/$(MODULE); $(MAKE) clean; cd $(LOCAL_DIR);) 
endif
	@rm -f *.o *.a
	@rm -f OBJS.finsmk

test:
	echo "val=$(TEST)"
	echo "comp='$(strip $(wildcard $(LIBS_DIR)/$(TEST)))' vs '$(LIBS_DIR)/$(TEST)'"
ifeq ($(LIBS_DIR)/$(TEST),$(strip $(wildcard $(LIBS_DIR)/$(TEST))))
	echo "libs=$(strip $(wildcard $(LIBS_DIR)/$(TEST)))"
#cd $(LIBS_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
else
	echo "mods=$(strip $(wildcard $(LIBS_DIR)/$(TEST)))"
#cd $(MODULES_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
endif

.PHONY:%.o
%.o:%.c $(INCLUDES)
	$(CC) $(CFLAGS) -c $< -o $@	

.PHONY:%
%:
ifneq ($(MAX_DEPTH),$(MAKELEVEL))
	echo "val=$@"
	echo "comp='$(strip $(wildcard $(LIBS_DIR)/$@))' vs '$(LIBS_DIR)/$@'"
ifeq ($(LIBS_DIR)/$@,$(strip $(wildcard $(LIBS_DIR)/$@)))
	echo "libs=$(strip $(wildcard $(LIBS_DIR)/$@))"
	cd $(LIBS_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
else
	echo "mods=$(strip $(wildcard $(LIBS_DIR)/$@))"
	cd $(MODULES_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
endif
else
	echo "Reached max depth"
endif