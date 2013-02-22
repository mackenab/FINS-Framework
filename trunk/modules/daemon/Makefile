LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME = daemon
LOCAL_LIBS = common
LOCAL_MODULES = switch

LOCAL_OBJS = daemon.o udpHandling.o tcpHandling.o icmpHandling.o
FULL_OBJS = $(call add_path,$(LOCAL_DIR),$(LOCAL_OBJS))

FULL_OBJS += $(call lib_objs, $(LOCAL_LIBS))
FULL_OBJS += $(call module_objs, $(LOCAL_MODULES))
OBJS = $(sort $(FULL_OBJS))

LOCAL_INC = -I. 
LOCAL_INC += $(call lib_includes,$(LOCAL_LIBS))
LOCAL_INC += $(call module_includes,$(LOCAL_MODULES))
INCLUDES = $(call grab_headers, $(LOCAL_INC))
CFLAGS += $(LOCAL_INC)



##### TARGETS #####
#	@ar rvs lib$(LOCAL_NAME).a $(OBJS)
.PHONY:all
all:$(LOCAL_LIBS) $(LOCAL_MODULES) $(LOCAL_NAME)
	@echo "$(LOCAL_NAME) is compiled\n"

.PHONY:$(LOCAL_NAME)
$(LOCAL_NAME):$(OBJS)
	@echo $(OBJS) > OBJS.finsmk 

.PHONY:%.o
%.o:%.c $(INCLUDES)
	@$(CC) $(CFLAGS) -c $< -o $@	

.PHONY:%
%:
ifneq ($(wildcard $(LIBS_DIR)/$@),)
	@cd $(LIBS_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
else
	@cd $(MODULES_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);
endif

.PHONY:clean
clean:
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) clean; cd $(LOCAL_DIR);)
	@$(foreach MODULE, $(strip $(LOCAL_MODULES)), cd $(MODULES_DIR)/$(MODULE); $(MAKE) clean; cd $(LOCAL_DIR);) 
	@rm -f *.o *.a
	@rm -f OBJS.finsmk