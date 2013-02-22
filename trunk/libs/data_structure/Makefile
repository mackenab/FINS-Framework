LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME = data_structure
LOCAL_LIBS = common

LOCAL_OBJS = queue.o finsqueue.o
FULL_OBJS = $(call add_path,$(LOCAL_DIR),$(LOCAL_OBJS))

FULL_OBJS += $(call lib_objs, $(LOCAL_LIBS))
OBJS = $(sort $(FULL_OBJS))

LOCAL_INC = -I. $(call lib_includes,$(LOCAL_LIBS))
INCLUDES = $(call grab_headers, $(LOCAL_INC))
CFLAGS += $(LOCAL_INC)



##### TARGETS #####
#	@ar rvs lib$(LOCAL_NAME).a $(OBJS)
.PHONY:all
all:$(LOCAL_LIBS) $(LOCAL_NAME) 
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
endif

.PHONY:clean
clean:
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) clean; cd $(LOCAL_DIR);)
	@rm -f *.o *.a
	@rm -f OBJS.finsmk	@echo "CFLAGS='$(CFLAGS)'"