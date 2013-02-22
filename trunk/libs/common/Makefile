LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#This is the Module name. This MUST be that same as the current directory!!!
LOCAL_NAME = common
LOCAL_LIBS = $(COMMON_LIBS)

#This is the list of objects needed to build the FINS core. NOTE: object files
#that contain a "main" function must NOT be included in this list!!!
LOCAL_OBJS = getMAC_Address.o metadata.o finstypes.o finstime.o finsthreads.o
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
	@cd $(LIBS_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) clean; cd $(LOCAL_DIR);)
	@rm -f *.o *.a
	@rm -f OBJS.finsmk