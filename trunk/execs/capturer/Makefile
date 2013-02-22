LOCAL_DIR := $(PWD)

ifndef FINS_ROOT_DIR
FINS_ROOT_DIR := $(LOCAL_DIR)/../../..
export FINS_ROOT_DIR
endif

# fins.mk contains the compiler and linker options for each target platform
include $(FINS_ROOT_DIR)/settings.finsmk

#Name of the module
LOCAL_NAME = capturer
LOCAL_LIBS = $(CAPTURER_LIBS)

LOCAL_INC = -I. $(call lib_includes,$(LOCAL_LIBS))
ifdef BUILD_FOR_ANDROID_ARM
#This is a tweak for ease of use, fix later by compiling libconfig
LOCAL_INC += -I$(LIBS_DIR)/common
endif
INCLUDES = $(call grab_headers, $(LOCAL_INC))
CFLAGS += $(LOCAL_INC)

LOCAL_OBJS = ethermod.o htoi.o wifistub.o
FULL_OBJS = $(call add_path,$(LOCAL_DIR),$(LOCAL_OBJS))

FULL_OBJS += $(call lib_objs, $(LOCAL_LIBS))
OBJS = $(sort $(FULL_OBJS))

INSTALL_DIR = /data/local/tmp



##### TARGETS #####
.PHONY:all
all:$(LOCAL_LIBS) $(LOCAL_NAME)
	@echo "$(LOCAL_NAME) is compiled\n"

.PHONY:$(LOCAL_NAME)
$(LOCAL_NAME):$(OBJS)
	@$(LD) $(LDFLAGS) $(OBJS) -o $(OBJ_DIR)/$(LOCAL_NAME)/$@ 

.PHONY:%.o
%.o:%.c $(INCLUDES)
	@$(CC) $(CFLAGS) -c $< -o $@	

.PHONY:%
%:
	@cd $(LIBS_DIR)/$@; $(MAKE) all; cd $(LOCAL_DIR);

.PHONY:clean
clean:
	@$(foreach LIB, $(strip $(LOCAL_LIBS)), cd $(LIBS_DIR)/$(LIB); $(MAKE) clean; cd $(LOCAL_DIR);) 
	@rm -f *.o
	@rm -f $(LOCAL_NAME)

.PHONY:install
install: $(LOCAL_NAME)
	@adb push $(LOCAL_NAME) $(INSTALL_DIR)/$(LOCAL_NAME)
	@adb shell chmod 777 $(INSTALL_DIR)/$(LOCAL_NAME)

.PHONY:debug
debug:
	$(GDB_CLIENT) $(LOCAL_NAME)

.PHONY:test
test:
	@echo "TEST='$(TEST)'"

old:
	@echo "FINS_ROOT_DIR='$(FINS_ROOT_DIR)'"
	@echo "OBJS='$(OBJS)'"
	@echo "CAPTURER_INC='$(CAPTURER_INC)'"
	@echo "CFLAGS='$(CFLAGS)'"
	@echo "INCLUDES='$(INCLUDES)'"
	@echo "CC='$(CC)'"
	@echo "LD='$(LD)'"
	@echo "LDFLAGS='$(LDFLAGS)'"
	@echo "CC='$(CC)'"
	@echo "CFLAGS='$(CFLAGS)'"
	