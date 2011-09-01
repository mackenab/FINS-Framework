################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include subdir.mk
-include udp/subdir.mk
-include tcp/subdir.mk
-include switch/subdir.mk
-include ipv4/subdir.mk
-include fins_headers/subdir.mk
-include data_structure/subdir.mk
-include arp/subdir.mk
-include RTM/subdir.mk
-include Jinni/subdir.mk
-include ICMP/subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: socketdaemon

# Tool invocations
socketdaemon: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc  -o"socketdaemon" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C_DEPS)$(EXECUTABLES) socketdaemon
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
