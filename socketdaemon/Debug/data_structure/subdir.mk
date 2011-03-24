################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../data_structure/queue.c \
../data_structure/queueModule.c 

OBJS += \
./data_structure/queue.o \
./data_structure/queueModule.o 

C_DEPS += \
./data_structure/queue.d \
./data_structure/queueModule.d 


# Each subdirectory must supply rules for building sources it contributes
data_structure/%.o: ../data_structure/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


