################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
O_SRCS += \
../socket_interceptor.o 

C_SRCS += \
../client_recvmsg.c \
../socket_interceptor.c 

OBJS += \
./client_recvmsg.o \
./socket_interceptor.o 

C_DEPS += \
./client_recvmsg.d \
./socket_interceptor.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


