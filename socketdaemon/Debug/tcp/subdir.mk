################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../tcp/tcp.c \
../tcp/tcp_in.c \
../tcp/tcp_out.c 

OBJS += \
./tcp/tcp.o \
./tcp/tcp_in.o \
./tcp/tcp_out.o 

C_DEPS += \
./tcp/tcp.d \
./tcp/tcp_in.d \
./tcp/tcp_out.d 


# Each subdirectory must supply rules for building sources it contributes
tcp/%.o: ../tcp/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


