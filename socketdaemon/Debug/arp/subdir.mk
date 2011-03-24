################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../arp/arp.c \
../arp/arp_in_out.c \
../arp/init_term_arp.c 

OBJS += \
./arp/arp.o \
./arp/arp_in_out.o \
./arp/init_term_arp.o 

C_DEPS += \
./arp/arp.d \
./arp/arp_in_out.d \
./arp/init_term_arp.d 


# Each subdirectory must supply rules for building sources it contributes
arp/%.o: ../arp/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


