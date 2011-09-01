################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../Jinni/handlers.c \
../Jinni/icmpHandling.c \
../Jinni/tcpHandling.c \
../Jinni/udpHandling.c 

OBJS += \
./Jinni/handlers.o \
./Jinni/icmpHandling.o \
./Jinni/tcpHandling.o \
./Jinni/udpHandling.o 

C_DEPS += \
./Jinni/handlers.d \
./Jinni/icmpHandling.d \
./Jinni/tcpHandling.d \
./Jinni/udpHandling.d 


# Each subdirectory must supply rules for building sources it contributes
Jinni/%.o: ../Jinni/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


