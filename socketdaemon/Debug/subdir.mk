################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../getMAC_Address.c \
../handlers.c \
../htoi.c \
../icmp.c \
../socketjinni.c \
../swito.c \
../tcpHandling.c \
../udpHandling.c \
../wifidemux.c 

OBJS += \
./getMAC_Address.o \
./handlers.o \
./htoi.o \
./icmp.o \
./socketjinni.o \
./swito.o \
./tcpHandling.o \
./udpHandling.o \
./wifidemux.o 

C_DEPS += \
./getMAC_Address.d \
./handlers.d \
./htoi.d \
./icmp.d \
./socketjinni.d \
./swito.d \
./tcpHandling.d \
./udpHandling.d \
./wifidemux.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


