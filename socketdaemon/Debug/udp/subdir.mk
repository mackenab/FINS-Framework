################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../udp/InputQueue_Read_local.c \
../udp/UDP_checksum.c \
../udp/create_ff.c \
../udp/udp.c \
../udp/udp_get_FF.c \
../udp/udp_in.c \
../udp/udp_out.c 

OBJS += \
./udp/InputQueue_Read_local.o \
./udp/UDP_checksum.o \
./udp/create_ff.o \
./udp/udp.o \
./udp/udp_get_FF.o \
./udp/udp_in.o \
./udp/udp_out.o 

C_DEPS += \
./udp/InputQueue_Read_local.d \
./udp/UDP_checksum.d \
./udp/create_ff.d \
./udp/udp.d \
./udp/udp_get_FF.d \
./udp/udp_in.d \
./udp/udp_out.d 


# Each subdirectory must supply rules for building sources it contributes
udp/%.o: ../udp/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


