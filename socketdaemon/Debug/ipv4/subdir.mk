################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../ipv4/IP4_checksum.c \
../ipv4/IP4_const_header.c \
../ipv4/IP4_dest_check.c \
../ipv4/IP4_exit.c \
../ipv4/IP4_forward.c \
../ipv4/IP4_fragment_data.c \
../ipv4/IP4_in.c \
../ipv4/IP4_init.c \
../ipv4/IP4_next_hop.c \
../ipv4/IP4_out.c \
../ipv4/IP4_reass.c \
../ipv4/IP4_receive_fdf.c \
../ipv4/IP4_route_info.c \
../ipv4/IP4_send_fdf.c \
../ipv4/ipv4.c 

OBJS += \
./ipv4/IP4_checksum.o \
./ipv4/IP4_const_header.o \
./ipv4/IP4_dest_check.o \
./ipv4/IP4_exit.o \
./ipv4/IP4_forward.o \
./ipv4/IP4_fragment_data.o \
./ipv4/IP4_in.o \
./ipv4/IP4_init.o \
./ipv4/IP4_next_hop.o \
./ipv4/IP4_out.o \
./ipv4/IP4_reass.o \
./ipv4/IP4_receive_fdf.o \
./ipv4/IP4_route_info.o \
./ipv4/IP4_send_fdf.o \
./ipv4/ipv4.o 

C_DEPS += \
./ipv4/IP4_checksum.d \
./ipv4/IP4_const_header.d \
./ipv4/IP4_dest_check.d \
./ipv4/IP4_exit.d \
./ipv4/IP4_forward.d \
./ipv4/IP4_fragment_data.d \
./ipv4/IP4_in.d \
./ipv4/IP4_init.d \
./ipv4/IP4_next_hop.d \
./ipv4/IP4_out.d \
./ipv4/IP4_reass.d \
./ipv4/IP4_receive_fdf.d \
./ipv4/IP4_route_info.d \
./ipv4/IP4_send_fdf.d \
./ipv4/ipv4.d 


# Each subdirectory must supply rules for building sources it contributes
ipv4/%.o: ../ipv4/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I.././udp -I.././tcp -I.././ipv4 -I.././arp -I.././data_structure -I../fins_headers -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


