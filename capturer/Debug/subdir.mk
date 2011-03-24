################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../ethermod.c \
../getMAC_Address.c \
../htoi.c \
../wifistub.c 

OBJS += \
./ethermod.o \
./getMAC_Address.o \
./htoi.o \
./wifistub.o 

C_DEPS += \
./ethermod.d \
./getMAC_Address.d \
./htoi.d \
./wifistub.d 


# Each subdirectory must supply rules for building sources it contributes
%.o: ../%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o"$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


