################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/attack.c \
../src/main.c \
../src/server.c \
../src/tag.c \
../src/utils.c 

OBJS += \
./src/attack.o \
./src/main.o \
./src/server.o \
./src/tag.o \
./src/utils.o 

C_DEPS += \
./src/attack.d \
./src/main.d \
./src/server.d \
./src/tag.d \
./src/utils.d 


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	gcc -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


