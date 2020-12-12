#ifndef INTERCEPTOR_COMMON_H
#define INTERCEPTOR_COMMON_H

// ptrace
#include <sys/ptrace.h>
// size_t, pid_t, pthread types
#include <sys/types.h>
// user struct regs
#include <sys/user.h>

// read, write, files, stdout and other standard stuff
#include <unistd.h>
// malloc, free, strttoull
#include <stdlib.h>
// fread, fwrite, scanf, sscanf
#include <stdio.h>
// strcpy, strcmp
#include <string.h>

// int types and sizes
#include <stdint.h>
// boolean from int
#include <stdbool.h>
// ctype for isdigit
#include <ctype.h>

#include "errorcodes.h"

#define FUNCTION_SIZE 8
#define POS_SIZE 64
#define LINE_SIZE 128
#define COMMAND_SIZE 256
#define BUFFER_SIZE 16

/* General use functions, in order to dump registers we must be attache to a program */
void print_usage(void);

/* Check if input char is a valid number */
bool isnumber(char * input);

ErrorCode is_func_running(const pid_t traced_program_id, const unsigned long long traced_func_address, const unsigned long size);

ErrorCode dump_memory(pid_t traced_program_id, unsigned long start_address, unsigned long nb_bytes);
ErrorCode dump_registers(const pid_t traced_program_id);

ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, const size_t data_length, unsigned char * output_buffer);
ErrorCode write_data(const pid_t traced_program_id,const unsigned long address_position, const size_t data_length, const unsigned char *input_buffer);

void ul_to_bytarray(unsigned long address, unsigned char *output);
void ull_to_bytearray(unsigned long long address, unsigned char *output);
ErrorCode data_to_ull(pid_t traced_program_id, const unsigned long long address, unsigned long long * value);

ErrorCode is_region_available(const pid_t traced_program_id, const unsigned long long region_address);
ErrorCode is_region_executable(const pid_t traced_program_id, const unsigned long long region_address);
#endif //COMMON_H
