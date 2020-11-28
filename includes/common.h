#ifndef INTERCEPTOR_COMMON_H
#define INTERCEPTOR_COMMON_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <libelf.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "errorcodes.h"

#define FUNCTION_SIZE 8
#define POS_SIZE 64
#define LINE_SIZE 128
#define COMMAND_SIZE 256
#define BUFFER_SIZE 16

/* General use functions, in order to dump registers we must be attache to a program */
void print_usage(void);
void dump_memory(const pid_t traced_program_id, const unsigned long start_address, const unsigned long nb_bytes);
ErrorCode dump_registers(const pid_t traced_program_id);

ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, const size_t data_length, unsigned char * output_buffer);
ErrorCode write_data(const pid_t traced_program_id,const unsigned long address_position, const size_t data_length, const unsigned char *input_buffer);

void ul_to_bytarray(unsigned long address, unsigned char *output);
void ull_to_bytearray(unsigned long long address, unsigned char *output);
ErrorCode data_to_ull(pid_t traced_program_id, const unsigned long long address, unsigned long long * value);

ErrorCode is_region_available(const pid_t traced_program_id, const unsigned long long region_address );
ErrorCode is_region_executable(const pid_t traced_program_id, const unsigned long long region_address);
#endif //COMMON_H
