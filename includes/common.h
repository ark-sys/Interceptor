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

#include <unistd.h>
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


/* #todo when everything is good, check if all macros are used */
#define PID_SIZE 16
#define FUNCTION_SIZE 64
#define POS_SIZE 64
#define LINE_SIZE 128
#define COMMAND_SIZE 256
#define BUFFER_SIZE 4


void print_usage(void);
void dump_memory(const pid_t traced_program_id, const unsigned long start_address, const unsigned long nb_bytes);
ErrorCode dump_registers(const pid_t traced_program_id);
ErrorCode get_registers_backup(const pid_t traced_program_id, struct user_regs_struct * registers);
ErrorCode set_registers_backup(const pid_t traced_program_id, struct user_regs_struct * registers);
ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, char * output_buffer);
ErrorCode write_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, const char * input_buffer);
ErrorCode write_values(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, const char *  input_buffer);
ErrorCode is_region_available(const pid_t traced_program_id, const unsigned long long region_address );

#endif //COMMON_H
