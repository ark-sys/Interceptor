#ifndef INTERCEPTOR_ELFSCAN_H
#define INTERCEPTOR_ELFSCAN_H

#include "common.h"
// used for info fetching on elf header
#include <libelf.h>
// used for open
#include <fcntl.h>

struct program_vars_t{
    pid_t traced_program_id;
    char traced_program_name[LINE_SIZE];
    int traced_program_type;

    unsigned long traced_function_size;
    unsigned long long traced_function_address; /* main_address + function_offset, if DYN type detected*/
    unsigned long long traced_function_offset;
    unsigned long long program_start_address;

    unsigned char instruction_backup[BUFFER_SIZE];
    struct user_regs_struct registers;
};

ErrorCode check_elf_type(const char * program_name, int *result);
ErrorCode is_DT_available(const char * program_name, int *result);

ErrorCode get_pid(const char * argument_1, struct program_vars_t * program_vars);

ErrorCode get_program_startaddress(pid_t traced_program_id, const char * traced_program_name, unsigned long long * program_start_address);
ErrorCode get_libc_function_address(const struct program_vars_t program_vars,
                                    unsigned long long *function_address, const char *libc_function_name);

ErrorCode get_function_offset(const char * traced_program_name, const char * function_name, unsigned long long * function_offset);
ErrorCode get_function_size(const char * traced_program_name, unsigned long long function_address, unsigned long * size_output);

#endif //INTERCEPTOR_ELFSCAN_H
