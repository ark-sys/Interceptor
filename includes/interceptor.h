#ifndef INTERCEPTOR_H_
#define INTERCEPTOR_H_

#include "common.h"
#include "elfscan.h"
#include "errorcodes.h"

struct breakpoint_t{
    unsigned long address;
    unsigned char original_data;
};

struct program_vars_t{
    pid_t traced_program_id;
    char traced_program_name[POS_SIZE];
    int * traced_program_type;

    int traced_function_size;
    unsigned long traced_function_address; /* main_address + function_offset, if DYN type detected*/
    unsigned long traced_function_offset;
    unsigned long program_main_address;

    char instruction_backup[BUFFER_SIZE];
    struct user_regs_struct registers;
};




#endif
