#ifndef INTERCEPTOR_H_
#define INTERCEPTOR_H_

#include "common.h"
#include "memory.h"
#include "elfscan.h"

struct breakpoint_t{
    unsigned long address;
    unsigned char original_data;
};




/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

/* Indirect call instruction */
static const unsigned char indirect_call[3] = {0xFF, 0xD0, 0xCC};

/* Jump instruction */
static const unsigned char jump_instruction[2] = {0x48, 0xB8};

ErrorCode set_breakpoint(const pid_t traced_program_id, const unsigned long address_position);
ErrorCode call_function_val(struct program_vars_t program_vars, const unsigned long function_to_call, const char *param);
ErrorCode call_function_ref(struct program_vars_t program_vars, const unsigned long function_to_call, const char *param);
#endif
