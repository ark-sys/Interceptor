#ifndef INTERCEPTOR_H_
#define INTERCEPTOR_H_

#include "common.h"
#include "elfscan.h"

// argument parse, and type verification
#include <getopt.h>
// PROT flags for mprotect
#include <sys/mman.h>
// wait, waitpid, status signals
#include <sys/wait.h>
/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

/* Indirect call instruction */
static const unsigned char indirect_call[3] = {0xFF, 0xD0, 0xCC};

/* Jump instruction */
static const unsigned char jump_instruction[2] = {0x48, 0xB8};

/* Endi instruction */
static const unsigned char end_instruction[2] = {0xFF, 0xE0};


ErrorCode setBreakpoint(const pid_t tracedProgramId, const unsigned long addressPosition);
ErrorCode bpLight(const pid_t tracedProgramId, const unsigned long addressPosition);
ErrorCode bp_first_regs(const pid_t tracedProgramId, const unsigned long addressPosition);

ErrorCode call_function_val(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param);
ErrorCode call_function_ref(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param);
ErrorCode
call_posix_memalign(struct program_vars_t program_vars, const unsigned long long memalign_address, const size_t size,
                    const size_t alignment, unsigned long long *address_to_region);
ErrorCode call_mprotect(struct program_vars_t program_vars, const unsigned long long mprotect_address, const unsigned long long mem_region, const size_t size, const char prot);
ErrorCode clean_memory(const struct program_vars_t program_vars, const unsigned long long mp_address, unsigned long long address_to_region, size_t size);
ErrorCode trampoline(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param);
int func4 (int i);

#endif
