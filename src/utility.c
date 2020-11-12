#include "common.h"

/*
 * In this file you can find helper functions that are used in the main program
 * such as functions that will help us by printing some info on screen
 * or functions that will help us make backups of the current register state
 *
 *
 * */


void print_usage(void){
    fprintf(stderr, "%s\n", "Usage : ./interceptor [program_name] [function_name] [function_to_call] [param_for_function_to_call]");
}


/*
 * This function will print current state of memory starting from the argument 'start_address' and will be showing 'nb_bytes'
 *
 * */
void dump_memory(pid_t traced_program_id, unsigned long start_address, unsigned long nb_bytes){
    unsigned data;
    fprintf(stdout, "===== MEMORY DUMP =====\n");
    for(int i = 0; i < nb_bytes; i = i+4){
        data = ptrace(PTRACE_PEEKTEXT, traced_program_id, (void *)(start_address+i), 0);
        fprintf(stdout, "0x%08lX : 0x%08X\n", (start_address+i), htonl(data));
    }
    fprintf(stdout,   "=======================\n\n");

}

ErrorCode dump_registers(pid_t traced_program_id){
    ErrorCode errorCode = NO_ERROR;
    struct user_regs_struct current_registers;

    if(ptrace(PTRACE_GETREGS, traced_program_id, NULL, &current_registers) < 0)
    {
        fprintf(stderr, "%s\n", "Failed to get current registers.");
        errorCode = ERROR;
    } else {
        fprintf(stdout, "==== REGISTERS  DUMP ====\n");
        fprintf(stdout, "RBP at 0x%016llX\nRIP at 0x%016llX\nRAX at 0x%016llX\nRDI at 0x%016llX\nRSP at 0x%016llX\n", current_registers.rbp, current_registers.rip, current_registers.rax, current_registers.rdi, current_registers.rsp);
        fprintf(stdout,   "=========================\n\n");
    }

    return errorCode;
}

ErrorCode get_registers_backup(const pid_t traced_program_id, struct user_regs_struct * registers){
    ErrorCode errorCode = NO_ERROR;
    if(ptrace(PTRACE_GETREGS, traced_program_id, NULL, registers) < 0){
        fprintf(stderr,"%s\n", "Failed to save current registers state.");
        errorCode = ERROR;
    }
    return errorCode;
}

ErrorCode set_registers_backup(const pid_t traced_program_id, struct user_regs_struct * registers){
    ErrorCode errorCode = NO_ERROR;
    if(ptrace(PTRACE_SETREGS, traced_program_id, NULL, registers) < 0){
        fprintf(stderr,"%s\n", "Failed to set backup registers state.");
        errorCode = ERROR;
    }
    return errorCode;
}

