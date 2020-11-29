#include "interceptor.h"

ErrorCode trampoline(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param){
    ErrorCode errorCode = NO_ERROR;
    unsigned long long current_param = strtoull(param, NULL, 10);

    fprintf(stdout, "%s\n", "========================================= START OF TRAMPOLINE =========================================");
    fprintf(stdout, "Function argument : %s\n", param);
    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = setBreakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            if( ptrace(PTRACE_GETREGS, program_vars.traced_program_id,0,&program_vars.registers) < 0) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {

                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, 8);
                dump_registers(program_vars.traced_program_id);

                struct user_regs_struct regs;
                fprintf(stdout, "Preparing call to function at address 0x%08llX\n", function_to_call);
                /* Get current register state for the traced program */
                if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                    errorCode = ERROR;
                } else {

                    /* Set current register with the new function and parameter to call
                    * rax -> address of the function to be called
                    * rip -> address of the current function
                    * rdi -> parameter for the function, points to rsp so we can retrieve the written value
                    * */
                    regs.rip = program_vars.traced_function_address;
                    regs.rdi = current_param;

                    /* Set new registers */
                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                        fprintf(stderr, "%s\n", "Failed to set new registers");
                        errorCode = ERROR;
                    } else {
                        /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                        errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address,
                                               sizeof(jump_instruction),
                                               (const unsigned char *) jump_instruction);
                        if (errorCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "Failed to write data in memory.");

                        } else {
                            unsigned char convert_array[FUNCTION_SIZE];

                            ull_to_bytearray(function_to_call, convert_array);
                            errorCode = write_data(program_vars.traced_program_id, (program_vars.traced_function_address + sizeof(jump_instruction)), FUNCTION_SIZE,
                                       (const unsigned char *) convert_array);
                            if(errorCode != NO_ERROR){
                                fprintf(stderr,"%s\n","Failed to write function address after jump instruction.");
                            } else {
                                errorCode = write_data(program_vars.traced_program_id, (program_vars.traced_function_address + sizeof(jump_instruction) + FUNCTION_SIZE), sizeof(end_instruction),
                                                       (const unsigned char *) end_instruction);
                                if(errorCode != NO_ERROR){
                                    fprintf(stderr,"%s\n","Failed to write end instruction after jump instruction.");
                                }
                                fprintf(stdout, "Jumping to 0x%08llX\n", function_to_call);
                                dump_memory(program_vars.traced_program_id, program_vars.traced_function_address, 24);
                            }

                       }
                    }
                }
            }
        }
    }
    return errorCode;
}

