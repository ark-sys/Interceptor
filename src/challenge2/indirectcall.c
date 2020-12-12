#include "interceptor.h"

ErrorCode
call_function_val(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    unsigned long long current_param = strtoull(param, NULL, 10);

    fprintf(stdout, "%s\n",
            "========================================= START OF INDIRECT CALL VAL =========================================");
    fprintf(stdout, "Function argument : %s\n", param);
    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE,
                          program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = setBreakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, 0, &program_vars.registers) < 0) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id, program_vars.traced_function_address, 8);
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
                    * rsp -> address of the top of the stack pointer, where the value will be written
                    * rdi -> parameter for the function, points to rsp so we can retrieve the written value
                    * */
                    regs.rax = function_to_call;
                    regs.rip = program_vars.traced_function_address;
                    regs.rdi = current_param;

                    /* Set new registers */
                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                        fprintf(stderr, "%s\n", "Failed to set new registers");
                        errorCode = ERROR;
                    } else {
                        /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                        errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address,
                                               sizeof(indirect_call),
                                               (const unsigned char *) indirect_call);
                        if (errorCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "Failed to write data in memory.");

                        } else {
                            fprintf(stdout, "Jumping to 0x%08llX\n", function_to_call);

                            /* Resume program execution */
                            if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                errorCode = ERROR;
                            } else {
                                fprintf(stdout, "%s\n", "Executing...");
                                /* Check if the program has actually continued*/
                                if (program_vars.traced_program_id !=
                                    waitpid(program_vars.traced_program_id, &wait_status, WCONTINUED)) {
                                    fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
                                    errorCode = ERROR;
                                } else {

                                    fprintf(stdout, "PID <%d> got signal: %s\n", program_vars.traced_program_id,
                                            strsignal(WSTOPSIG(wait_status)));
                                    /* Get the state of the registers after the execution */
                                    if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                                        errorCode = ERROR;
                                        fprintf(stderr, "Failed to get registers.\n");
                                    } else {

                                        /* Recover the returned value from the execution of the called function */
                                        unsigned long long return_value = regs.rax;
                                        fprintf(stdout, "\nReturned value is %llu\n", return_value);

                                        /* Pass the returned value from the called function to the traced function */
                                        dump_registers(program_vars.traced_program_id);

                                        fprintf(stdout, "\n%s\n",
                                                "Restoring traced program memory and registers from backup");
                                        /* Write the data to its previous location*/
                                        errorCode = write_data(program_vars.traced_program_id,
                                                               program_vars.traced_function_address,
                                                               BUFFER_SIZE,
                                                               (const unsigned char*)program_vars.instruction_backup);
                                        if (errorCode != NO_ERROR) {
                                            fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                        } else {
                                            fprintf(stdout, "%s\n", "Registers before backup");
                                            dump_registers(program_vars.traced_program_id);
                                            /*
                                             * Set rip to the beginning of the function
                                             * And pass to rdi the return value from the called function
                                             * */
                                            program_vars.registers.rip = program_vars.traced_function_address;
                                            program_vars.registers.rdi = return_value;

                                            /* restore registers state */
                                            if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, 0,
                                                       &program_vars.registers) < 0) {
                                                fprintf(stderr, "%s\n",
                                                        "Failed to recover registers backup.");
                                            }
                                            fprintf(stdout, "%s\n", "Registers after backup");
                                            dump_registers(program_vars.traced_program_id);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return errorCode;
}


ErrorCode
call_function_ref(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    fprintf(stdout, "%s\n",       "========================================= START OF INDIRECT CALL REF =========================================");
    fprintf(stdout, "Function argument : %s\n", param);

    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE,
                          program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = setBreakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, 0, &program_vars.registers) < 0) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id, program_vars.traced_function_address, 8);
                dump_registers(program_vars.traced_program_id);

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08llX\n", function_to_call);
                /* Get current register state for the traced program */
                if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                    errorCode = ERROR;
                } else {

                    /* Set current register with the new function and parameter to call
                    * rax -> address of the function to be called
                    * rip -> address of the current function
                    * rsp -> address of the top of the stack pointer, where the value will be written
                    * rdi -> parameter for the function, points to rsp so we can retrieve the written value
                    * */
                    regs.rax = function_to_call;
                    regs.rip = program_vars.traced_function_address;
                    regs.rsp = regs.rsp - sizeof(unsigned long);
                    regs.rdi = regs.rsp;

                    fprintf(stdout, "RSP before write at 0x%016llX\n", regs.rsp);
                    dump_memory(program_vars.traced_program_id, regs.rsp, 8);

                    unsigned long convert_param = strtoul(param, NULL, 10);
                    unsigned char convert_array[4];

                    ul_to_bytarray(convert_param, convert_array);
                    /* Write argument param to memory space addressed by regs.rsp */
                    errorCode = write_data(program_vars.traced_program_id, regs.rsp, sizeof(convert_array),
                                           (const unsigned char *) convert_array);
                    if (errorCode != NO_ERROR) {
                        fprintf(stderr, "Failed to write value to memory.");

                    } else {

                        /* Set new registers */
                        if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                            fprintf(stderr, "%s\n", "Failed to set new registers");
                            errorCode = ERROR;
                        } else {
                            /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address,
                                                   sizeof(indirect_call),
                                                   (const unsigned char *)  indirect_call);
                            if (errorCode != NO_ERROR) {
                                fprintf(stderr, "%s\n", "Failed to write data in memory.");

                            } else {
                                fprintf(stdout, "Jumping to 0x%08llX\n", function_to_call);

                                /* Resume program execution */
                                if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                    fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                    errorCode = ERROR;
                                } else {

                                    fprintf(stdout, "%s\n", "Executing...");
                                    /* Check if the program has actually continued*/
                                    if (program_vars.traced_program_id !=
                                        waitpid(program_vars.traced_program_id, &wait_status, WCONTINUED)) {
                                        fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
                                        errorCode = ERROR;
                                    } else {

                                        fprintf(stdout, "PID <%d> got signal: %s\n", program_vars.traced_program_id,
                                                strsignal(WSTOPSIG(wait_status)));
                                        if (WSTOPSIG(wait_status) != SIGTRAP) {
                                            fprintf(stderr, "%s\n", "Error detected");
                                            errorCode = ERROR;
                                        } else {

                                            /* Get the state of the registers after the execution */
                                            if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) <
                                                0) {
                                                errorCode = ERROR;
                                                fprintf(stderr, "Failed to get registers.\n");
                                            } else {

                                                /* Recover the returned value from the execution of the called function */
                                                unsigned long long return_value = regs.rax;
                                                fprintf(stdout, "\nReturned value is %llu\n", return_value);

                                                dump_registers(program_vars.traced_program_id);

                                                fprintf(stdout, "\n%s\n",
                                                        "Restoring traced program memory and registers from backup");


                                                /* Write the data to its previous location*/
                                                errorCode = write_data(program_vars.traced_program_id,
                                                                       program_vars.traced_function_address,
                                                                       BUFFER_SIZE,
                                                                       (const unsigned char *) program_vars.instruction_backup);
                                                if (errorCode != NO_ERROR) {
                                                    fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                                } else {
                                                    fprintf(stdout, "%s\n", "Registers before backup");
                                                    dump_registers(program_vars.traced_program_id);
                                                    program_vars.registers.rdi = return_value;
                                                    program_vars.registers.rip = program_vars.traced_function_address;
                                                    /* restore registers state */
                                                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, 0,
                                                               &program_vars.registers) < 0) {
                                                        fprintf(stderr, "%s\n",
                                                                "Failed to recover registers backup.");
                                                    }
                                                    fprintf(stdout, "%s\n", "Registers after backup");
                                                    dump_registers(program_vars.traced_program_id);
                                                }

                                            }

                                        }

                                    }
                                }
                            }
                        }

                    }

                }
            }
        }
    }
    return errorCode;
}

