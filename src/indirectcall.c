#include "interceptor.h"

ErrorCode call_function_ref(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    fprintf(stdout, "%s\n", "========================================= START OF INDIRECT CALL REF =========================================");

    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup(program_vars.traced_program_id, &program_vars.registers);
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, 8);
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
                    regs.rsp = regs.rsp - sizeof(int);
                    regs.rdi = regs.rsp;

                    fprintf(stdout,"RSP before write at 0x%016llX\n", regs.rsp);
                    dump_memory(program_vars.traced_program_id,regs.rsp, 8);

                    /* Write argument param to memory space addressed by regs.rsp */
                    errorCode = write_values(program_vars.traced_program_id, regs.rsp, strlen(param), param);
                    if(errorCode != NO_ERROR)
                    {
                        fprintf(stderr, "Failed to write value to memory.");

                    } else {

                        /* Set new registers */
                        if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                            fprintf(stderr, "%s\n", "Failed to set new registers");
                            errorCode = ERROR;
                        } else {
                            /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, sizeof(indirect_call), (char *)indirect_call);
                            if(errorCode != NO_ERROR)
                            {
                                fprintf(stderr, "%s\n","Failed to write data in memory.");

                            } else {
                                fprintf(stdout, "Jumping to 0x%08llX\n", function_to_call);

                                /* Resume program execution */
                                if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                    fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                    errorCode = ERROR;
                                } else {

                                    /* Check if the program has actually continued*/
                                    if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status, WCONTINUED)) {
                                        fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
                                        errorCode = ERROR;
                                    } else {


                                        fprintf(stdout, "PID <%d> got signal: %s\n", program_vars.traced_program_id, strsignal(WSTOPSIG(wait_status)));
                                        /* Get the state of the registers after the execution */
                                        if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL,&regs) < 0) {
                                            errorCode = ERROR;
                                            fprintf(stderr, "Failed to get registers.\n");
                                        } else {

                                            /* Recover the returned value from the execution of the called function */
                                            unsigned long long return_value = regs.rax;
                                            fprintf(stdout, "\nReturned value is %llu\n", return_value);

                                            dump_registers(program_vars.traced_program_id);

                                            /* Write the data to its previous location*/
                                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address,
                                                                   BUFFER_SIZE, program_vars.instruction_backup);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "%s\n","Failed to recover data backup.");
                                            } else {
                                                fprintf(stdout, "%s\n","Registers before backup");
                                                dump_registers(program_vars.traced_program_id);
                                                program_vars.registers.rdi = return_value;
                                                program_vars.registers.rip = program_vars.traced_function_address;
                                                /* restore registers state */
                                                errorCode = set_registers_backup(program_vars.traced_program_id, &program_vars.registers);
                                                if (errorCode != NO_ERROR) {
                                                    fprintf(stderr,"%s\n",
                                                            "Failed to recover registers backup.");
                                                }
                                                fprintf(stdout, "%s\n","Registers after backup");
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
    return errorCode;
}

ErrorCode call_function_val(struct program_vars_t program_vars, const unsigned long long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    fprintf(stdout, "%s\n", "========================================= START OF INDIRECT CALL VAL =========================================");

    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup(program_vars.traced_program_id, &program_vars.registers);
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, 8);
                dump_registers(program_vars.traced_program_id);

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08llX\n", function_to_call);
                /* Get current register state for the traced program */
                if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                    errorCode = ERROR;
                } else {

                    unsigned long long current_param = strtoull(param, NULL, 10);
                    if(current_param == 0){
                        fprintf(stderr,"%s\n", "Failed to convert parameter.");
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
                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, sizeof(indirect_call),
                                                   (char *) indirect_call);
                            if (errorCode != NO_ERROR) {
                                fprintf(stderr, "%s\n", "Failed to write data in memory.");

                            } else {
                                fprintf(stdout, "Jumping to 0x%08llX\n", function_to_call);

                                /* Resume program execution */
                                if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                    fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                    errorCode = ERROR;
                                } else {

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

                                            /* Write the data to its previous location*/
                                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE,
                                                                   program_vars.instruction_backup);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                            } else {
                                                fprintf(stdout, "%s\n", "Registers before backup");
                                                dump_registers(program_vars.traced_program_id);
                                                program_vars.registers.rip = program_vars.traced_function_address;
                                                program_vars.registers.rdi = return_value;

                                                /* restore registers state */
                                                errorCode = set_registers_backup(program_vars.traced_program_id, &program_vars.registers);
                                                if (errorCode != NO_ERROR) {
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
    return errorCode;
}

ErrorCode
call_posix_memalign(struct program_vars_t program_vars, const unsigned long long memalign_address, const size_t size,
                    unsigned long long *address_to_region) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    fprintf(stdout, "%s\n", "========================================= START OF INDIRECT CALL MEMALIGN =========================================");


    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup(program_vars.traced_program_id, &program_vars.registers);
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {
                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, 8);
                dump_registers(program_vars.traced_program_id);

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08llX\n", memalign_address);
                /* Get current register state for the traced program */
                if (ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                    errorCode = ERROR;
                } else {

                    /* Set current register with the new function and parameter to call
                    * rax -> address of the function to be called in the traced program, in this case posix_memalign
                    * rip -> address of the beginning of the current function
                    * rsp -> address of the top of the stack pointer, where the value of the new address will be written
                    * rdi -> first parameter of the function, points to rsp so we can retrieve the written pointer
                    * rsi -> second parameter of the function, specifies allignement for posix_memalign
                    * rdx -> third parameter of the function, specifies the size in blocks of the new region
                    * */
                    regs.rax = memalign_address;
                    regs.rip = program_vars.traced_function_address;
                    regs.rdi = regs.rsp - 32;
                    regs.rsi = (unsigned long long) (512);
                    regs.rdx = (unsigned long long) (size);

                    /* Set new registers */
                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                        fprintf(stderr, "%s\n", "Failed to set new registers");
                        errorCode = ERROR;
                    } else {
                        /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                        errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, sizeof(indirect_call), (char *) indirect_call);
                        if (errorCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "Failed to write data in memory.");

                        } else {
                            fprintf(stdout, "Jumping to 0x%08llX\n", memalign_address);

                            /* Resume program execution */
                            if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                errorCode = ERROR;
                            } else {

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

                                        /* Recover the returned value from the execution of the called function
                                         * Here we have the address to the newly created region
                                         * */
                                        *address_to_region = regs.rdi;
                                        fprintf(stdout, "\nNew region created at 0x%016llX\n", *address_to_region);

                                        unsigned long long return_value = regs.rax;
                                        fprintf(stdout, "\nReturned value for posix_memalign is %llu\n", return_value);

                                        dump_registers(program_vars.traced_program_id);

                                        /* Check if the new address is located inside heap boundaries */
                                        errorCode = is_region_available(program_vars.traced_program_id, *address_to_region);
                                        if(errorCode != NO_ERROR){
                                            fprintf(stderr, "%s\n", "posix_memalign failure.");
                                        } else {
                                            /* Write the data to its previous location*/
                                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE,
                                                                   program_vars.instruction_backup);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                            } else {
                                                fprintf(stdout, "%s\n", "Registers before backup");
                                                dump_registers(program_vars.traced_program_id);
                                                program_vars.registers.rip = program_vars.traced_function_address;
                                                /* restore registers state */
                                                errorCode = set_registers_backup(program_vars.traced_program_id, &program_vars.registers);
                                                if (errorCode != NO_ERROR) {
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
    return errorCode;
}

ErrorCode call_mprotect(struct program_vars_t program_vars, const unsigned long long mprotect_address, const unsigned long long mem_region, const size_t size, const char __prot) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;
    fprintf(stdout, "%s\n", "========================================= START OF INDIRECT CALL MPROTECT =========================================");
    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_program_id, program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {
            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup(program_vars.traced_program_id, &program_vars.registers);
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {
                /* Look at the current data at rip */
                dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, 8);
                dump_registers(program_vars.traced_program_id);

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08llX\n", mprotect_address);
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
                    regs.rax = mprotect_address;
                    regs.rip = program_vars.traced_function_address;
                    regs.rdi = mem_region;
                    regs.rsi = (unsigned long long) (size);
                    regs.rdx = (unsigned long long) (__prot);

                    /* Set new registers */
                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                        fprintf(stderr, "%s\n", "Failed to set new registers");
                        errorCode = ERROR;
                    } else {
                        /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                        errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, sizeof(indirect_call),
                                               (char *) indirect_call);
                        if (errorCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "Failed to write data in memory.");

                        } else {
                            fprintf(stdout, "Jumping to 0x%08llX\n", mprotect_address);

                            /* Resume program execution */
                            if (ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0) {
                                fprintf(stderr, "%s\n", "Failed to resume execution of program.");
                                errorCode = ERROR;
                            } else {

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

                                        if(return_value != 0){
                                            errorCode = ERROR;
                                            fprintf(stderr, "Failed to call mprotect on 0x%08llX\n", mem_region);
                                        } else {
                                            dump_registers(program_vars.traced_program_id);

                                            /* Write the data to its previous location*/
                                            errorCode = write_data(program_vars.traced_program_id, program_vars.traced_function_address, BUFFER_SIZE,
                                                                   program_vars.instruction_backup);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                            } else {
                                                fprintf(stdout, "%s\n", "Registers before backup");
                                                dump_registers(program_vars.traced_program_id);
                                                /* restore registers state */
                                                program_vars.registers.rip = program_vars.traced_function_address;
                                                errorCode = set_registers_backup(program_vars.traced_program_id, &program_vars.registers);
                                                if (errorCode != NO_ERROR) {
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
    return errorCode;
}
