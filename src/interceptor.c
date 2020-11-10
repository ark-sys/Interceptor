#include "interceptor.h"
/* Structure needed to store variables used in different sections of the program */
static struct program_vars_t program_vars;

/* Byte code instruction of 'trap' */
static const unsigned char trap_instruction = 0xCC;

/* Indirect call instruction */
static const unsigned char indirect_call[3] = {0xFF, 0xD0, 0xCC};

/* Jump instruction */
static const unsigned char jump_instruction[2] = {0x48, 0xB8};

static void print_usage(void){
    fprintf(stderr, "%s\n", "Usage : ./Interceptor [program_name] [function_name]");
}

static void dump_memory(unsigned long start_address, int nb_bytes){
    unsigned data;
    fprintf(stdout, "===== MEMORY DUMP =====\n");
    for(int i = 0; i < nb_bytes; i = i+4){
        data = ptrace(PTRACE_PEEKTEXT, program_vars.traced_program_id, (void *)(start_address+i), 0);
        fprintf(stdout, "0x%08lX : 0x%08X\n", (start_address+i), htonl(data));
    }
    fprintf(stdout,   "=======================\n\n");

}

static ErrorCode dump_registers(void){
    ErrorCode errorCode = NO_ERROR;
    struct user_regs_struct current_registers;

    if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &current_registers) < 0)
    {
        fprintf(stderr, "%s\n", "Failed to get current registers.");
        errorCode = ERROR;
    } else {
        fprintf(stdout, "==== REGISTERS  DUMP ====\n");
        fprintf(stdout, "RIP at 0x%016llX\nRAX at 0x%016llX\nRDI at 0x%016llX\nRSP at 0x%016llX\n", current_registers.rip, current_registers.rax, current_registers.rdi, current_registers.rsp);
        fprintf(stdout,   "=========================\n\n");
    }

    return errorCode;
}

static ErrorCode get_program_mainaddress(void)
{
    ErrorCode errCode = NO_ERROR;
    char path_to_mem[POS_SIZE];
    FILE * program_maps_fd;

    /* Create the command that will get us the position of the beginning of the main during runtime */
    snprintf(path_to_mem, POS_SIZE, "cat /proc/%d/maps", program_vars.traced_program_id);

    /* Open the file and do some error checking */
    if((program_maps_fd = popen(path_to_mem, "r")) == NULL){
        perror("Failed to open maps for PID %s");
        errCode = NULL_POINTER;
    } else {

        char readline[LINE_SIZE];
        /* Start reading one line at the time */
        while(fgets(readline, LINE_SIZE, program_maps_fd)){
            /* If line contains r-xp and the name of the program, then we know that is the first line of /proc/pid/maps which contains the start address for the functions */
            if((strstr(readline, program_vars.traced_program_name) != NULL) && (strstr(readline, "r-xp") != NULL)){
                /* Get the first item of the line */
                strtok(readline, "-");
                /* Since readline is a char* buffer, convert it to unsigned long to match address representation */
                program_vars.program_main_address = strtoul(readline, NULL,16);
                /* strtoul returns 0 if there is an error.
                 * Also if PID is really 0, then something is reaaallly wrong
                 * */
                if(program_vars.program_main_address == 0){
                    errCode = ERROR;
                }
                break;
            }
        }
        pclose(program_maps_fd);

    }
    return errCode;
}

/* Return the pid of a program. */
static ErrorCode get_pid(const char * argument_1)
{
    ErrorCode errCode = NO_ERROR;

    FILE* command_1_fd;
    FILE* command_2_fd;

    char command[COMMAND_SIZE];
    char pid_buffer[LINE_SIZE];

    /* Check if the file exists and is accessible */
    if (access(argument_1, F_OK) != -1){
        fprintf(stdout, "\nOpening binary: <%s>\n", argument_1);

        /* Store the program name for later use */
        snprintf(program_vars.traced_program_name, POS_SIZE, "%s", argument_1);

        /* pgrep -c <program_name> , check how many instances of the program are running */
        snprintf(command, COMMAND_SIZE, "pgrep -c %s", argument_1);
        command_1_fd = popen(command, "r");

        /* Check the command execution status */
        if(command_1_fd == NULL)
        {
            perror("Failed to run command.");
            errCode = NULL_POINTER;
        } else {
            /* Read the line and check that we are actually reading characters */
            if (fgets(pid_buffer, LINE_SIZE, command_1_fd) == NULL)
            {
                perror("Failed to read command output.");
                errCode = NULL_POINTER;
            } else {
                /* No programs have been found running */
                if (strtol(pid_buffer, NULL, 10) == 0){
                    errCode = PROGRAM_NOT_RUNNING;
                } else
                    /* One instance of the program has been found */
                if (strtol(pid_buffer, NULL, 10) == 1){
                    /* pgrep <program_name>
                     * actually get the PID of the program that we want to trace
                     * */
                    snprintf(command, COMMAND_SIZE, "pgrep %s", argument_1);
                    command_2_fd = popen(command, "r");
                    if (command_2_fd == NULL){
                        perror("Failed to run command.");
                        errCode = NULL_POINTER;
                    } else {
                        if (fgets(pid_buffer, LINE_SIZE, command_2_fd) == NULL){
                            perror("Failed to read PID.");
                            errCode = NULL_POINTER;
                        } else {
                            /* The PID is converted and stored in a global structure for later use */
                            program_vars.traced_program_id = strtol(pid_buffer, NULL, 10);

                            /* Check current elf type so we know if we have to evaluate an offset for functions or not */
                            errCode = check_elf_type(argument_1, &program_vars.traced_program_type);
                            if((errCode != NO_ERROR) || (program_vars.traced_program_type == NULL)){
                                fprintf(stderr,"%s\n", "Failed to get elf type.");
                            }else{
                                /*  if dynamic elf detected, base address for main */
                                if (program_vars.traced_program_type == ET_DYN){
                                    get_program_mainaddress();
                                }  else {
                                    program_vars.program_main_address = 0;
                                }
                            }
                        }
                        pclose(command_2_fd);
                    } /*END if on command_2_fd */

                } /* Multiple instances of the program have been found */
                else {
                    fprintf(stdout, "%ld instances of binary <%s> have been found.\n Please select which one you want to trace\n", strtol(pid_buffer, NULL, 10), argument_1);
                    //#todo add prompt selection in case multiple instances have been found
                    errCode= ERROR;
                }
            } //END if on first fgets
            pclose(command_1_fd);
        } //END if on command_1_fd

    } else {
        /* On access failure, print help */
        print_usage();
        errCode = FILE_NOT_FOUND;
    } // END ifelse acces()


    return errCode;
}



/* Parses the traced program memory file and returns the address of function passed as argument; return value is the second argument */
static ErrorCode get_function_offset(const char * function_name, unsigned long * function_offset)
{
    ErrorCode errCode = NO_ERROR;
    FILE * binary_dump_fd;

    char command[COMMAND_SIZE];
    char readline[LINE_SIZE];

    /* Prepare the command that has to be called in order to parse the binary */
    /* Command alias in bash : objdump -t <program_name> | grep -w <function_name> | cut -d " " -f1 */
    snprintf(command, COMMAND_SIZE, "objdump -t %s | grep -w %s | cut -d \" \" -f1", program_vars.traced_program_name, function_name);

    binary_dump_fd = popen(command, "r");
    if(binary_dump_fd == NULL)
    {
        fprintf(stderr, "%s\n", "Failed to open binary dump.");
        errCode = NULL_POINTER;
    } else {

        /* Check if we are correctly reading lines */
        if (fgets(readline, LINE_SIZE, binary_dump_fd) == NULL)
        {
            errCode = NULL_POINTER;
        } else {

            /* Check if the content that we got has a good format (like a function's address)*/
            if(strtol(readline, NULL, 16) == 0){
                errCode = FUNCTION_NOT_FOUND;

            } else {
                /* Get a correct representation of the address from char* to unsigned long*/
                *function_offset = strtoul(readline, NULL, 16);
            }
        }

        pclose(binary_dump_fd);
    }

    return errCode;
}

static ErrorCode get_function_size(unsigned long function_address, int * size_output){
    ErrorCode errorCode = NO_ERROR;
    char command[COMMAND_SIZE];
    char readline[LINE_SIZE];
    FILE * command_fd;
    /*
     * This command will print the size of functions (number of instructions) that appear in the symbol table
     * format the output to a decimal value
     * select only the value for the function that we are tracing
     * recover the actual size of the function
     * */
    snprintf(command, COMMAND_SIZE, "nm --print-size --size-sort --radix=d %s | grep %lu | cut -d \" \" -f2", program_vars.traced_program_name, function_address);
    command_fd = popen(command, "r");
    if(command_fd == NULL){
        fprintf(stderr, "%s\n", "Failed to run nm command.");
        errorCode = NULL_POINTER;
    } else {

        if(fgets(readline, LINE_SIZE, command_fd) == NULL)
        {
            errorCode = NULL_POINTER;
        } else {
            *size_output = atoi(readline);
        }
    }
    return errorCode;
}

static ErrorCode get_registers_backup(void){
    ErrorCode errorCode = NO_ERROR;
    if(ptrace(PTRACE_GETREGS, program_vars.traced_program_id, NULL, &program_vars.registers) < 0){
        fprintf(stderr,"%s\n", "Failed to save current registers state.");
        errorCode = ERROR;
    }
    return errorCode;
}

static ErrorCode set_registers_backup(void){
    ErrorCode errorCode = NO_ERROR;
    if(ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &program_vars.registers) < 0){
        fprintf(stderr,"%s\n", "Failed to set backup registers state.");
        errorCode = ERROR;
    }
    return errorCode;
}

static ErrorCode set_breakpoint(const unsigned long address_position){
    ErrorCode errorCode = NO_ERROR;
    unsigned data;
    int wait_status;
    char path_to_mem[128];
    FILE * mem_file_fd;


    /* Prepare path to memory file and open it with some error checking */
    snprintf(path_to_mem, 128, "/proc/%d/mem", program_vars.traced_program_id);
    mem_file_fd = fopen(path_to_mem, "r+");
    if(mem_file_fd == NULL){
        errorCode = NULL_POINTER;
        perror("Failed to open mem file.");
    } else {
        /* Get file position at offset "address_position", so we can write at the first instruction of the traced function */
        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Read data at address position before we set the breakpoint. This should have the same result as 'objdump -d' at the 'address_position' section. */
            data = ptrace(PTRACE_PEEKTEXT, program_vars.traced_program_id, (void *)address_position,0);
            fprintf(stdout,"Setting breakpoint at 0x%08lX. Data is 0x%08X\n", address_position, htonl(data));
            /* Write the trap instruction at the beginning of the trace function */
            if(fwrite(&trap_instruction, 1,1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write trap.");
            }
        }

        /* If everything went fine, close the file to apply changes */
        fclose(mem_file_fd);

        /* Check that no error has been made in the previous part */
        if(errorCode == NO_ERROR){

            /* Restart the process and wait that it continues */
            if(ptrace(PTRACE_CONT, program_vars.traced_program_id, NULL, NULL) < 0){
                perror("Failed to resume execution of program.");
                errorCode = ERROR;
            } else {

                /* Check that the process actually changed its state */
                if(program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status, WCONTINUED)){
                    perror("Error waitpid.");
                    errorCode = ERROR;
                } else {
                    fprintf(stdout, "PID <%d> got signal: %s\n\n", program_vars.traced_program_id, strsignal(WSTOPSIG(wait_status)));

                } // End of waitpid section


            } // End of PTRACE_CONT section

        } // End of check on errorCode

    }// End of if on mem_file_fd

    return errorCode;
}

static ErrorCode read_data(const unsigned long address_position, size_t data_length, char * output_buffer){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", program_vars.traced_program_id);
    if (NULL == (mem_file_fd = fopen(path_to_mem, "r"))){
        errorCode = NULL_POINTER;
        perror("Failed to open memory file.");
    } else {

        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Read data to buffer */
            if(fread(output_buffer, sizeof(char)*data_length,1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to read data.");
            }
        }
        fclose(mem_file_fd);
    }
    return errorCode;
}

static ErrorCode write_data(const unsigned long address_position, size_t data_length, const char * input_buffer){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", program_vars.traced_program_id);
    if (NULL == (mem_file_fd = fopen(path_to_mem, "r+"))){
        errorCode = NULL_POINTER;
        perror("Failed to open memory file.");
    } else {

        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Just a print message to see what we are writing */
            fprintf(stdout, "Writing ");
            for(int i = 0; i < (int)data_length; i++){

                fprintf(stdout, "0x%X ", (input_buffer[i] & 0xFF));
            }
            fprintf(stdout, " at address 0x%08lX\n" ,address_position);

            /* Write data from buffer to memory */
            if(fwrite(input_buffer, sizeof(char), data_length, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write data.");
            } else {
                fclose(mem_file_fd);

                fprintf(stdout,"%s\n", "Memory state after writing.");
                dump_memory(address_position, data_length*2);
            }

        }

    }
    return errorCode;
}

static ErrorCode write_values(const unsigned long address_position, size_t data_length, const char *  input_buffer){
    ErrorCode errorCode = NO_ERROR;

    int tmp = atoi(input_buffer);

    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", program_vars.traced_program_id);
    if (NULL == (mem_file_fd = fopen(path_to_mem, "r+"))){
        errorCode = NULL_POINTER;
        perror("Failed to open memory file.");
    } else {

        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {
            /* Just a print message to see what we are writing */
            fprintf(stdout, "Writing %x at address 0x%08lX.\n", (unsigned)tmp,address_position);

            if(fwrite(&tmp, sizeof(int),1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write data.");
            } else {
                /* Write data from buffer to memory */
                fprintf(stdout, "%s\n", "Memory state after writing.");
                dump_memory(address_position, data_length * 2);
            }

            fclose(mem_file_fd);

        }

    }

    return errorCode;
}

static ErrorCode call_function_ref(const unsigned long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup();
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_function_address, 8);
                dump_registers();

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08lX\n", function_to_call);
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
                    dump_memory(regs.rsp, 8);

                    /* Write argument param to memory space addressed by regs.rsp */
                    errorCode = write_values(regs.rsp, strlen(param), param);
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
                            errorCode = write_data(program_vars.traced_function_address, sizeof(indirect_call), (char *)indirect_call);
                            if(errorCode != NO_ERROR)
                            {
                                fprintf(stderr, "%s\n","Failed to write data in memory.");

                            } else {
                                fprintf(stdout, "Jumping to 0x%08lX\n", function_to_call);

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

                                            /* Pass the returned value from the called function to the traced function */
                                            regs.rip = program_vars.traced_function_address;
                                            ptrace(PTRACE_SETREGS, program_vars.traced_program_id,0 , &regs);

                                            dump_registers();

                                            /* Stop the execution of the program so we can reinstate the data backup to its previous location */
                                            errorCode = set_breakpoint(program_vars.traced_function_address);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "Failed to set breakpoint at line %d.\n",__LINE__);
                                            } else {

                                                /* Write the data to its previous location*/
                                                errorCode = write_data(program_vars.traced_function_address,
                                                                       BUFFER_SIZE, program_vars.instruction_backup);
                                                if (errorCode != NO_ERROR) {
                                                    fprintf(stderr, "%s\n","Failed to recover data backup.");
                                                } else {
                                                    fprintf(stdout, "%s\n","Registers before backup");
                                                    dump_registers();
                                                    program_vars.registers.rip = program_vars.traced_function_address;
                                                    program_vars.registers.rdi = return_value;

                                                    /* restore registers state */
                                                    errorCode = set_registers_backup();
                                                    if (errorCode != NO_ERROR) {
                                                        fprintf(stderr,"%s\n",
                                                                "Failed to recover registers backup.");
                                                    }
                                                    fprintf(stdout, "%s\n","Registers after backup");
                                                    dump_registers();
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

static ErrorCode call_function_val(const unsigned long function_to_call, const char *param) {
    ErrorCode errorCode = NO_ERROR;
    int wait_status;

    /* Read and do a backup of a certain amount of memory data that will be replaced by the indirect call instruction */
    errorCode = read_data(program_vars.traced_function_address, BUFFER_SIZE, program_vars.instruction_backup);
    if (errorCode != NO_ERROR) {
        fprintf(stderr, "%s\n", "Failed to read memory backup");
    } else {

        /* Set a breakpoint at the beginning of the function so we can stop its execution */
        errorCode = set_breakpoint(program_vars.traced_function_address);
        if (errorCode != NO_ERROR) {
            fprintf(stderr, "%s\n", "Failed to set breakpoint.");
        } else {

            /* Get a backup of all registers before we start operations */
            errorCode = get_registers_backup();
            if (errorCode != NO_ERROR) {
                fprintf(stderr, "%s\n", "Failed to get registers backup.");
            } else {


                /* Look at the current data at rip */
                dump_memory(program_vars.traced_function_address, 8);
                dump_registers();

                struct user_regs_struct regs;
                fprintf(stdout, "Calling function at address 0x%08lX\n", function_to_call);
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
                    regs.rdi = (unsigned long long) (atoi(param));

                    /* Set new registers */
                    if (ptrace(PTRACE_SETREGS, program_vars.traced_program_id, NULL, &regs) < 0) {
                        fprintf(stderr, "%s\n", "Failed to set new registers");
                        errorCode = ERROR;
                    } else {
                        /* Open /proc/pid/mem so we can write the indirect call instruction followed by a breakpoint (so we can recover the return value from the called function) */
                        errorCode = write_data(program_vars.traced_function_address, sizeof(indirect_call),
                                               (char *) indirect_call);
                        if (errorCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "Failed to write data in memory.");

                        } else {
                            fprintf(stdout, "Jumping to 0x%08lX\n", function_to_call);

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
                                        regs.rip = program_vars.traced_function_address;
                                        ptrace(PTRACE_SETREGS, program_vars.traced_program_id, 0, &regs);

                                        dump_registers();

                                        /* Stop the execution of the program so we can reinstate the data backup to its previous location */
                                        errorCode = set_breakpoint(program_vars.traced_function_address);
                                        if (errorCode != NO_ERROR) {
                                            fprintf(stderr, "Failed to set breakpoint at line %d.\n", __LINE__);
                                        } else {

                                            /* Write the data to its previous location*/
                                            errorCode = write_data(program_vars.traced_function_address, BUFFER_SIZE,
                                                                   program_vars.instruction_backup);
                                            if (errorCode != NO_ERROR) {
                                                fprintf(stderr, "%s\n", "Failed to recover data backup.");
                                            } else {
                                                fprintf(stdout, "%s\n", "Registers before backup");
                                                dump_registers();
                                                program_vars.registers.rip = program_vars.traced_function_address;
                                                program_vars.registers.rdi = return_value;

                                                /* restore registers state */
                                                errorCode = set_registers_backup();
                                                if (errorCode != NO_ERROR) {
                                                    fprintf(stderr, "%s\n",
                                                            "Failed to recover registers backup.");
                                                }
                                                fprintf(stdout, "%s\n", "Registers after backup");
                                                dump_registers();
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

int func4 (int * i){
    *i = *i * 1000000;
    return *i;
}

int main(int argc, char *argv[]) {
    printf("\e[1;1H\e[2J");
    if (argc != 5) {
        print_usage();
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(INVALID_ARGUMENT));
        return INVALID_ARGUMENT;
    }

    ErrorCode errCode;
    /* Get program name from argument_1, check for errors and store name in global struct */
    /* Get the PID of current instance of the program */
    errCode = get_pid(argv[1]);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\n<%s> PID: %d\n", argv[1], program_vars.traced_program_id);
    }

    /* Look for the address of the target function in the binary dump */
    errCode = get_function_offset(argv[2], &program_vars.traced_function_offset);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        program_vars.traced_function_address = program_vars.traced_function_offset + program_vars.program_main_address;
        fprintf(stdout, "\nTracing function <%s> at address: 0x%08lX\n", argv[2], program_vars.traced_function_address);
    }

    /* Retrieve the size of the function in memory  */
    errCode = get_function_size(program_vars.traced_function_offset, &program_vars.traced_function_size);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\nFunction size: %d bytes.\n", program_vars.traced_function_size);
    }

    unsigned long addr_func_to_call;
    errCode = get_function_offset(argv[3], &addr_func_to_call);
    if (errCode != NO_ERROR){
        fprintf(stderr, "%s\n","Failed to get address for func2.");
        return errCode;
    } else {
        addr_func_to_call = addr_func_to_call + program_vars.program_main_address;
    }
    /*
     * START OPERATIONS ON CURRENT PID
     */

    int wait_status;

    if(ptrace(PTRACE_ATTACH, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stderr, "Error during PTRACE_ATTACH at line %d.\n", __LINE__);
    } else {

        if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,0)){
            fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
        } else {

            /* State of memory and registers of traced function */
            dump_memory(program_vars.traced_function_address, program_vars.traced_function_size);
            dump_registers();

//#todo sanity check and conversion on value here before we pass it to functions

            if (strcmp("func2", argv[3]) == 0) {
                errCode = call_function_val(addr_func_to_call, argv[4]);
                if (errCode != NO_ERROR) {
                    fprintf(stderr, "%s\n", "Failed to call func2.");
                }
            } else if (strcmp("func3", argv[3]) == 0) {
                errCode = call_function_ref(addr_func_to_call, argv[4]);
                if (errCode != NO_ERROR) {
                    fprintf(stderr, "%s\n", "Failed to call func2.");
                }
            } else {

                fprintf(stderr, "Function not found at line %d.", __LINE__);
            }

        }
    }

    /*
     * END OF OPERATIONS
     * */

    if(ptrace(PTRACE_DETACH, program_vars.traced_program_id, NULL, NULL) < 0){
        errCode = ERROR;
        fprintf(stderr, "Error during PTRACE_DETACH.\n");
    } else {
        fprintf(stdout, "\nDetached from PID %d\n\n", program_vars.traced_program_id);
    }

    return errCode;
}