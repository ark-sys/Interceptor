#include "elfscan.h"
/*
 *  Check if ELF has been compiled dynamically or statically
 * */
ErrorCode check_elf_type(const char *program_name, int *result) {
    ErrorCode errorCode = NO_ERROR;

    Elf64_Ehdr *ehdr;
    Elf *elf;
    int fd;

    /* Open the input file */
    if ((fd = open(program_name, O_RDONLY)) == -1) {
        perror("Failed to open file.");
        errorCode = FILE_NOT_FOUND;
    } else {
        /* Obtain the ELF descriptor */
        (void) elf_version(EV_CURRENT);
        if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
            perror("Failed to get ELF begin section.");
            errorCode = ERROR;
        } else {

            /* Get header for current elf */
            if ((ehdr = elf64_getehdr(elf)) == NULL) {
                perror("Failed to get data section for Elf64 header");
                errorCode = ERROR;

            } else {

                switch (*result = ehdr->e_type) {
                    case ET_DYN:
                        fprintf(stdout, "DYN type detected.\n");
                        break;
                    case ET_EXEC:
                        fprintf(stdout, "EXEC type detected.\n");
                        break;
                    default:
                        fprintf(stderr, "Failed to get ELF type detected.\n");
                        errorCode = ERROR;
                        break;
                }

            }
            elf_end(elf);
        }
        close(fd);
    }

    return errorCode;
}

/*
 * Check if libraries are linked dynamically, otherwise get_libc_function_address(...) to lok for address in the traced space address
 * This will be done unorthodoxly
 * */
ErrorCode is_DT_available(const char *program_name, int *result) {
    ErrorCode errorCode = NO_ERROR;
    char command[LINE_SIZE];
    char readline[LINE_SIZE];
    snprintf(command, LINE_SIZE, "objdump -TC %s | grep 'no symbols'", program_name);
    FILE *command_1_fd;

    /* Check the command execution status */
    if ((command_1_fd = popen(command, "r")) == NULL) {
        perror("Failed to run command.");
        errorCode = NULL_POINTER;
    } else {
        /* Check only in the first few line*/
        if(fread(readline, LINE_SIZE, 1, command_1_fd) == 0){
            /*Symbol table seems to be dynamically linked */
            *result = 1;
        }else {
            /* 'no symbols' message have been found from command 'pgrep -TC <program_name> | grep 'no symbols''*/
            *result = 0;
        }
        pclose(command_1_fd);
    }
    return errorCode;
}

/* Return the pid of a program. */
ErrorCode get_pid(const char *argument_1, struct program_vars_t *program_vars) {
    ErrorCode errCode = NO_ERROR;
    /* pgrep count file descriptor */
    FILE *command_1_fd;
    /* pgrep pid */
    FILE *command_2_fd;
    /* cat cmdline binary path */
    FILE *command_3_fd;

    char command[COMMAND_SIZE];
    char pid_buffer[LINE_SIZE];

    /* pgrep -c <program_name> , check how many instances of the program are running */
    snprintf(command, COMMAND_SIZE, "pgrep -c %s", argument_1);


    /* Check the command execution status */
    if ((command_1_fd = popen(command, "r")) == NULL) {
        perror("Failed to run command.");
        errCode = NULL_POINTER;
    } else {
        /* Read the line and check that we are actually reading characters */
        if (fgets(pid_buffer, LINE_SIZE, command_1_fd) == NULL) {
            perror("Failed to read command output.");
            errCode = NULL_POINTER;
        } else {
            /* No programs have been found running */
            if (strtol(pid_buffer, NULL, 10) == 0) {
                errCode = PROGRAM_NOT_RUNNING;
            } else
                /* One instance of the program has been found */
            if (strtol(pid_buffer, NULL, 10) == 1) {
                /* pgrep <program_name>
                 * actually get the PID of the program that we want to trace
                 * */
                snprintf(command, COMMAND_SIZE, "pgrep %s", argument_1);
                command_2_fd = popen(command, "r");
                if (command_2_fd == NULL) {
                    perror("Failed to run command.");
                    errCode = NULL_POINTER;
                } else {
                    if (fgets(pid_buffer, LINE_SIZE, command_2_fd) == NULL) {
                        perror("Failed to read PID.");
                        errCode = NULL_POINTER;
                    } else {
                        /* The PID is converted and stored in a global structure for later use */
                        if ((program_vars->traced_program_id = (pid_t) strtol(pid_buffer, NULL, 10)) == 0) {
                            errCode = ERROR;
                            fprintf(stderr, "%s\n", "Failed to convert PID from char * to pid_t.");
                        } else {

                            /* Retrieve and store the exact path for the currently traced program
                             * Absolute path can be found via command line by typing 'ls -l /proc/pid/exe', the absolute path is the one after the arrow
                             * */
                            char path_to_program[COMMAND_SIZE];
                            snprintf(path_to_program, COMMAND_SIZE, "ls -l  /proc/%d/exe | cut -d \">\" -f2",
                                     program_vars->traced_program_id);

                            if ((command_3_fd = popen(path_to_program, "r")) == NULL) {
                                errCode = NULL_POINTER;
                                fprintf(stderr, "%s\n", "Failed to recover path of traced executable");
                            } else {
                                char buffer[COMMAND_SIZE];
                                if (fgets(buffer, COMMAND_SIZE, command_3_fd) == NULL) {
                                    errCode = NULL_POINTER;
                                    fprintf(stderr, "%s\n", "Failed to read path to executable.");
                                } else {

                                    sscanf(buffer, "%s", program_vars->traced_program_name);
                                    /* Check if the file is actually accessible */
                                    if (access(program_vars->traced_program_name, F_OK) != 0) {
                                        perror("Failed to access elf binary.");
                                        print_usage();
                                        errCode = FILE_NOT_FOUND;
                                    } else {

                                        /* Check current elf type so we know if we have to evaluate an offset for functions or not */
                                        errCode = check_elf_type(program_vars->traced_program_name,
                                                                 &program_vars->traced_program_type);
                                        if (errCode != NO_ERROR) {
                                            fprintf(stderr, "%s\n", "Failed to get elf type.");
                                        } else {
                                            /*  if dynamic elf detected, base address for main */
                                            if (program_vars->traced_program_type == ET_DYN) {
                                                get_program_startaddress(program_vars->traced_program_id, argument_1,
                                                                         &program_vars->program_start_address);
                                            } else {
                                                program_vars->program_start_address = 0;
                                            }
                                        }
                                    }
                                }
                                pclose(command_3_fd);
                            }
                        }
                    }
                    pclose(command_2_fd);
                } /*END if on command_2_fd */

            } /* Multiple instances of the program have been found */
            else {
                fprintf(stdout,
                        "%ld instances of binary <%s> have been found.\n Please select which one you want to trace\n",
                        strtol(pid_buffer, NULL, 10), argument_1);
                errCode = ERROR;
            }
        } //END if on first fgets
        pclose(command_1_fd);
    } //END if on command_1_fd




    return errCode;
}

ErrorCode get_program_startaddress(const pid_t traced_program_id, const char *traced_program_name,
                                   unsigned long long *program_start_address) {
    ErrorCode errCode = NO_ERROR;
    char path_to_mem[POS_SIZE];
    FILE *program_maps_fd;

    /* Create the command that will get us the position of the beginning of the main during runtime
     *
     * grep command will parse the file looking for
     * the line that contains the pattern '<program_name> and r-xp' (section where the executable functions of the program are located)
     * Once the line is found, it is piped to the cut commend that will split it in two parts (with the split happening at the first -)
     * We then take the first part that will correspond to the address that we are looking for
     * */
    snprintf(path_to_mem, POS_SIZE, "grep -E \'r-xp.*%s\' /proc/%d/maps | cut -d \"-\" -f1", traced_program_name,
             traced_program_id);

    /* Open the file and do some error checking */
    if ((program_maps_fd = popen(path_to_mem, "r")) == NULL) {
        perror("Failed to open maps for PID %s");
        errCode = NULL_POINTER;
    } else {

        char readline[LINE_SIZE];
        /* Start reading one line at the time */
        if (fgets(readline, LINE_SIZE, program_maps_fd) == NULL) {
            perror("Failed to read maps file.");
            errCode = NULL_POINTER;
        } else {
            /* Since readline is a char* buffer, convert it to unsigned long to match address representation */
            *program_start_address = strtoull(readline, NULL, 16);
            /* strtoul returns 0 if there is an error.
             * Also if PID is really 0, then something is reaaallly wrong
             * */
            if (*program_start_address == 0) {
                errCode = ERROR;
            } else {
                fprintf(stdout, "Program start address has been located at 0x%llX\n", *program_start_address);
            }


        }
        pclose(program_maps_fd);

    }
    return errCode;
}


ErrorCode
get_libc_function_address(const struct program_vars_t program_vars,
                          unsigned long long *function_address, const char *libc_function_name) {

    ErrorCode errCode = NO_ERROR;


    char command[COMMAND_SIZE];
    char readline[LINE_SIZE];
    FILE *command_fd;

    /* In this value we store the result of is_DT_available. This will check il libraries are dynamically linked or not */
    int isdt;
    errCode = is_DT_available(program_vars.traced_program_name, &isdt);
    if (errCode != NO_ERROR){
        fprintf(stderr, "%s\n", "Failed to check if libraries are dynamically linked");
    }
    /*
     * If traced program is statically linked, then all libraries are compiled within its addressing space
     * So we can fetch for libc address by simply looking at disassemble dump
     * */
    if ((program_vars.traced_program_type == ET_EXEC) && (isdt == 0)) {
        /*
         * This command will first retrieve the symbol tableo for the traced program
         * Then we will look for the line that matches exactly the function that we need
         * From this line we will select the first that that corresponds to the libc function address in the traced program
         * */
        snprintf(command, COMMAND_SIZE, "objdump -t %s | grep -w '%s' | cut -d \" \" -f1",
                 program_vars.traced_program_name, libc_function_name);
        /* Open the file and do some error checking */
        if ((command_fd = popen(command, "r")) == NULL) {
            perror("Failed to open command for PID %s");
            errCode = NULL_POINTER;
        } else {
            /* Check if we are correctly reading lines */
            if (fgets(readline, LINE_SIZE, command_fd) == NULL) {
                errCode = NULL_POINTER;
            } else {

                /* Check if the content that we got has a good format (like a function's address)*/
                if (strtoul(readline, NULL, 16) == 0) {
                    errCode = FUNCTION_NOT_FOUND;
                } else {
                    /* Get a correct representation of the address from char* to unsigned long*/
                    *function_address = strtoul(readline, NULL, 16);
                }
            }
            pclose(command_fd);
        }

    } else
        /*
         * In this case libc is dynamically linked, we need to
         * First : get base address for libc in traced program memory
         * Second : get offset for the function that we are looking for in libc .so file
         * Third : sum up there two addresses, this will be the final address that we will need if we want to call a libc function
         *
         * */
     {
        char path_to_mem[POS_SIZE];
        unsigned long long libc_mem_baseaddress;
        FILE *program_maps_fd;

        /* Create the command that will get us the position of the beginning of the main during runtime */
        snprintf(path_to_mem, POS_SIZE, "grep -E \'r-xp.*libc\' /proc/%d/maps", program_vars.traced_program_id);

        /* Open the file and do some error checking */
        if (NULL == (program_maps_fd = popen(path_to_mem, "r"))) {
            perror("Failed to open maps for PID %s");
            errCode = NULL_POINTER;
        } else {

            /* Recover the line that contains the address and path for the executable library */
            if (fgets(readline, LINE_SIZE, program_maps_fd) == NULL) {
                perror("Failed to read maps file.");
                errCode = NULL_POINTER;
            } else {

                /* libc_mem_baseaddress will contain start of address of libc in tracee memory.
                 * buffer1 will contain the path to the .so used during program link
                 * */
                char buffer1[POS_SIZE];

                if (sscanf(readline, "%llx-%*x %*s %*x %*s %*d %s", &libc_mem_baseaddress, buffer1) == EOF) {
                    perror("Failed to scan line.");
                    errCode = ERROR;
                } else {

                    /*  Convert libc address to unsigned long long*/
                    if (libc_mem_baseaddress == 0) {
                        errCode = ERROR;
                        fprintf(stderr, "%s\n", "Conversion of libc base address failed");
                    } else {

                        /*
                         * This command will first check if the function that we are looking for is unique in the symbol table
                         * A '/' has been added before the first '%s' because during the last tokenization we removed it (:
                         * */
                        snprintf(command, COMMAND_SIZE, "objdump -TC /%s | grep -w %s", buffer1, libc_function_name);
                        /* Open the file and do some error checking */
                        if ((command_fd = popen(command, "r")) == NULL) {
                            perror("Failed to open command for PID %s");
                            errCode = NULL_POINTER;
                        } else {
                            /* Check if we are correctly reading lines */
                            if (fgets(readline, LINE_SIZE, command_fd) == NULL) {
                                errCode = NULL_POINTER;
                            } else {

                                /* Check if the content that we got has a good format (like a function's address)*/
                                if (strtoul(readline, NULL, 16) == 0) {
                                    errCode = FUNCTION_NOT_FOUND;
                                } else {
                                    /* Get a correct representation of the address from char* to unsigned long*/
                                    *function_address = strtoul(readline, NULL, 16) + libc_mem_baseaddress;
                                }
                            }
                            pclose(command_fd);
                        }

                    }
                }

            }
            pclose(program_maps_fd);
        }
    }
    return errCode;
}

/* Parses the traced program memory file and returns the address of function passed as argument; return value is the second argument */
ErrorCode
get_function_offset(const char *traced_program_name, const char *function_name, unsigned long long *function_offset) {
    ErrorCode errCode = NO_ERROR;
    FILE *binary_dump_fd;

    char command[COMMAND_SIZE];
    char readline[LINE_SIZE];

    /* Prepare the command that has to be called in order to parse the binary */
    /* Command alias in bash : objdump -t <program_name> | grep -w <function_name> | cut -d " " -f1 */
    snprintf(command, COMMAND_SIZE, "objdump -t %s | grep -w %s | cut -d \" \" -f1", traced_program_name,
             function_name);

    binary_dump_fd = popen(command, "r");
    if (binary_dump_fd == NULL) {
        fprintf(stderr, "%s\n", "Failed to open binary dump.");
        errCode = NULL_POINTER;
    } else {

        /* Check if we are correctly reading lines */
        if (fgets(readline, LINE_SIZE, binary_dump_fd) == NULL) {
            errCode = NULL_POINTER;
        } else {

            /* Check if the content that we got has a good format (like a function's address)*/
            if (strtoul(readline, NULL, 16) == 0) {
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

ErrorCode get_function_size(const char *traced_program_name, unsigned long long int function_address,
                            unsigned long *size_output) {
    ErrorCode errorCode = NO_ERROR;
    char command[COMMAND_SIZE];
    char readline[LINE_SIZE];
    FILE *command_fd;
    /*
     * This command will print the size of functions (number of instructions) that appear in the symbol table
     * format the output to a decimal value
     * select only the value for the function that we are tracing
     * recover the actual size of the function
     * */
    snprintf(command, COMMAND_SIZE, "nm --print-size --size-sort --radix=d %s | grep %llu | cut -d \" \" -f2",
             traced_program_name, function_address);
    command_fd = popen(command, "r");
    if (command_fd == NULL) {
        fprintf(stderr, "%s\n", "Failed to run nm command.");
        errorCode = NULL_POINTER;
    } else {

        if (fgets(readline, LINE_SIZE, command_fd) == NULL) {
            errorCode = NULL_POINTER;
        } else {
            if ((*size_output = strtoul(readline, NULL, 10)) == 0) {
                errorCode = ERROR;
            }
        }
    }
    return errorCode;
}
