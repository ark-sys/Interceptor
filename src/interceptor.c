#include "interceptor.h"

/* Structure needed to store variables used in different sections of the program */
static struct program_vars_t program_vars;

int func4(int i) {
    i = i + 10;
    return i;
}

int main(int argc, char *argv[]) {
    ErrorCode errCode;
    if (argc < 6){
        fprintf(stderr, "Missing parameters. %s \n", ErrorCodetoString(INVALID_ARGUMENT));
        print_usage();
        return INVALID_ARGUMENT;
    }

    /* Clear screen */
//    system("clear");

    /*
     * mode == 0 -> running indirect call
     * mode == 1 -> running trampoline
     * */
    int mode;

    /*
     * Type of indirect call (default) 0 -> call by value
     *                                 1 -> call by reference
     *                                 2 -> allocate memory, put execute flags, inject call, do call by value, clean memory
     * */
    int type_ic = 0;

    /* Parse for arguments */
    int c;
    char program_name[POS_SIZE];
    char traced_function_name[POS_SIZE];
    char function_to_call[POS_SIZE];
    char param[POS_SIZE];
    while ((c = getopt(argc, argv, "f:t:ai:r:p:h")) != -1) {
        switch (c) {
            case 'h':
                print_usage();
                break;
            case 't':
                mode = 1;
                strcpy(function_to_call, "func4");
                break;
            case 'f':
                strcpy(traced_function_name, optarg);
                break;
            case 'i':
                mode = 0;
                strcpy(function_to_call, optarg);
                break;
            case 'r':
                type_ic = 1;
                break;
            case 'a':
                type_ic = 2;
                break;
            case 'p':
                strcpy(param, optarg);
                break;
            case '?':
                if ((optopt == 't') || (optopt == 'i') || (optopt == 'p')) {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                } else if (isprint(optopt)) {
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                    print_usage();
                } else {
                    fprintf(stderr,
                            "Unknown option character `\\x%x'.\n",
                            optopt);
                }
                return INVALID_ARGUMENT;
            default:
                abort();
        }
    }


    /*Retrieve non-parameter argument*/
    strcpy(program_name, argv[optind]);

    /* Get program name from argument_1, check for errors and store name in global struct */
    /* Get the PID of current instance of the program */
    errCode = get_pid(program_name, &program_vars);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\n<%s> PID: %d\n", program_name, program_vars.traced_program_id);
    }

    /* Look for the address of the target function in the binary dump */
    errCode = get_function_offset(program_vars.traced_program_name, traced_function_name,
                                  &program_vars.traced_function_offset);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        program_vars.traced_function_address = program_vars.traced_function_offset + program_vars.program_start_address;
        fprintf(stdout, "\nTracing function <%s> at address: 0x%08llX\n", traced_function_name,
                program_vars.traced_function_address);
    }

    /* Retrieve the size of the function in memory  */
    errCode = get_function_size(program_vars.traced_program_name, program_vars.traced_function_offset,
                                &program_vars.traced_function_size);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\n<%s>> size: %lu bytes.\n\n", traced_function_name, program_vars.traced_function_size);
    }


    unsigned long long addr_func_to_call = 0;
    unsigned long long func4_address = 0;
    unsigned long func4_size = 0;


    /*
     * Addresses will be stored here
     * pms_address : posix_memalign address
     * address_to_region : address to newly allocated memory by posix_memalign
     * mp_address : mprotect address
     *
     * */

    unsigned long long pma_address = 0;
    unsigned long long address_to_region = 0;
    unsigned long long mp_address = 0;

    /* Running program for indirect call, here we fetch for useful information before attaching to PID */
    if (mode == 0) {

        errCode = get_function_offset(program_vars.traced_program_name, function_to_call, &addr_func_to_call);
        if (errCode != NO_ERROR) {
            fprintf(stderr, "%s <%s>\n", "Failed to get address for", function_to_call);
        } else {
            addr_func_to_call = addr_func_to_call + program_vars.program_start_address;
        }


    } else if (mode == 1) {


        /* Look for the address of the target function in the binary dump of this program */
        errCode = get_function_offset(argv[0], function_to_call, &func4_address);
        if (errCode != NO_ERROR) {
            fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
            return errCode;
        } else {
            fprintf(stdout, "Function to inject <%s> at address: 0x%08llX\n", function_to_call, func4_address);
        }
        /* Retrieve the size of the function in memory  */
        errCode = get_function_size(argv[0], func4_address, &func4_size);
        if (errCode != NO_ERROR) {
            fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
            return errCode;
        } else {
            fprintf(stdout, "\n<%s> size: %lu bytes.\n\n", function_to_call, func4_size);
        }

        /*
         * Look for the address of posix_memalign in the dynamically linked libc and store it in pma_address
         * */
        errCode = get_libc_function_address(program_vars, &pma_address, "posix_memalign");
        if (errCode != NO_ERROR) {
            fprintf(stderr, "%s: %s\n", "Failed to get posix_memalign address.", ErrorCodetoString(errCode));
        } else {
            fprintf(stdout, "posix_memalign located at 0x%016llX\n", pma_address);
        }

        /*
         * Look for the address of protect address in the dynamically liked libc and store it in mp_address
         * */
        errCode = get_libc_function_address(program_vars, &mp_address, "mprotect");
        if (errCode != NO_ERROR) {
            fprintf(stderr, "%s: %s\n", "Failed to get posix_memalign address.",
                    ErrorCodetoString(errCode));
        } else {

            fprintf(stdout, "mprotect located at 0x%016llX\nzn", mp_address);
        }
    }



    /*
     * 
     * 
     *                                                          START OF OPERATIONS ON CURRENT PID
     * 
     * 
     *
     */
    int wait_status;
    if (ptrace(PTRACE_ATTACH, program_vars.traced_program_id, NULL, NULL) < 0) {
        fprintf(stderr, "Error during PTRACE_ATTACH at line %d.\n", __LINE__);
    } else {

        if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status, 0)) {
            fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
        } else {

            /* State of memory and registers of traced function */
            dump_memory(program_vars.traced_program_id, program_vars.traced_function_address,
                        program_vars.traced_function_size);
            dump_registers(program_vars.traced_program_id);

            /* For mode 0, the program will run a simple indirect call as required by challenge 2*/
            if (mode == 0) {
// ============================================================================================================================
                /*
                 * Simple indirect call to a function in the traced program memory with argument passed as value
                 * */
                if (type_ic == 1) {
                    errCode = call_function_ref(program_vars, addr_func_to_call, param);
                    if (errCode != NO_ERROR) {
                        fprintf(stderr, "Failed to call <%s> with argument <%s>\n", function_to_call, param);
                    }
                } else {
                    errCode = call_function_val(program_vars, addr_func_to_call, param);
                    if (errCode != NO_ERROR) {
                        fprintf(stderr, "Failed to call <%s> with argument <%s>\n", function_to_call, param);
                    }
                }
// ============================================================================================================================
            } else
                /*
                 * For mode 1, the program will allocate some excutable memory in tracee (with posix_memalign + mprotect ), inject a function in tracee new memory and set a jump to this function
                 * */
            if (mode == 1) {
                /*
                 * call posix_memalign from traced program and allocate 'func4_size' chunks of memory so we can write func4 instructions
                 * New memory will be pointed by the address stored in address_to_region
                 * */
                errCode = call_posix_memalign(program_vars, pma_address, func4_size, getpagesize(), &address_to_region);
                if (errCode != NO_ERROR) {
                    fprintf(stderr, "%s: %s\n", "Failed to call posix memalign.", ErrorCodetoString(errCode));
                } else {

                    /*
                    * Call mprotect on the new memory created by the previous call of posix_memalign
                    * mprotect will change protection flags if 'func4_size' chunks of memory starting from 'aligned_region'
                    * New flags will allow execution on new allocated memory
                    * */
                    errCode = call_mprotect(program_vars, mp_address, address_to_region, func4_size,
                                            (PROT_READ | PROT_WRITE | PROT_EXEC));
                    if (errCode != NO_ERROR) {
                        fprintf(stderr, "mprotect: %s\n", ErrorCodetoString(errCode));
                    } else {
                        /*
                         *  Check if mprotect put correct rights (expeciallu "execution") on new allocated memory
                         * */
                        errCode = is_region_executable(program_vars.traced_program_id, address_to_region);
                        if (errCode != NO_ERROR) {
                            fprintf(stderr, "%s\n", "New memory doesn't seem to be executable.");
                        } else {
                            /*
                           * RECAP : At this point we have allocated some space in [heap] memory and given rwx flags to it
                           * So now we will fill this space in memory with the function that we want to execute
                           * func4 is located in this program, so in order to run it from the traced program we need to write its instructions in the traced [heap] memory
                           * */

                            /*
                           * Create a buffer in which we will store func4 instructions
                           * */
                            unsigned char *func4_buffer = malloc(sizeof(unsigned char) * func4_size);
                            if (func4_buffer == NULL) {
                                fprintf(stderr, "%s\n", "Failed to malloc buffer.");
                                errCode = NULL_POINTER;
                            } else {

                                /*
                                 * Fill the buffer with func4 instructions
                                 * Since its in this program address space, we can access its address with &func4
                                 * */
                                fprintf(stdout, "Reading <%s> instructions from %s\n", "func4", argv[0]);
                                errCode = read_data(getpid(), (unsigned long long) &func4, func4_size,
                                                    func4_buffer);
                                if (errCode != NO_ERROR) {
                                    fprintf(stderr, "%s\n", "Failed to read func4 data in buffer.");
                                } else {

                                    /*
                                     * Write the instructions in the traced [heap] memory
                                     * */
                                    fprintf(stdout, "Writing <%s> instructions to %s\n", "func4", program_name);
                                    errCode = write_data(program_vars.traced_program_id, address_to_region,
                                                         func4_size, (const unsigned char *) func4_buffer);
                                    if (errCode != NO_ERROR) {
                                        fprintf(stderr, "%s\n", "Failed to write func4 data in heap.");
                                    } else {


                                        if (type_ic == 2){
                                            /*
                                            * At this point we assume that instructions were correctly written
                                            * So we can finally proceed by calling the function by value
                                             *
                                             *
                                             * This will demo challenge 3
                                            * */
                                            fprintf(stdout, "Preparing call to <%s>\n", function_to_call);
                                            errCode = call_function_val(program_vars, address_to_region, param);
                                            if (errCode != NO_ERROR) {
                                                fprintf(stderr, "%s <%s>\n", "Failed call to function", function_to_call);
                                            } else {
                                                errCode = clean_memory(program_vars, mp_address, address_to_region, func4_size);
                                                if (errCode != NO_ERROR) {
                                                    fprintf(stderr, "%s <%llu>\n", "Failed clean memory at", address_to_region);
                                                }
                                            }
                                        } else {

                                            /*
                                             * At this point we assume that instructions were correctly written
                                             * So we can finally proceed by calling the trampoline
                                             *
                                             * This will demo challenge 4
                                             * */
                                            fprintf(stdout, "Preparing call to <%s>\n", function_to_call);
                                            errCode = trampoline(program_vars, address_to_region, param);
                                            if (errCode != NO_ERROR) {
                                                fprintf(stderr, "%s <%s>\n", "Failed call to function", function_to_call);
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


    /*
     * END OF OPERATIONS
     * */

    if (ptrace(PTRACE_DETACH, program_vars.traced_program_id, NULL, NULL) < 0) {
        errCode = ERROR;
        fprintf(stderr, "Error during PTRACE_DETACH.\n");
    } else {
        fprintf(stdout, "\nDetached from PID %d\n\n", program_vars.traced_program_id);
    }

    return errCode;
}
