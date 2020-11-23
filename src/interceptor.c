#include "interceptor.h"

/* Structure needed to store variables used in different sections of the program */
static struct program_vars_t program_vars;
int func4 (int i){
    i = i*2;
    return i;
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
    errCode = get_pid(argv[1], &program_vars);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\n<%s> PID: %d\n", argv[1], program_vars.traced_program_id);
    }

    /* Look for the address of the target function in the binary dump */
    errCode = get_function_offset(program_vars.traced_program_name, argv[2], &program_vars.traced_function_offset);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        program_vars.traced_function_address = program_vars.traced_function_offset + program_vars.program_start_address;
        fprintf(stdout, "\nTracing function <%s> at address: 0x%08llX\n", argv[2], program_vars.traced_function_address);
    }

    /* Retrieve the size of the function in memory  */
    errCode = get_function_size(program_vars.traced_program_name, program_vars.traced_function_offset, &program_vars.traced_function_size);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\n<%s>> size: %lu bytes.\n\n",argv[2], program_vars.traced_function_size);
    }

    unsigned long long addr_func_to_call;




    /*
     * 
     * 
     * START OPERATIONS ON CURRENT PID
     * 
     * 
     *
     */
    int wait_status;

    if(ptrace(PTRACE_ATTACH, program_vars.traced_program_id, NULL, NULL) < 0){
        fprintf(stderr, "Error during PTRACE_ATTACH at line %d.\n", __LINE__);
    } else {

        if (program_vars.traced_program_id != waitpid(program_vars.traced_program_id, &wait_status,0)){
            fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
        } else {

            /* State of memory and registers of traced function */
            dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, program_vars.traced_function_size);
            dump_registers(program_vars.traced_program_id);

//#todo sanity check and conversion on value here before we pass it to functions
            /*
             * Simple indirect call to a function in the traced program memory with argument passed as value
             * */
            if (strcmp("func2", argv[3]) == 0) {
                errCode = get_function_offset(program_vars.traced_program_name, argv[3], &addr_func_to_call);
                if (errCode != NO_ERROR){
                    fprintf(stderr, "%s <%s>\n","Failed to get address for",argv[3]);
                } else {
                    addr_func_to_call = addr_func_to_call + program_vars.program_start_address;
                    errCode = call_function_val(program_vars, addr_func_to_call, argv[4]);
                    if (errCode != NO_ERROR) {
                        fprintf(stderr, "Failed to call <%s> with argument <%s>\n", argv[3], argv[4]);
                    }
                }



            } else
                /*
                 * Simple indirect call to a function in the traced program memory with argument passed as reference
                 * */
            if (strcmp("func3", argv[3]) == 0) {
                errCode = get_function_offset(program_vars.traced_program_name, argv[3], &addr_func_to_call);
                if (errCode != NO_ERROR){
                    fprintf(stderr, "%s <%s>\n","Failed to get address for",argv[3]);
                } else {
                    addr_func_to_call = addr_func_to_call + program_vars.program_start_address;
                    errCode = call_function_ref(program_vars, addr_func_to_call, argv[4]);
                    if (errCode != NO_ERROR) {
                        fprintf(stderr, "Failed to call <%s> with argument <%s>\n", argv[3], argv[4]);
                    }
                }


            } else
                /*
                 * Indirect call to a function written in the [heap] memory of the traced program
                 *
                 */

                if(strcmp("func4", argv[3]) == 0) {

                unsigned long long func4_address;
                /* Look for the address of the target function in the binary dump */
                errCode = get_function_offset(argv[0],argv[3], &func4_address);
                if (errCode != NO_ERROR) {
                    fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
                    return errCode;
                } else {
                }

                fprintf(stdout, "\nFunction to inject <%s> at address: 0x%08llX\n", argv[3],func4_address);
                unsigned long func4_size;
                /* Retrieve the size of the function in memory  */
                errCode = get_function_size(argv[0], func4_address, &func4_size);
                if (errCode != NO_ERROR) {
                    fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
                    return errCode;
                } else {
                    fprintf(stdout, "\n<%s> size: %lu bytes.\n\n",argv[3], func4_size);
                }

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
                unsigned long long aligned_region;
                /*
                 * Look for the address of posix_memalign in the dynamically linked libc and store it in pma_address
                 * */
                errCode = get_libc_function_address(program_vars,
                                                    &pma_address, "posix_memalign");
                if(errCode != NO_ERROR){
                    fprintf(stderr, "%s: %s\n","Failed to get posix_memalign address.", ErrorCodetoString(errCode));
                }else{
                    /*
                     * call posix_memalign from traced program and allocate 'func4_size' chunks of memory so we can write func4 instructions
                     * New memory will be pointed by the address stored in address_to_region
                     * */
                    fprintf(stdout,"\nposix_memalign located at 0x%016llX\n", pma_address);
                    /*
                     *  sysconf(_SC_PAGESIZE)  -> portable version of getpagesize
                     * */
                    errCode = call_posix_memalign(program_vars, pma_address, func4_size, 1024, &address_to_region);
                    if (errCode != NO_ERROR){
                        fprintf(stderr, "%s: %s\n", "Failed to call posix memalign.", ErrorCodetoString(errCode));
                    } else {
                        /*
                         * Manually align memory, work in progress
                         * */
                        aligned_region = address_to_region & ~((unsigned long long)(getpagesize()-1));
//                        aligned_region = address_to_region;
                        /*
                         * Look for the address of protect address in the dynamically liked libc and store it in mp_address
                         * */
                        errCode = get_libc_function_address(program_vars, &mp_address, "mprotect");
                        if(errCode != NO_ERROR){
                            fprintf(stderr, "%s: %s\n","Failed to get posix_memalign address.", ErrorCodetoString(errCode));
                        }else{
                            /*
                             * Call mprotect on the new memory created by the previous call of posix_memalign
                             * mprotect will change protection flags if 'func4_size' chunks of memory starting from 'aligned_region'
                             * New flags will allow execution on new allocated memory
                             * */
                            fprintf(stdout,"\nmprotect located at 0x%016llX\n", mp_address);
                            errCode = call_mprotect(program_vars, mp_address, aligned_region, func4_size, (PROT_READ | PROT_WRITE | PROT_EXEC));
                            if (errCode != NO_ERROR){
                                fprintf(stderr, "mprotect: %s\n", ErrorCodetoString(errCode));
                            } else {

                                errCode = is_region_executable(program_vars.traced_program_id, aligned_region);
                                if (errCode == NO_ERROR){
                                    /*
                                     * RECAP : At this point we have allocated some space in [heap] memory and given rwx flags to it
                                     * So now we will fill this space in memory with the function that we want to execute
                                     * func4 is located in this program, so in order to run it from the traced program we need to write its instructions in the traced [heap] memory
                                     * */

                                    /*
                                     * Create a buffer in which we will store func4 instructions
                                     * */
                                    unsigned char * func4_buffer = malloc(sizeof(unsigned char) * func4_size);
                                    if (func4_buffer == NULL){
                                        fprintf(stderr, "%s\n", "Failed to malloc buffer.");
                                        errCode = NULL_POINTER;
                                    } else {
                                        /*
                                         * Fill the buffer with func4 instructions
                                         * Since its in this program address space, we can access its address with &func4
                                         * */
                                        fprintf(stdout, "Reading <%s> instructions from %s\n","func4",argv[0]);
                                        errCode = read_data(getpid(),(unsigned long long)&func4, func4_size, func4_buffer);
                                        if(errCode != NO_ERROR){
                                            fprintf(stderr, "%s\n", "Failed to read func4 data in buffer.");
                                        }else{
                                            /*
                                             * Write the instructions in the traced [heap] memory
                                             * */
                                            fprintf(stdout, "Writing <%s> instructions to %s\n","func4",argv[1]);
                                            errCode = write_data(program_vars.traced_program_id, aligned_region, func4_size, (const unsigned char*)func4_buffer);
                                            if(errCode != NO_ERROR){
                                                fprintf(stderr, "%s\n", "Failed to write func4 data in heap.");
                                            } else {

                                                /*
                                                 * At this point we assume that instructions were correctly written
                                                 * So we can finally proceed by calling func4
                                                 * */
                                                fprintf(stdout, "Preparing call to <%s>\n", argv[4]);
//                                            errCode = call_function_val(program_vars, aligned_region, argv[4]);
                                                errCode = trampoline(program_vars, aligned_region, argv[4]);
                                                if(errCode != NO_ERROR){
                                                    fprintf(stderr, "%s <%s>\n", "Failed call to function", argv[4]);
                                                }
//                                                else {
//                                                    /*
//                                                     * Restore heap memory as it was before
//                                                     * */
//                                                    unsigned char * cleaning_buffer = malloc(sizeof(unsigned char) * func4_size);
//                                                    if( cleaning_buffer == NULL ){
//                                                        fprintf(stderr, "%s\n","Failed to malloc cleaning buffer");
//                                                        errCode = NULL_POINTER;
//                                                    } else {
//                                                        /* Fill the buffer with nothing */
//                                                        for(int i = 0; i<(int)func4_size; i++){
//                                                            cleaning_buffer[i] = 0x00;
//                                                        }
//
//                                                        /* Write the buffer at the location in heap where the injected function was written  */
//                                                        errCode = write_data(program_vars.traced_program_id, aligned_region, func4_size, (const unsigned char *)cleaning_buffer);
//                                                        if(errCode != NO_ERROR){
//                                                            fprintf(stderr,"%s\n","Failed to write cleaning buffer");
//                                                        }else{
//                                                            /* Restore previous protection flags for allocated region in heap  */
//                                                            call_mprotect(program_vars, mp_address, aligned_region, func4_size, (PROT_READ | PROT_WRITE));
//                                                        }
//                                                    }
//                                                    free(cleaning_buffer);
//                                                }
//                                call_function_ref(program_vars, address_to_region, argv[4]);
                                            }
                                        }
                                        free(func4_buffer);
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                fprintf(stderr, "Function not found.");

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
