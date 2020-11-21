#include "interceptor.h"

/* Structure needed to store variables used in different sections of the program */
static struct program_vars_t program_vars;
int func4 (int i){
    i = 0;
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
        fprintf(stdout, "\nFunction size: %lu bytes.\n", program_vars.traced_function_size);
    }

    unsigned long long addr_func_to_call;
    errCode = get_function_offset(program_vars.traced_program_name, argv[3], &addr_func_to_call);
    if (errCode != NO_ERROR){
        fprintf(stderr, "%s\n","Failed to get address for func2.");
        return errCode;
    } else {
        addr_func_to_call = addr_func_to_call + program_vars.program_start_address;
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
            dump_memory(program_vars.traced_program_id,program_vars.traced_function_address, program_vars.traced_function_size);
            dump_registers(program_vars.traced_program_id);

//#todo sanity check and conversion on value here before we pass it to functions

//            if (strcmp("func2", argv[3]) == 0) {
//                errCode = call_function_val(program_vars, addr_func_to_call, argv[4]);
//                if (errCode != NO_ERROR) {
//                    fprintf(stderr, "%s\n", "Failed to call func2.");
//                }
//            } else if (strcmp("func3", argv[3]) == 0) {
//                errCode = call_function_ref(program_vars, addr_func_to_call, argv[4]);
//                if (errCode != NO_ERROR) {
//                    fprintf(stderr, "%s\n", "Failed to call func2.");
//                }
//            } else {
//
//                fprintf(stderr, "Function not found at line %d.", __LINE__);
//            }

        }
    }

    unsigned long long func4_address;
    /* Look for the address of the target function in the binary dump */
    errCode = get_function_offset(argv[0],"func4", &func4_address);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\nFunction to inject <%s> at address: 0x%08llX\n", "func4",func4_address );
    }
    unsigned long func4_size;
    /* Retrieve the size of the function in memory  */
    errCode = get_function_size(argv[0], func4_address, &func4_size);
    if (errCode != NO_ERROR) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(errCode));
        return errCode;
    } else {
        fprintf(stdout, "\nFunction size: %lu bytes.\n", func4_size);
    }

    unsigned long long pma_address;
    unsigned long long address_to_region = 0;
    errCode = get_libc_function_address(program_vars.traced_program_id, "posix_memalign", &pma_address);
    if(errCode != NO_ERROR){
        fprintf(stderr, "%s: %s\n","Failed to get posix_memalign address.", ErrorCodetoString(errCode));
    }else{
        fprintf(stdout,"posix_memalign located at 0x%016llX\n", pma_address);
        errCode = call_posix_memalign(program_vars, pma_address, func4_size, &address_to_region);
        if (errCode != NO_ERROR){
            fprintf(stderr, "%s: %s\n", "Failed to call posix memalign.", ErrorCodetoString(errCode));
        }
    }


    unsigned long long mp_address;
    errCode = get_libc_function_address(program_vars.traced_program_id, "mprotect", &mp_address);
    if(errCode != NO_ERROR){
        fprintf(stderr, "%s: %s\n","Failed to get posix_memalign address.", ErrorCodetoString(errCode));
    }else{
        fprintf(stdout,"mprotect located at 0x%016llX\n", mp_address);
        errCode = call_mprotect(program_vars, mp_address, address_to_region, func4_size, (PROT_READ | PROT_WRITE | PROT_EXEC));
        if (errCode != NO_ERROR){
            fprintf(stderr, "%s: %s\n", "Failed to call posix memalign.", ErrorCodetoString(errCode));
        }
    }


    char * func4_buffer = malloc(sizeof(char)* func4_size);
    struct user_regs_struct backupregs;
//    get_registers_backup(program_vars.traced_program_id, &backupregs);
//    set_breakpoint(program_vars.traced_program_id,program_vars.traced_function_address);
    read_data(getpid(),func4_address, func4_size, func4_buffer);
    write_data(program_vars.traced_program_id, address_to_region, func4_size, func4_buffer);
//    backupregs.rip = program_vars.traced_function_address;
//    set_registers_backup(program_vars.traced_program_id, &backupregs);

//    call_function_ref(program_vars, address_to_region, argv[4]);
      call_function_val(program_vars, address_to_region, argv[4]);
//    call_mprotect(program_vars, mp_address, address_to_region, 32, (PROT_READ | PROT_WRITE ));
    free(func4_buffer);
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
