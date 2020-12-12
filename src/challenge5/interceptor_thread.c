#include "thread_helper.h"

static struct program_vars_t program_vars;


int main(int argc, char **argv){

    printf("\e[1;1H\e[2J");
    if (argc != 3) {
        fprintf(stderr, "Error! line:%d:%s.\n", __LINE__, ErrorCodetoString(INVALID_ARGUMENT));
        return INVALID_ARGUMENT;
    }

    ErrorCode errCode = NO_ERROR;
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


    int wait_status;
    long thread_list[POS_SIZE];
    int number_of_threads;
    getthreadlist(program_vars.traced_program_id, thread_list, &number_of_threads);


    for (int i = 0; i < number_of_threads; i++) {
        /* Attach to all threads  */
        if(ptrace(PTRACE_ATTACH, thread_list[i], NULL, NULL) < 0){
            fprintf(stderr, "Error during PTRACE_ATTACH at line %d.\n", __LINE__);
        } else {
            /* Wait for all threads */
            if (thread_list[i] != waitpid((__pid_t) thread_list[i], &wait_status, 0)){
                fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
            }else{
                fprintf(stdout, "TID <%ld> got signal: %s\n", thread_list[i],
                        strsignal(WSTOPSIG(wait_status)));

            }


        }


    }
    bpLight(program_vars.traced_program_id, program_vars.traced_function_address + 24);


    for(int i = 0; i< number_of_threads; i++){
//        struct user_regs_struct registers;
//        ptrace(PTRACE_GETREGS, thread_list[i], NULL, &registers);
//        registers.rip  = program_vars.traced_function_address;
//        ptrace(PTRACE_SETREGS, thread_list[i], NULL, &registers);
        ptrace(PTRACE_CONT, thread_list[i], NULL, NULL);

        /* Wait for all threads with __WALL */
        if (thread_list[i] != waitpid((__pid_t) thread_list[i], &wait_status, WCONTINUED)){
            fprintf(stderr, "Error waitpid at line %d\n", __LINE__);
        }else{
            fprintf(stdout, "TID <%ld> got signal: %s\n", thread_list[i],
                    strsignal(WSTOPSIG(wait_status)));

        }
    }


    while (1);
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
