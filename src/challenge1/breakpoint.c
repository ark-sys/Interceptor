#include "interceptor.h"

/*
 *
 * This file will only contain the function that sets a breakpoint accordingly to challenge 1
 *
 * */
ErrorCode set_breakpoint(const pid_t traced_program_id, const unsigned long address_position){
    ErrorCode errorCode = NO_ERROR;
    unsigned data;
    int wait_status;
    char path_to_mem[128];
    FILE * mem_file_fd;


    /* Prepare path to memory file and open it with some error checking */
    snprintf(path_to_mem, 128, "/proc/%d/mem", traced_program_id);
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
            data = ptrace(PTRACE_PEEKTEXT, traced_program_id, (void *)address_position,0);
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
            if(ptrace(PTRACE_CONT, traced_program_id, NULL, NULL) < 0){
                perror("Failed to resume execution of program.");
                errorCode = ERROR;
            } else {

                /* Check that the process actually changed its state */
                if(traced_program_id != waitpid(traced_program_id, &wait_status, WCONTINUED)){
                    perror("Error waitpid.");
                    errorCode = ERROR;
                } else {
                    fprintf(stdout, "bp: PID <%d> got signal: %s\n\n", traced_program_id, strsignal(WSTOPSIG(wait_status)));

                } // End of waitpid section


            } // End of PTRACE_CONT section

        } // End of check on errorCode

    }// End of if on mem_file_fd

    return errorCode;
}

/*
 *
 * This file will only contain the function that sets a breakpoint accordingly to challenge 1
 *
 * */
ErrorCode bp_light(const pid_t traced_program_id, const unsigned long address_position){
    ErrorCode errorCode = NO_ERROR;
    unsigned data;
    char path_to_mem[128];
    FILE * mem_file_fd;


    /* Prepare path to memory file and open it with some error checking */
    snprintf(path_to_mem, 128, "/proc/%d/mem", traced_program_id);
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
            data = ptrace(PTRACE_PEEKTEXT, traced_program_id, (void *)address_position,0);
            fprintf(stdout,"Setting breakpoint at 0x%08lX. Data is 0x%08X\n", address_position, htonl(data));
            /* Write the trap instruction at the beginning of the trace function */
            if(fwrite(&trap_instruction, 1,1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write trap.");
            }
        }

        /* If everything went fine, close the file to apply changes */
        fclose(mem_file_fd);

    }// End of if on mem_file_fd

    return errorCode;
}