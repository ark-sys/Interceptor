
#include "interceptor.h"
// include endiannes conversion -> htonl, used in PTRACE_PEEKTEXT
#include <netinet/in.h>

/*
 *
 * This file will only contain the function that sets a breakpoint accordingly to challenge 1
 *
 * */
ErrorCode setBreakpoint(const pid_t tracedProgramId, const unsigned long addressPosition){
    ErrorCode errorCode = NO_ERROR;
    unsigned long data;
    int waitStatus;
    char pathToMem[128];
    FILE * memFileFd;


    /* Prepare path to memory file and open it with some error checking */
    snprintf(pathToMem, 128, "/proc/%d/mem", tracedProgramId);
    memFileFd = fopen(pathToMem, "r+");
    if(memFileFd == NULL){
        errorCode = NULL_POINTER;
        perror("Failed to open mem file.");
    } else {
        /* Get file position at offset "addressPosition", so we can write at the first instruction of the traced function */
        if (fseek(memFileFd, (long)addressPosition, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Read data at address position before we set the breakpoint. This should have the same result as 'objdump -d' at the 'addressPosition' section. */
            data = ptrace(PTRACE_PEEKTEXT, tracedProgramId, (void *) addressPosition, 0);
            fprintf(stdout, "Setting breakpoint at 0x%08lX. Data is 0x%08X\n", addressPosition, htonl((uint32_t) data));
            /* Write the trap instruction at the beginning of the trace function */
            if(fwrite(&trap_instruction, 1, 1, memFileFd) == 0){
                errorCode = ERROR;
                perror("Failed to write trap.");
            }
        }

        /* If everything went fine, close the file to apply changes */
        fclose(memFileFd);

        /* Check that no error has been made in the previous part */
        if(errorCode == NO_ERROR){

            /* Restart the process and wait that it continues */
            if(ptrace(PTRACE_CONT, tracedProgramId, NULL, NULL) < 0){
                perror("Failed to resume execution of program.");
                errorCode = ERROR;
            } else {

                /* Check that the process actually changed its state */
                if(tracedProgramId != waitpid(tracedProgramId, &waitStatus, WCONTINUED)){
                    perror("Error waitpid.");
                    errorCode = ERROR;
                } else {
                    fprintf(stdout, "bp: PID <%d> got signal: %s\n\n", tracedProgramId, strsignal(WSTOPSIG(waitStatus)));

                } // End of waitpid section


            } // End of PTRACE_CONT section

        } // End of check on errorCode

    }// End of if on memFileFd

    return errorCode;
}

/*
 *
 * This file will only contain the function that sets a breakpoint accordingly to challenge 1
 *
 * */
ErrorCode bpLight(const pid_t tracedProgramId, const unsigned long addressPosition){
    ErrorCode errorCode = NO_ERROR;
    unsigned long data;
    char pathToMem[128];
    FILE * memFileFd;


    /* Prepare path to memory file and open it with some error checking */
    snprintf(pathToMem, 128, "/proc/%d/mem", tracedProgramId);
    memFileFd = fopen(pathToMem, "r+");
    if(memFileFd == NULL){
        errorCode = NULL_POINTER;
        perror("Failed to open mem file.");
    } else {
        /* Get file position at offset "addressPosition", so we can write at the first instruction of the traced function */
        if (fseek(memFileFd, (long)addressPosition, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Read data at address position before we set the breakpoint. This should have the same result as 'objdump -d' at the 'addressPosition' section. */
            data = (unsigned int) ptrace(PTRACE_PEEKTEXT, tracedProgramId, (void *) addressPosition, 0);
            fprintf(stdout, "Setting breakpoint at 0x%08lX. Data is 0x%08X\n", addressPosition, htonl((uint32_t) data));
            /* Write the trap instruction at the beginning of the trace function */
            if(fwrite(&trap_instruction, 1, 1, memFileFd) == 0){
                errorCode = ERROR;
                perror("Failed to write trap.");
            }
        }

        /* If everything went fine, close the file to apply changes */
        fclose(memFileFd);

    }// End of if on memFileFd

    return errorCode;
}

/*
 *
 * This file will only contain the function that sets a breakpoint accordingly to challenge 1
 *
 * */
ErrorCode bp_first_regs(const pid_t tracedProgramId, const unsigned long addressPosition){
    ErrorCode errorCode = NO_ERROR;
    int waitStatus;
    char pathToMem[128];
    FILE * memFileFd;
    struct user_regs_struct registers;
    char instr_buckup[4];


    /* Prepare path to memory file and open it with some error checking */
    snprintf(pathToMem, 128, "/proc/%d/mem", tracedProgramId);
    memFileFd = fopen(pathToMem, "r+");
    if(memFileFd == NULL){
        perror("Failed to open mem file.");
        errorCode = NULL_POINTER;
    } else {
        /* Get file position at offset "addressPosition", so we can write at the first instruction of the traced function */
        if (fseek(memFileFd, (long)addressPosition, SEEK_SET) != 0){
            perror("Failed to get offset.");
            errorCode = ERROR;
        } else {

            /* Read data at address position before we set the breakpoint. This should have the same result as 'objdump -d' at the 'addressPosition' section. */
            if(fread(instr_buckup, 4,1,memFileFd) == 0){
                perror("Failed reading instructions.");
            }else{
                /* Get file position at offset "addressPosition", so we can write at the first instruction of the traced function */
                if (fseek(memFileFd, (long)addressPosition, SEEK_SET) != 0){
                    perror("Failed to get offset.");
                    errorCode = ERROR;
                }else{
                    fprintf(stdout, "Setting breakpoint at 0x%08lX. Data is 0x%08X\n", addressPosition, instr_buckup);
                    /* Write the trap instruction at the beginning of the trace function */
                    if(fwrite(&trap_instruction, 1, 1, memFileFd) == 0){
                        errorCode = ERROR;
                        perror("Failed to write trap.");
                    }
                }
            }

        }

        /* If everything went fine, close the file to apply changes */
        fclose(memFileFd);

        /* Check that no error has been made in the previous part */
        if(errorCode == NO_ERROR){

            /* Restart the process and wait that it continues */
            if(ptrace(PTRACE_CONT, tracedProgramId, NULL, NULL) < 0){
                perror("Failed to resume execution of program.");
                errorCode = ERROR;
            } else {

                /* Check that the process actually changed its state */
                if(tracedProgramId != waitpid(tracedProgramId, &waitStatus, WCONTINUED)){
                    perror("Error waitpid.");
                    errorCode = ERROR;
                } else {
                    fprintf(stdout, "bp: PID <%d> got signal: %s\n\n", tracedProgramId, strsignal(WSTOPSIG(waitStatus)));

                    errorCode = dump_registers(tracedProgramId);
                    if (errorCode != NO_ERROR ){
                        fprintf(stderr, "%s\n","Failed to dump registers.");
                    }
                    errorCode = write_data(tracedProgramId, addressPosition, 4, instr_buckup);
                    if (errorCode != NO_ERROR ){
                        fprintf(stderr, "%s\n","Failed to recover backup.");
                    }
                } // End of waitpid section


            } // End of PTRACE_CONT section

        } // End of check on errorCode

    }// End of if on memFileFd

    return errorCode;
}
