#include "common.h"

/*
 * In this file you can find helper functions that are used in the main program
 * such as functions that will help us by printing some info on screen
 * or functions that will help us make backups of the current register state
 *
 *
 * */


void print_usage(void){
    fprintf(stderr, "%s\n", "Usage : ./interceptor [program_name] [function_name] [function_to_call] [param_for_function_to_call]");
}


/*
 * This function will print current state of memory starting from the argument 'start_address' and will be showing 'nb_bytes'
 *
 * */
void dump_memory(pid_t traced_program_id, unsigned long start_address, unsigned long nb_bytes){
    unsigned data;
    fprintf(stdout, "===== MEMORY DUMP =====\n");
    for(int i = 0; i < (int)nb_bytes; i = i+4){
        data = ptrace(PTRACE_PEEKTEXT, traced_program_id, (void *)(start_address+i), 0);
        fprintf(stdout, "0x%08lX : 0x%08X\n", (start_address+i), htonl(data));
    }


    fprintf(stdout,   "=======================\n\n");

}

ErrorCode dump_registers(pid_t traced_program_id){
    ErrorCode errorCode = NO_ERROR;
    struct user_regs_struct current_registers;

    if(ptrace(PTRACE_GETREGS, traced_program_id, NULL, &current_registers) < 0)
    {
        fprintf(stderr, "%s\n", "Failed to get current registers.");
        errorCode = ERROR;
    } else {
        fprintf(stdout, "==== REGISTERS  DUMP ====\n");
        fprintf(stdout, "RBP at 0x%016llX\nRSP at 0x%016llX\nRIP at 0x%016llX\nRAX at 0x%016llX\nRDI at 0x%016llX\nRSI at 0x%016llX\nRDX at 0x%016llX\n", current_registers.rbp, current_registers.rsp, current_registers.rip, current_registers.rax, current_registers.rdi, current_registers.rsi, current_registers.rdx);
        fprintf(stdout,   "=========================\n\n");
    }

    return errorCode;
}

ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, char * output_buffer){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", traced_program_id);
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
                perror("Failed to read data.");
                errorCode = ERROR;
            }
        }
        fclose(mem_file_fd);
    }
    return errorCode;
}

ErrorCode write_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, const char * input_buffer){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", traced_program_id);
    if (NULL == (mem_file_fd = fopen(path_to_mem, "r+"))){
        errorCode = NULL_POINTER;
        perror("Failed to open memory file.");
    } else {

        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {

            /* Just a print message to see what we are writing */
            fprintf(stdout, "\nWriting ");
            for(int i = 0; i < (int)data_length; i++){

                fprintf(stdout, "0x%X ", (input_buffer[i] & 0xFF));
            }
            fprintf(stdout, "at address 0x%08lX\n" ,address_position);

            /* Write data from buffer to memory */
            if(fwrite(input_buffer, sizeof(char), data_length, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write data.");
            } else {
                fclose(mem_file_fd);

                fprintf(stdout,"%s\n", "Memory state after writing.");
                dump_memory(traced_program_id,address_position, data_length*2);
            }
        }
    }
    return errorCode;
}

ErrorCode write_values(const pid_t traced_program_id, unsigned long address_position, size_t data_length, const char *  input_buffer){
    ErrorCode errorCode = NO_ERROR;

    int tmp = atoi(input_buffer);

    char path_to_mem[64];
    FILE * mem_file_fd;
    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", traced_program_id);
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
                dump_memory(traced_program_id, address_position, data_length * 2);
            }

            fclose(mem_file_fd);

        }

    }

    return errorCode;
}

/*
 * Check if the new region created by posix_memalign has been correctly created in heap
 * The new region should be inside heap boundaries and with 'rw-p' flags
 *
 * */
ErrorCode is_region_available(const pid_t traced_program_id, const unsigned long long region_address ){
    ErrorCode errorCode = NO_ERROR;

    char path_to_mem[POS_SIZE];
    FILE * program_maps_fd;

    /* Create the command that will get us the position of the beginning of the main during runtime */
    snprintf(path_to_mem, POS_SIZE, "grep -E \'rw-p.*heap\' /proc/%d/maps | cut -d \" \" -f1", traced_program_id);

    /* Open the file and do some error checking */
    if(NULL == (program_maps_fd = popen(path_to_mem, "r")) ){
        perror("Failed to open maps for PID %s");
        errorCode = NULL_POINTER;
    } else {

        char readline[LINE_SIZE];
        /* Recover the line that contains heap addresses and rw-p flags  */
        if(fgets(readline, LINE_SIZE, program_maps_fd) == NULL )
        {
            perror("Heap region has not been found.");
            errorCode = NULL_POINTER;
        } else {
            /* Values in which heap boundaries (l_addr-h_addr in maps file) will be stored */
            unsigned long long low_boundary;
            unsigned long long high_boundary;

            if (sscanf(readline, "%llX-%llX", &low_boundary, &high_boundary) != 2){
                perror("Failed to read boundaries for heap.");
                errorCode = ERROR;
            } else {

                fprintf(stdout, "\nNew region created at 0x%016llX\n", region_address);
                /* Check if argument address is actually in heap region */
                if((region_address >= low_boundary) & (region_address < high_boundary)){
                    fprintf(stdout, "Allocated memory has been located in heap region. Heap boundaries are %llX-%llX\n", low_boundary, high_boundary);
                } else {
                    /* If we are here, than it meas that 'address_region' is not in heap, so posix_memalign failed*/
                    errorCode = ERROR;
                    fprintf(stderr, "%s\n", "The newly created region is not in heap.");
                }

            }

        }
        pclose(program_maps_fd);
    }

    return errorCode;
}
