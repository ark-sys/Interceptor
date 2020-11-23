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
    unsigned char * output_buffer = malloc(sizeof(unsigned char) * nb_bytes);
    fprintf(stdout, "===== MEMORY DUMP =====\n");
    read_data(traced_program_id,start_address, nb_bytes,output_buffer);
    for(int i = 0; i < (int)nb_bytes; i = i+4){
        fprintf(stdout, "0x%08lX : 0x%02X 0x%02X 0x%02X 0x%02X\n", (start_address+i), (unsigned char)output_buffer[i], (unsigned char)output_buffer[i+1], (unsigned char)output_buffer[i+2], (unsigned char)output_buffer[i+3]);
    }
    fprintf(stdout,   "=======================\n\n");
    free(output_buffer);
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

ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, const size_t data_length, unsigned char * output_buffer){
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
            if(fread(output_buffer, sizeof(unsigned char)*data_length,1, mem_file_fd) == 0){
                perror("Failed to read data.");
                errorCode = ERROR;
            }
        }
        fclose(mem_file_fd);
    }
    return errorCode;
}

//#todo fix write buffer
ErrorCode write_data(const pid_t traced_program_id, unsigned long address_position, const size_t data_length, const unsigned char *input_buffer){
    ErrorCode errorCode = NO_ERROR;
    char path_to_mem[64];
    FILE * mem_file_fd;

    /* Prepare path to memory file */
    snprintf(path_to_mem, 64, "/proc/%d/mem", traced_program_id);
    if (NULL == (mem_file_fd = fopen(path_to_mem, "wb"))){
        errorCode = NULL_POINTER;
        perror("Failed to open memory file.");
    } else {

        if (fseek(mem_file_fd, (long)address_position, SEEK_SET) != 0){
            errorCode = ERROR;
            perror("Failed to get offset.");
        } else {
            /* Just a print message to see what we are writing */
            fprintf(stdout,"%s", "Writing ");
            for(int i = 0; i < (int)data_length; i++){
                fprintf(stdout,"0x%02X ",(unsigned char)input_buffer[i]);
            }
            fprintf(stdout, "at address 0x%08lX.\n", address_position);
            if(fwrite(input_buffer, data_length*sizeof(char),1, mem_file_fd) == 0){
                errorCode = ERROR;
                perror("Failed to write data.");
            }
            fclose(mem_file_fd);

            fprintf(stdout, "%s\n", "Memory state after writing.");
            dump_memory(traced_program_id, address_position, data_length * 2);
        }

    }

    return errorCode;
}

/*
 * Convert unsigned long value to byte array rapresentation like {0xCC...}
 * We do so to make sure we are writing the correct data in memmory
 * Endianness is also respected
 * */
void ul_to_bytarray(unsigned long address, unsigned char *output){
    output[0] = (unsigned char)((address) & 0xFF);
    output[1] = (unsigned char)((address >> 8) & 0xFF);
    output[2] = (unsigned char)((address >> 16) & 0xFF);
    output[3] = (unsigned char)((address >> 24) & 0xFF);
    fprintf(stdout,"Converted %lu to 0x%02X 0x%02X 0x%02X 0x%02X\n", address, output[0], output[1], output[2], output[3]);
}

void ull_to_bytarray(unsigned long long address, unsigned char *output){

    output[0] = (unsigned char)((address) & 0xFF);
    output[1] = (unsigned char)((address >> 8) & 0xFF);
    output[2] = (unsigned char)((address >> 16) & 0xFF);
    output[3] = (unsigned char)((address >> 24) & 0xFF);
    output[4] = (unsigned char)((address >> 32) & 0xFF);
    output[5] = (unsigned char)((address >> 40) & 0xFF);
    output[6] = (unsigned char)((address >> 48) & 0xFF);
    output[7] = (unsigned char)((address >> 56) & 0xFF);
    fprintf(stdout,"Converted %llu to 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X\n", address, output[0], output[1], output[2], output[3], output[4], output[5], output[6], output[7]);
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
                if((region_address >= low_boundary) && (region_address < high_boundary)){
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

/*
 * Check if the new region created by posix_memalign has been correctly created in heap
 * The new region should be inside heap boundaries and with 'rw-p' flags
 *
 * */
ErrorCode is_region_executable(const pid_t traced_program_id, const unsigned long long region_address){
    ErrorCode errorCode = NO_ERROR;

    char path_to_mem[POS_SIZE];
    FILE * program_maps_fd;

    /* Create the command that will get us the line containing executable heap addresses */
    snprintf(path_to_mem, POS_SIZE, "grep -E \'rwxp.*heap\' /proc/%d/maps | cut -d \" \" -f1", traced_program_id);

    /* Open the file and do some error checking */
    if(NULL == (program_maps_fd = popen(path_to_mem, "r")) ){
        perror("Failed to open maps for PID %s");
        errorCode = NULL_POINTER;
    } else {

        char readline[LINE_SIZE];
        /* Recover the line that contains heap addresses and rw-p flags  */
        if(fgets(readline, LINE_SIZE, program_maps_fd) == NULL )
        {
            perror("Executable heap region has not been found.");
            errorCode = NULL_POINTER;
        } else {
            /* Values in which heap boundaries (l_addr-h_addr in maps file) will be stored */
            unsigned long long low_boundary;
            unsigned long long high_boundary;

            if (sscanf(readline, "%llX-%llX", &low_boundary, &high_boundary) != 2){
                perror("Failed to read boundaries for heap.");
                errorCode = ERROR;
            } else {

                /* Check if argument address is actually in heap region */
                if((region_address >= low_boundary) && (region_address < high_boundary)){
                    fprintf(stdout, "Allocated memory has been located in heap region. Executable heap boundaries are %llX-%llX\n\n", low_boundary, high_boundary);
                } else {
                    /* If we are here, than it meas that 'address_region' is not in heap, so posix_memalign failed*/
                    errorCode = ERROR;
                    fprintf(stderr, "%s\n", "Executable region is not in heap.");
                }

            }

        }
        pclose(program_maps_fd);
    }

    return errorCode;
}