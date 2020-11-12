#include "../includes/memory.h"

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
                errorCode = ERROR;
                perror("Failed to read data.");
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
