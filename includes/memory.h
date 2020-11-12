#ifndef INTERCEPTOR_MEMORY_H
#define INTERCEPTOR_MEMORY_H

#include "common.h"

/* Function prototypes */
ErrorCode read_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, char * output_buffer);
ErrorCode write_data(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, const char * input_buffer);
ErrorCode write_values(const pid_t traced_program_id, const unsigned long address_position, size_t data_length, const char *  input_buffer);
#endif //MEMORY_H
