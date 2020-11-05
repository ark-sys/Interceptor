#ifndef MYINCLUDE_H_
#define MYINCLUDE_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* #todo when everything is good, check if all macros are used */
#define PID_SIZE 16
#define FUNCTION_SIZE 64
#define POS_SIZE 64
#define LINE_SIZE 128
#define COMMAND_SIZE 256
#define BUFFER_SIZE 4

struct breakpoint_t{
    unsigned long address;
    unsigned char original_data;
};

struct program_vars_t{
  pid_t traced_program_id;
  char traced_program_name[POS_SIZE];

  char traced_function_name[FUNCTION_SIZE];
  int traced_function_size;
  unsigned long traced_function_address; /* main_address + function_offset*/

  unsigned long program_main_address;

  char instruction_backup[BUFFER_SIZE];
  struct user_regs_struct registers;
};

typedef enum _ErrorCode_t {
    NO_ERROR = 0,
    ERROR,
    NULL_POINTER,
    MALLOC_FAILED,
    FILE_NOT_FOUND,
    FUNCTION_NOT_FOUND,
    COMMAND_NOT_FOUND,
    INVALID_ARGUMENT,
    PROGRAM_NOT_RUNNING
} ErrorCode;

static inline const char * ErrorCodetoString(ErrorCode errCode)
{
  static const char *ErrorCodeString[] =
  {
    "No error",
    "Error",
    "Null pointer",
    "Malloc failed",
    "File not found",
    "Function not found",
    "Command not found",
    "Invalid argument",
    "Program not running"
  };
  return ErrorCodeString[errCode];
}

#endif
