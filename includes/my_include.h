#ifndef MYINCLUDE_H_
#define MYINCLUDE_H_

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include <stdint.h>
#include <stdbool.h>

#define PID_SIZE 16
#define POS_SIZE 64

struct program_vars_t{
  pid_t traced_program_id;
  char * traced_pid_string;
  int traced_pid_string_s;

  char * traced_program_name;
  int program_name_s;
  unsigned long program_main_address;

  char * traced_function_name;
  int traced_function_s;
  unsigned long function_address; // main_address + function_offset


};

typedef enum _ErrorCode_t {
    NO_ERROR = 0,
    ERROR,
    NULL_POINTER,
    MALLOC_FAILED,
    FILE_NOT_FOUND,
    FUNCTION_NOT_FOUND,
    COMMAND_NOT_FOUND,
    INVALID_ARGUMENT
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
    "Invalid argument"
  };
  return ErrorCodeString[errCode];
}











#endif
