#ifndef ERRORCODES_H
#define ERRORCODES_H

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



#endif //ERRORCODES_H
