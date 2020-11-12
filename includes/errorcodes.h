#ifndef INTERCEPTOR_ERRORCODES_H
#define INTERCEPTOR_ERRORCODES_H

typedef enum _ErrorCode_t {
    NO_ERROR = 0,
    ERROR,
    NULL_POINTER,
    FILE_NOT_FOUND,
    FUNCTION_NOT_FOUND,
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
                    "File not found",
                    "Function not found",
                    "Invalid argument",
                    "Program not running"
            };
    return ErrorCodeString[errCode];
}

#endif //ERRORCODES_H
