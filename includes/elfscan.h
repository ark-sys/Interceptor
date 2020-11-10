#ifndef ELFSCAN_H
#define ELFSCAN_H

#include "common.h"
#include "errorcodes.h"

/* Function prototypes */
ErrorCode check_elf_type(const char * program_name, int *result);

#endif //ELFSCAN_H
