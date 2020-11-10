#ifndef SEL_COMMON_H
#define SEL_COMMON_H

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
#include <libelf.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>


/* #todo when everything is good, check if all macros are used */
#define PID_SIZE 16
#define FUNCTION_SIZE 64
#define POS_SIZE 64
#define LINE_SIZE 128
#define COMMAND_SIZE 256
#define BUFFER_SIZE 4

#endif //COMMON_H
