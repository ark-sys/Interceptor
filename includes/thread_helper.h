//
// Created by Khaled on 25/11/2020.
//

#ifndef INTERCEPTOR_THREAD_HELPER_H
#define INTERCEPTOR_THREAD_HELPER_H
#include <dirent.h>
#include "interceptor.h"

ErrorCode getthreadlist(const pid_t traced_program_id, long * thread_list, int * number_of_threads);
ErrorCode stopthreads(struct program_vars_t program_vars);

#endif //INTERCEPTOR_THREAD_HELPER_H
