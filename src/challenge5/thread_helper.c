#include "thread_helper.h"

ErrorCode getthreadlist(const pid_t traced_program_id, long *thread_list, int *number_of_threads) {
    ErrorCode errorCode = NO_ERROR;

    DIR *dir;
    struct dirent *ent;
    int count = 0;

    char path_to_task[LINE_SIZE];
    char current_pid[POS_SIZE];

    /* Convert current pid to char for later if condition*/
    snprintf(current_pid, POS_SIZE, "%d", traced_program_id);
    /* Prepare path to folder that contains subfolder for each thread of a proccess*/
    snprintf(path_to_task, LINE_SIZE, "/proc/%d/task/", traced_program_id);


    /* Open dir with some error checking */
    if ((dir = opendir(path_to_task)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            /* Exclude files that contain these characters*/
            if (strcmp(ent->d_name, ".") == 0) { continue; }
            if (strcmp(ent->d_name, "..") == 0) { continue; }
            if (strcmp(ent->d_name, current_pid) == 0) { continue; }
            /* Convert the name of each folder in integer -> that corresponds to the thead id that we are looking for */
            thread_list[count] = strtol(ent->d_name, NULL, 10);
            if (thread_list[count] == 0) {
                errorCode = ERROR;
                fprintf(stderr, "%s\n", "Failed conversion of TID from char* to int");
            }
            fprintf(stdout, "Thread n%d  %s\n", count, ent->d_name);

            count++;
        }
        closedir(dir);

        *number_of_threads = count;

    } else {
        /* could not open directory */
        errorCode = NULL_POINTER;

    }


    return errorCode;

}
