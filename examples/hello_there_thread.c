#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>

#define NUMBER_OF_THREADS 10

/* Prototypes declaration */
void * increment(void * argv);
void * print_value(void * argv);


int globalint = 0;
pthread_t increment_thread[NUMBER_OF_THREADS];
pthread_t print_thread;

int reader=0;
int writer=1;
pthread_mutex_t increment_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t read_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t write_cond = PTHREAD_COND_INITIALIZER;

void * increment(void *argv){
    (void)argv;
    int * n_thread = (int*) argv;
    while (1){
        assert(pthread_mutex_lock(&increment_lock) == 0);
        while(!writer) { pthread_cond_wait(&write_cond, &increment_lock); }
        printf("Thread %d : incrementing\n", *n_thread);
        globalint++;


        reader++;
        writer--;
        pthread_cond_signal(&read_cond);
        assert(pthread_mutex_unlock(&increment_lock) == 0);
    }
    pthread_exit(NULL);
}

void * print_value(void *argv){
    (void)argv;

    while (1){
        assert(pthread_mutex_lock(&increment_lock) == 0);
        while(!reader) { pthread_cond_wait(&read_cond, &increment_lock); }
        printf("%d\n", globalint);
        reader--;
        writer++;
        pthread_cond_signal(&write_cond);
        assert(pthread_mutex_unlock(&increment_lock) == 0);
    }
    pthread_exit(NULL);

}

int main(void) {

    for (int i = 0; i<NUMBER_OF_THREADS; i++){
        pthread_create(&increment_thread[i],NULL, increment, &i);
    }
    pthread_create(&print_thread,NULL, print_value, NULL);


    for (int i = 0; i<NUMBER_OF_THREADS; i++){
        pthread_join(increment_thread[i], NULL);
    }
    pthread_join(print_thread, NULL);

    pthread_mutex_destroy(&increment_lock);

    printf("ya.\n");
    return 0;
}