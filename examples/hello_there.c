#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>

/* Prototypes declaration */
int func1(int i);

int func2(int i);

int func3(int *i);
/*static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}*/

int func1(int i) {
    i = i + 1;
    return i;
}

int func2(int i) {
    return i;
}

int func3(int * i){
    return *i;
}


int main(void) {
    int i = 0;
//    void * pointer;
//    int ret = posix_memalign(&pointer,getpagesize(),16);
//    if (ret!=0){
//        perror("pma");
//    }
//    ret = mprotect(pointer, 16, (PROT_EXEC | PROT_READ | PROT_WRITE));
//    if (ret!=0){
//        perror("mp");
//    }

    while (1) {
        i = func1(i);
        printf("%d\n", i);
        sleep(1);
    }

    printf("ya.\n");

    return 0;
}
