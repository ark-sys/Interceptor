#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

/* Prototypes declaration */
int func1(int i);

int func2(int i);

int func3(int *i);


int func1(int i) {
    i = i + 1;
    return i;
}

int func2(int i) {
    return i;
}

int func3(int *i){
    return *i;
}

int main(void) {
    int i = 0;
//    void * pointer;
//    int ret = posix_memalign(&pointer,getpagesize(),19);
//    if (ret!=0){
//        perror("pma");
//    }
//    ret = mprotect(pointer, 19, (PROT_EXEC | PROT_READ | PROT_WRITE));
//    if (ret!=0){
//        perror("mp");
//    }

    while (1) {
        printf("%d\n", (i=func1(i)));
        sleep(1);
    }

    printf("ya.\n");
    return 0;
}
