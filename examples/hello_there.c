#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/* Prototypes declaration */
int func1(int i);

int func2(int i);

int func3(int *i);


int func1(int i) {
    i = i + 1;
    return i;
}

int func2(int i) {
    i = i + 3;
    return i;
}

int func3(int *i){
    *i = *i + 5;
    return *i;
}

int main(void) {
    int i = 0;
    while (1) {
        printf("%d\n", (i=func1(i)));
        sleep(1);
    }

    printf("ya.\n");
    return 0;
}
