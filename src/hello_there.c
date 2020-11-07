#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

/* Prototypes declaration */
int func1(int i);

int func2(int i);

int func3(int *i);

/*static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}*/

static int exit_value = 0;

static void sig_handler(int _) {
    exit_value = 1;
}

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
    signal(SIGINT, sig_handler);

    while (!exit_value) {
        i = func1(i);
        printf("%d\n", i);
        sleep(1);
    }

    printf("ya.\n");

    return 0;
}
