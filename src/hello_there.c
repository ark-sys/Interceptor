#include <stdio.h>
#include <unistd.h>

/* Prototypes declaration */
int func1(int i);
int func2(int * i);
/*static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}*/

int func1(int i){
    i = i+1;
    printf("%d\n", i);
    return i;
}

int func2(int * i){
    *i = *i * 420;
    return *i;
}

int main(void) {
    int i = 0;
    while(1){
        i = func1(i);
        sleep(1);
    }

  return 0;
}
