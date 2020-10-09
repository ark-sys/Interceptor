#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}*/

static int func1(int i){
    printf("%d\n", i);
    return i;
}

static int func2(int * i){
    *i = 300000;
    return *i;
}

int main(void) {
    int i = 0;
    while(1){
    func1(i++);
    sleep(1);
  }

  return 0;
}
