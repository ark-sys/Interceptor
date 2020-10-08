#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}*/

static void func1(int i){
    printf("%d\n", i);
}

static void func2(int * i){
    printf("%d\n", *i);
}

int main(void) {
    int i = 0;
    while(1){
    func1(i++);
    sleep(1);
  }

  return 0;
}
