#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define N_ITERATIONS 100

static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(1, cool_message, 13);
}

static void func2(int i){
    printf("%d\n", i);
}


int main(void) {
  for(int i = 0; i < N_ITERATIONS; i++){
    func2(i);
    sleep(1);
  }

  return 0;
}
