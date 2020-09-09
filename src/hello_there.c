#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define N_ITERATIONS 100

static const char * cool_message = "Hello there.\n";

static void func1(void){
    write(2, cool_message, strlen(cool_message));
}

int main(void) {
  for(int i = 0; i < N_ITERATIONS; i++){
    func1();
    sleep(1);
  }
  return 0;
}
