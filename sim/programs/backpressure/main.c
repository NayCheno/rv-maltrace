#include "../common/tohost.h"

int main(void) {
  volatile unsigned long acc = 0;
  for (unsigned long i = 0; i < 64; i++) {
    acc += i;
  }
  rvmt_finish(acc == 2016 ? 1 : 2);
  return 0;
}
