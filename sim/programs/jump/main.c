#include "../common/tohost.h"

static void foo(volatile int *value) {
  *value = 7;
}

int main(void) {
  volatile int value = 0;
  foo(&value);
  rvmt_finish(value == 7 ? 1 : 2);
  return 0;
}
