#include "../common/tohost.h"

int main(void) {
  volatile int x = 1;
  volatile int y = 2;
  volatile int z = x + y;
  rvmt_finish(z == 3 ? 1 : 2);
  return 0;
}
