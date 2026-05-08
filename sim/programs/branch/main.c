#include "../common/tohost.h"

int main(void) {
  volatile int x = 1;
  volatile int y = 0;
  if (x == 1) {
    y = 10;
  } else {
    y = 20;
  }
  rvmt_finish(y == 10 ? 1 : 2);
  return 0;
}
