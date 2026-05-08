#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  static const char message[] = "rv-maltrace hello\n";
  long wrote = syscall(SYS_write, STDOUT_FILENO, message, sizeof(message) - 1);
  return wrote == (long)(sizeof(message) - 1) ? 0 : 1;
}
