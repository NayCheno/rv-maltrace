#include <fcntl.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  static const char path[] = "/tmp/rvmt_trace_validation_input.txt";
  static const char seed[] = "rv-maltrace file validation\n";
  char buffer[128];

  long fd = syscall(SYS_openat, AT_FDCWD, path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
  if (fd < 0) {
    return 2;
  }
  long seeded = syscall(SYS_write, (int)fd, seed, sizeof(seed) - 1);
  syscall(SYS_close, (int)fd);
  if (seeded != (long)(sizeof(seed) - 1)) {
    return 3;
  }

  fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) {
    return 4;
  }
  long count = syscall(SYS_read, (int)fd, buffer, sizeof(buffer));
  if (count <= 0) {
    syscall(SYS_close, (int)fd);
    return 5;
  }
  syscall(SYS_write, STDOUT_FILENO, buffer, (size_t)count);
  syscall(SYS_close, (int)fd);
  return 0;
}
