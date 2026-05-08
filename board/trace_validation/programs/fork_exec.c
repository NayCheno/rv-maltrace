#define _GNU_SOURCE

#include <signal.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(void) {
  long child = syscall(SYS_clone, SIGCHLD, 0, NULL, NULL, 0);
  if (child == 0) {
    char *argv[] = {"/bin/true", NULL};
    syscall(SYS_execve, argv[0], argv, environ);
    _exit(127);
  }
  if (child < 0) {
    return 2;
  }

  int status = 0;
  long waited = syscall(SYS_wait4, child, &status, 0, NULL);
  return waited == child && WIFEXITED(status) ? 0 : 3;
}
