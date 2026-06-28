#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_bpf
#define SYS_bpf 280
#endif
#ifndef SYS_perf_event_open
#define SYS_perf_event_open 241
#endif
#ifndef SYS_gettid
#define SYS_gettid 178
#endif

#define RVMT_MARKER_SYSCALL 1023
#define RVMT_PID_MARKER_BASE 0xd0000000u
#define RVMT_PID_MARKER_VALUE_MASK 0x00ffffffu
#define RVMT_PID_MARKER_PARENT_PID 1u
#define RVMT_PID_MARKER_PARENT_TGID 2u
#define RVMT_PID_MARKER_CHILD_PID 3u
#define RVMT_PID_MARKER_CHILD_TGID 4u
#define RVMT_PID_MARKER_CHILD_PRE_EXEC_PID 5u
#define RVMT_PID_MARKER_CHILD_PRE_EXEC_TGID 6u

static sigjmp_buf g_sigill_jmp;

static void sigill_handler(int signo) {
  (void)signo;
  siglongjmp(g_sigill_jmp, 1);
}

static unsigned long parse_hex32(const char *text) {
  char *end = NULL;
  errno = 0;
  unsigned long value = strtoul(text, &end, 0);
  if (errno || end == text || value > 0xffffffffUL) {
    fprintf(stderr, "invalid marker value: %s\n", text);
    _exit(2);
  }
  return value;
}

static long rvmt_marker(uint32_t value) {
  return syscall(RVMT_MARKER_SYSCALL, (unsigned long)value, 0, 0, 0, 0, 0);
}

static uint32_t rvmt_pid_marker_value(unsigned int kind, long value) {
  return RVMT_PID_MARKER_BASE |
         ((kind & 0x0fu) << 24) |
         ((uint32_t)value & RVMT_PID_MARKER_VALUE_MASK);
}

static long rvmt_gettid(void) {
  return syscall(SYS_gettid);
}

static void rvmt_emit_pid_marker(const char *label, unsigned int kind, long value) {
  uint32_t marker = rvmt_pid_marker_value(kind, value);
  rvmt_marker(marker);
  printf("RVMT_PID_MARKER label=%s kind=%u value=%ld marker=0x%08x\n",
         label, kind, value, marker);
  fflush(stdout);
}

static void touch_file(const char *path, const char *fmt, ...) {
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    printf("RVMT_FILE_TOUCH_FAIL path=%s errno=%d\n", path, errno);
    fflush(stdout);
    return;
  }
  if (fmt != NULL) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) {
      write(fd, buf, (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf));
    }
  }
  close(fd);
}

static void wait_for_file(const char *path) {
  for (;;) {
    if (access(path, F_OK) == 0) {
      return;
    }
    usleep(100000);
  }
}

static uint64_t read_rdcycle(void) {
  uint64_t value;
  __asm__ volatile("rdcycle %0" : "=r"(value));
  return value;
}

static uint64_t read_rdinstret(void) {
  uint64_t value;
  __asm__ volatile("rdinstret %0" : "=r"(value));
  return value;
}

static uint64_t read_rdtime(void) {
  uint64_t value;
  __asm__ volatile("rdtime %0" : "=r"(value));
  return value;
}

static void probe_counter(const char *name, uint64_t (*reader)(void)) {
  struct sigaction old_action;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = sigill_handler;
  sigemptyset(&action.sa_mask);
  sigaction(SIGILL, &action, &old_action);
  if (sigsetjmp(g_sigill_jmp, 1) == 0) {
    uint64_t a = reader();
    uint64_t b = reader();
    printf("RVMT_CAP_PROBE name=%s status=AVAILABLE value0=%llu value1=%llu delta=%lld\n",
           name, (unsigned long long)a, (unsigned long long)b, (long long)(b - a));
  } else {
    printf("RVMT_CAP_PROBE name=%s status=SIGILL_COUNTER_GATED signal=SIGILL\n", name);
  }
  sigaction(SIGILL, &old_action, NULL);
}

static int mode_capability(void) {
  struct timespec ts;
  errno = 0;
  printf("RVMT_CAPABILITY_PROBE_BEGIN pid=%ld\n", (long)getpid());
  probe_counter("rdcycle", read_rdcycle);
  probe_counter("rdinstret", read_rdinstret);
  probe_counter("rdtime", read_rdtime);
  errno = 0;
  int rc = clock_gettime(CLOCK_MONOTONIC, &ts);
  printf("RVMT_CAP_PROBE name=clock_gettime_monotonic status=%s rc=%d errno=%d sec=%ld nsec=%ld\n",
         rc == 0 ? "AVAILABLE" : "OPERATION_NOT_SUPPORTED", rc, errno, (long)ts.tv_sec, (long)ts.tv_nsec);
  errno = 0;
  long perf_rc = syscall(SYS_perf_event_open, NULL, 0, -1, -1, 0);
  printf("RVMT_CAP_PROBE name=perf_event_open_null status=%s rc=%ld errno=%d\n",
         perf_rc < 0 && errno == ENOSYS ? "SYSCALL_ENOSYS" :
         perf_rc < 0 && errno == EPERM ? "PERMISSION_DENIED" :
         perf_rc < 0 ? "OPERATION_NOT_SUPPORTED" : "AVAILABLE",
         perf_rc, errno);
  errno = 0;
  long bpf_rc = syscall(SYS_bpf, 0, NULL, 0);
  printf("RVMT_CAP_PROBE name=bpf_null status=%s rc=%ld errno=%d\n",
         bpf_rc < 0 && errno == ENOSYS ? "SYSCALL_ENOSYS" :
         bpf_rc < 0 && errno == EPERM ? "PERMISSION_DENIED" :
         bpf_rc < 0 ? "OPERATION_NOT_SUPPORTED" : "AVAILABLE",
         bpf_rc, errno);
  errno = 0;
  long ptrace_rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  printf("RVMT_CAP_PROBE name=ptrace_traceme status=%s rc=%ld errno=%d\n",
         ptrace_rc == 0 ? "AVAILABLE" : (errno == EPERM ? "PERMISSION_DENIED" : "OPERATION_NOT_SUPPORTED"),
         ptrace_rc, errno);
  errno = 0;
  long prctl_rc = prctl(PR_GET_NAME, NULL, 0, 0, 0);
  printf("RVMT_CAP_PROBE name=prctl_get_name_badptr status=%s rc=%ld errno=%d\n",
         prctl_rc < 0 && errno == EFAULT ? "AVAILABLE" :
         prctl_rc < 0 && errno == ENOSYS ? "SYSCALL_ENOSYS" : "OPERATION_NOT_SUPPORTED",
         prctl_rc, errno);
  printf("RVMT_CAPABILITY_PROBE_DONE\n");
  fflush(stdout);
  return 0;
}

static int mode_workload(int argc, char **argv) {
  if (argc < 6) {
    fprintf(stderr, "usage: %s workload SAMPLE BEGIN END COMMAND [ARGS...]\n", argv[0]);
    return 2;
  }
  const char *sample = argv[2];
  uint32_t begin = (uint32_t)parse_hex32(argv[3]);
  uint32_t end = (uint32_t)parse_hex32(argv[4]);
  printf("RVMT_OFFICIAL_WORKLOAD_BEGIN sample=%s parent_pid=%ld command=%s\n", sample, (long)getpid(), argv[5]);
  fflush(stdout);
  rvmt_marker(begin);
  rvmt_emit_pid_marker("workload_parent_pid", RVMT_PID_MARKER_PARENT_PID, rvmt_gettid());
  rvmt_emit_pid_marker("workload_parent_tgid", RVMT_PID_MARKER_PARENT_TGID, (long)getpid());
  pid_t child = fork();
  if (child == 0) {
    rvmt_emit_pid_marker("workload_child_pid", RVMT_PID_MARKER_CHILD_PID, rvmt_gettid());
    rvmt_emit_pid_marker("workload_child_tgid", RVMT_PID_MARKER_CHILD_TGID, (long)getpid());
    execv(argv[5], &argv[5]);
    printf("RVMT_OFFICIAL_WORKLOAD_EXEC_FAIL sample=%s errno=%d\n", sample, errno);
    fflush(stdout);
    _exit(127);
  }
  int status = 0;
  pid_t waited = waitpid(child, &status, 0);
  rvmt_marker(end);
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  printf("RVMT_OFFICIAL_WORKLOAD_DONE sample=%s child_pid=%ld waited=%ld rc=%d raw_status=%d\n",
         sample, (long)child, (long)waited, exit_code, status);
  fflush(stdout);
  return exit_code;
}

static int mode_runtime_map(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: %s runtime-map BEGIN END LABEL\n", argv[0]);
    return 2;
  }
  uint32_t begin = (uint32_t)parse_hex32(argv[2]);
  uint32_t end = (uint32_t)parse_hex32(argv[3]);
  const char *label = argv[4];
  char ready[128];
  char cont[128];
  snprintf(ready, sizeof(ready), "/tmp/rvmt-map-ready-%ld", (long)getpid());
  snprintf(cont, sizeof(cont), "/tmp/rvmt-map-continue-%ld", (long)getpid());
  unlink(ready);
  unlink(cont);
  printf("RVMT_RUNTIME_MAP_TARGET_READY label=%s pid=%ld ready=%s continue=%s\n", label, (long)getpid(), ready, cont);
  fflush(stdout);
  touch_file(ready, "pid=%ld label=%s\n", (long)getpid(), label);
  wait_for_file(cont);
  rvmt_marker(begin);
  syscall(SYS_getpid);
  write(STDOUT_FILENO, "RVMT_RUNTIME_MAP_TARGET_ACTIVE\n", 31);
  rvmt_marker(end);
  printf("RVMT_RUNTIME_MAP_TARGET_DONE label=%s pid=%ld\n", label, (long)getpid());
  fflush(stdout);
  unlink(ready);
  unlink(cont);
  return 0;
}

static int mode_fork_ownership(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s fork-ownership BEGIN END\n", argv[0]);
    return 2;
  }
  uint32_t begin = (uint32_t)parse_hex32(argv[2]);
  uint32_t end = (uint32_t)parse_hex32(argv[3]);
  pid_t parent = getpid();
  char child_file[128];
  char child_ready[128];
  snprintf(child_file, sizeof(child_file), "/tmp/rvmt-fork-child-%ld", (long)parent);
  unlink(child_file);
  pid_t child = fork();
  if (child == 0) {
    pid_t self = getpid();
    char cont[128];
    snprintf(child_ready, sizeof(child_ready), "/tmp/rvmt-fork-pre-ready-%ld", (long)self);
    snprintf(cont, sizeof(cont), "/tmp/rvmt-fork-continue-%ld", (long)self);
    unlink(child_ready);
    unlink(cont);
    touch_file(child_ready, "pid=%ld ppid=%ld\n", (long)self, (long)getppid());
    wait_for_file(cont);
    rvmt_marker(begin);
    rvmt_emit_pid_marker("fork_parent_pid", RVMT_PID_MARKER_PARENT_PID, (long)getppid());
    rvmt_emit_pid_marker("fork_parent_tgid", RVMT_PID_MARKER_PARENT_TGID, (long)getppid());
    rvmt_emit_pid_marker("fork_child_pid", RVMT_PID_MARKER_CHILD_PID, rvmt_gettid());
    rvmt_emit_pid_marker("fork_child_tgid", RVMT_PID_MARKER_CHILD_TGID, (long)self);
    rvmt_emit_pid_marker("fork_child_pre_exec_pid", RVMT_PID_MARKER_CHILD_PRE_EXEC_PID, rvmt_gettid());
    rvmt_emit_pid_marker("fork_child_pre_exec_tgid", RVMT_PID_MARKER_CHILD_PRE_EXEC_TGID, (long)getpid());
    rvmt_marker(end);
    char *const args[] = {"/bin/busybox", "sleep", "15", NULL};
    execv(args[0], args);
    _exit(127);
  }
  touch_file(child_file, "%ld\n", (long)child);
  printf("RVMT_FORK_OWNERSHIP_PARENT parent_pid=%ld child_pid=%ld child_file=%s\n",
         (long)parent, (long)child, child_file);
  fflush(stdout);
  for (int i = 0; i < 4; ++i) {
    syscall(SYS_getpid);
    write(STDOUT_FILENO, "RVMT_FORK_PARENT_SYSCALL\n", 25);
    usleep(100000);
  }
  int status = 0;
  waitpid(child, &status, 0);
  printf("RVMT_FORK_OWNERSHIP_DONE parent_pid=%ld child_pid=%ld rc=%d raw_status=%d\n",
         (long)parent, (long)child, WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status), status);
  fflush(stdout);
  unlink(child_file);
  return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s MODE ...\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "capability") == 0) {
    return mode_capability();
  }
  if (strcmp(argv[1], "workload") == 0) {
    return mode_workload(argc, argv);
  }
  if (strcmp(argv[1], "runtime-map") == 0) {
    return mode_runtime_map(argc, argv);
  }
  if (strcmp(argv[1], "fork-ownership") == 0) {
    return mode_fork_ownership(argc, argv);
  }
  fprintf(stderr, "unknown mode: %s\n", argv[1]);
  return 2;
}
