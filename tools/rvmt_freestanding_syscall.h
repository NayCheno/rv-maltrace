#ifndef RVMT_FREESTANDING_SYSCALL_H
#define RVMT_FREESTANDING_SYSCALL_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

char **environ = 0;

#define RVMT_CAT2(a, b) a##b
#define RVMT_CAT(a, b) RVMT_CAT2(a, b)
#define RVMT_NARGS_IMPL(_0, _1, _2, _3, _4, _5, _6, _7, N, ...) N
#define RVMT_NARGS(...) RVMT_NARGS_IMPL(_, ##__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)
#define RVMT_DISPATCH(name, count) RVMT_CAT(name, count)

#define rvmt_syscall_1(n)                                                                            \
  ({                                                                                                  \
    register long _a0 __asm__("a0");                                                                 \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "=r"(_a0) : "r"(_a7) : "memory");                                   \
    _a0;                                                                                              \
  })

#define rvmt_syscall_2(n, x0)                                                                         \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0) : "r"(_a7) : "memory");                                  \
    _a0;                                                                                              \
  })

#define rvmt_syscall_3(n, x0, x1)                                                                     \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a1 __asm__("a1") = (long)(x1);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0) : "r"(_a1), "r"(_a7) : "memory");                         \
    _a0;                                                                                              \
  })

#define rvmt_syscall_4(n, x0, x1, x2)                                                                 \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a1 __asm__("a1") = (long)(x1);                                                    \
    register long _a2 __asm__("a2") = (long)(x2);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a7) : "memory");              \
    _a0;                                                                                              \
  })

#define rvmt_syscall_5(n, x0, x1, x2, x3)                                                             \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a1 __asm__("a1") = (long)(x1);                                                    \
    register long _a2 __asm__("a2") = (long)(x2);                                                    \
    register long _a3 __asm__("a3") = (long)(x3);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a7) : "memory");   \
    _a0;                                                                                              \
  })

#define rvmt_syscall_6(n, x0, x1, x2, x3, x4)                                                         \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a1 __asm__("a1") = (long)(x1);                                                    \
    register long _a2 __asm__("a2") = (long)(x2);                                                    \
    register long _a3 __asm__("a3") = (long)(x3);                                                    \
    register long _a4 __asm__("a4") = (long)(x4);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a7)       \
                     : "memory");                                                                    \
    _a0;                                                                                              \
  })

#define rvmt_syscall_7(n, x0, x1, x2, x3, x4, x5)                                                     \
  ({                                                                                                  \
    register long _a0 __asm__("a0") = (long)(x0);                                                    \
    register long _a1 __asm__("a1") = (long)(x1);                                                    \
    register long _a2 __asm__("a2") = (long)(x2);                                                    \
    register long _a3 __asm__("a3") = (long)(x3);                                                    \
    register long _a4 __asm__("a4") = (long)(x4);                                                    \
    register long _a5 __asm__("a5") = (long)(x5);                                                    \
    register long _a7 __asm__("a7") = (long)(n);                                                     \
    __asm__ volatile("ecall" : "+r"(_a0)                                                            \
                     : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a7) : "memory");    \
    _a0;                                                                                              \
  })

#define syscall(...) RVMT_DISPATCH(rvmt_syscall_, RVMT_NARGS(__VA_ARGS__))(__VA_ARGS__)

static __attribute__((noreturn)) void rvmt_exit(long code) {
  syscall(SYS_exit, code);
  for (;;) {
    __asm__ volatile("wfi");
  }
}

#define _exit(code) rvmt_exit(code)

static void *rvmt_memset_impl(void *dest, int value, size_t count) {
  unsigned char *out = (unsigned char *)dest;
  for (size_t i = 0; i < count; ++i) {
    out[i] = (unsigned char)value;
  }
  return dest;
}

static void *rvmt_memcpy_impl(void *dest, const void *src, size_t count) {
  unsigned char *out = (unsigned char *)dest;
  const unsigned char *in = (const unsigned char *)src;
  for (size_t i = 0; i < count; ++i) {
    out[i] = in[i];
  }
  return dest;
}

#define memset(dest, value, count) rvmt_memset_impl((dest), (value), (count))
#define memcpy(dest, src, count) rvmt_memcpy_impl((dest), (src), (count))

#define sigemptyset(set) ((int)((rvmt_memset_impl((set), 0, sizeof(*(set))) == 0) ? -1 : 0))
#define sigaction(signum, act, oldact) syscall(SYS_rt_sigaction, (signum), (act), (oldact), 8)

extern int main();

static __attribute__((noreturn)) void rvmt_start_c(uintptr_t *stack) {
  int argc = (int)stack[0];
  char **argv = (char **)&stack[1];
  int rc = main(argc, argv);
  rvmt_exit(rc);
}

__asm__(
    ".section .text,\"ax\",@progbits\n"
    ".global _start\n"
    "_start:\n"
    "  mv a0, sp\n"
    "  call rvmt_start_c\n");

#endif
