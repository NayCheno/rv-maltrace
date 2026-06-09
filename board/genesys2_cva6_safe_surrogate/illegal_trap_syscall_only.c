// Safe repository-authored malware-like synthetic sample for Genesys2/CVA6.
// It mirrors experiments/linux_behavior/malware_like/programs/illegal_trap.c
// without libc so it can be transferred over the board UART as a tiny ELF.

struct rvmt_kernel_sigaction {
  void (*handler)(int);
  unsigned long flags;
  void (*restorer)(void);
  unsigned long mask;
};

static inline long rvmt_syscall4(long n, long a0, long a1, long a2, long a3) {
  register long x10 asm("a0") = a0;
  register long x11 asm("a1") = a1;
  register long x12 asm("a2") = a2;
  register long x13 asm("a3") = a3;
  register long x17 asm("a7") = n;
  asm volatile("ecall" : "+r"(x10) : "r"(x11), "r"(x12), "r"(x13), "r"(x17) : "memory");
  return x10;
}

static void sigill_handler(int signum) {
  (void)signum;
  static const char message[] = "synthetic SIGILL\n";
  rvmt_syscall4(64, 1, (long)message, sizeof(message) - 1, 0);
  rvmt_syscall4(93, 0, 0, 0, 0);
  __builtin_unreachable();
}

void _start(void) {
  struct rvmt_kernel_sigaction action = {
      .handler = sigill_handler,
      .flags = 0,
      .restorer = 0,
      .mask = 0,
  };

  for (volatile unsigned long warmup = 0; warmup < 80000000UL; ++warmup) {
  }

  rvmt_syscall4(134, 4, (long)&action, 0, 8);
  asm volatile(".word 0xffffffff");
  rvmt_syscall4(93, 1, 0, 0, 0);

  __builtin_unreachable();
}
