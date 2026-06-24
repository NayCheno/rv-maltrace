typedef unsigned long u64;
typedef long s64;

#define SYS_write 64
#define SYS_getpid 172
#define SYS_exit 93

static volatile u64 g_sink;

static inline long syscall3(long number, long arg0, long arg1, long arg2) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
}

static inline long syscall0(long number) {
    register long a0 __asm__("a0");
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "=r"(a0) : "r"(a7) : "memory");
    return a0;
}

static inline u64 rdcycle_value(void) {
    u64 value;
    __asm__ volatile("rdcycle %0" : "=r"(value));
    return value;
}

static u64 cstr_len(const char *text) {
    u64 n = 0;
    while (text[n] != 0) {
        ++n;
    }
    return n;
}

static void write_buf(const char *text, u64 len) {
    syscall3(SYS_write, 1, (long)text, (long)len);
}

static void write_str(const char *text) {
    write_buf(text, cstr_len(text));
}

static char *append_str(char *out, const char *text) {
    while (*text != 0) {
        *out++ = *text++;
    }
    return out;
}

static char *append_dec_small(char *out, unsigned value) {
    char tmp[16];
    unsigned index = 0;
    if (value == 0) {
        *out++ = '0';
        return out;
    }
    while (value > 0 && index < sizeof(tmp)) {
        tmp[index++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (index > 0) {
        *out++ = tmp[--index];
    }
    return out;
}

static char *append_hex64(char *out, u64 value) {
    static const char hex[] = "0123456789abcdef";
    *out++ = '0';
    *out++ = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        *out++ = hex[(value >> (unsigned)shift) & 0xfU];
    }
    return out;
}

static void busy_loop(u64 iters) {
    u64 local = g_sink + 0x9e3779b97f4a7c15UL;
    for (u64 i = 0; i < iters; ++i) {
        local ^= i + (local << 7);
        local += (local >> 3) ^ 0xa5a5a5a5a5a5a5a5UL;
    }
    g_sink = local;
}

static void emit_row(unsigned rep, u64 loop_delta, u64 syscall_delta, u64 total_delta, long pid) {
    char line[256];
    char *out = line;
    out = append_str(out, "RVMT_CYCLE_SMOKE rep=");
    out = append_dec_small(out, rep);
    out = append_str(out, " loop_delta=");
    out = append_hex64(out, loop_delta);
    out = append_str(out, " syscall_delta=");
    out = append_hex64(out, syscall_delta);
    out = append_str(out, " total_delta=");
    out = append_hex64(out, total_delta);
    out = append_str(out, " pid=");
    out = append_hex64(out, (u64)pid);
    out = append_str(out, " sink=");
    out = append_hex64(out, g_sink);
    *out++ = '\n';
    write_buf(line, (u64)(out - line));
}

void _start(void) {
    enum { reps = 5 };
    const u64 iters = 10000;
    write_str("RVMT_CYCLE_SMOKE_BEGIN reps=5 iters=10000\n");
    u64 probe = rdcycle_value();
    char probe_line[80];
    char *out = probe_line;
    out = append_str(out, "RVMT_CYCLE_SMOKE_RDCYCLE_AVAILABLE value=");
    out = append_hex64(out, probe);
    *out++ = '\n';
    write_buf(probe_line, (u64)(out - probe_line));
    for (unsigned rep = 1; rep <= reps; ++rep) {
        u64 start = rdcycle_value();
        busy_loop(iters);
        u64 after_loop = rdcycle_value();
        long pid = syscall0(SYS_getpid);
        u64 after_syscall = rdcycle_value();
        emit_row(rep, after_loop - start, after_syscall - after_loop, after_syscall - start, pid);
    }
    write_str("RVMT_CYCLE_SMOKE_DONE reps=5\n");
    syscall3(SYS_exit, 0, 0, 0);
    for (;;) {
    }
}
