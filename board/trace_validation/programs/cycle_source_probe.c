typedef unsigned long u64;
typedef long s64;
typedef unsigned int u32;

#define SYS_read 63
#define SYS_write 64
#define SYS_close 57
#define SYS_getpid 172
#define SYS_perf_event_open 241
#define SYS_exit 93

#define PERF_TYPE_HARDWARE 0
#define PERF_COUNT_HW_CPU_CYCLES 0

struct perf_event_attr_min {
    u32 type;
    u32 size;
    u64 config;
    u64 sample_period;
    u64 sample_type;
    u64 read_format;
    u64 flags;
    u32 wakeup_events;
    u32 bp_type;
    u64 bp_addr;
    u64 bp_len;
};

static volatile u64 g_sink;

static inline long syscall0(long number) {
    register long a0 __asm__("a0");
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "=r"(a0) : "r"(a7) : "memory");
    return a0;
}

static inline long syscall1(long number, long arg0) {
    register long a0 __asm__("a0") = arg0;
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a7) : "memory");
    return a0;
}

static inline long syscall3(long number, long arg0, long arg1, long arg2) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0), "+r"(a1), "+r"(a2) : "r"(a7) : "memory");
    return a0;
}

static inline long syscall5(long number, long arg0, long arg1, long arg2, long arg3, long arg4) {
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0), "+r"(a1), "+r"(a2), "+r"(a3), "+r"(a4) : "r"(a7) : "memory");
    return a0;
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

static char *append_dec_unsigned(char *out, u64 value) {
    char tmp[24];
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

static char *append_dec_signed(char *out, s64 value) {
    if (value < 0) {
        *out++ = '-';
        return append_dec_unsigned(out, (u64)(-value));
    }
    return append_dec_unsigned(out, (u64)value);
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

static void emit_unavailable(const char *reason, long code) {
    char line[160];
    char *out = line;
    out = append_str(out, "RVMT_CYCLE_SOURCE_UNAVAILABLE source=perf_hw_cycles reason=");
    out = append_str(out, reason);
    out = append_str(out, " code=");
    out = append_dec_signed(out, code);
    *out++ = '\n';
    write_buf(line, (u64)(out - line));
}

static void emit_row(unsigned rep, u64 loop_delta, u64 syscall_delta, u64 total_delta, long pid) {
    char line[288];
    char *out = line;
    out = append_str(out, "RVMT_CYCLE_SOURCE rep=");
    out = append_dec_unsigned(out, rep);
    out = append_str(out, " source=perf_hw_cycles loop_delta=");
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

static long read_counter(int fd, u64 *value) {
    long rc = syscall3(SYS_read, fd, (long)value, 8);
    return rc == 8 ? 0 : rc;
}

void _start(void) {
    enum { reps = 5 };
    const u64 iters = 10000;
    write_str("RVMT_CYCLE_SOURCE_BEGIN source=perf_hw_cycles reps=5 iters=10000\n");

    struct perf_event_attr_min attr;
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.sample_period = 0;
    attr.sample_type = 0;
    attr.read_format = 0;
    attr.flags = 0;
    attr.wakeup_events = 0;
    attr.bp_type = 0;
    attr.bp_addr = 0;
    attr.bp_len = 0;

    long fd = syscall5(SYS_perf_event_open, (long)&attr, 0, -1, -1, 0);
    if (fd < 0) {
        emit_unavailable("perf_event_open_failed", fd);
        syscall1(SYS_exit, 0);
    }

    u64 probe = 0;
    long read_rc = read_counter((int)fd, &probe);
    if (read_rc != 0) {
        emit_unavailable("perf_read_failed", read_rc);
        syscall1(SYS_close, fd);
        syscall1(SYS_exit, 0);
    }

    char probe_line[128];
    char *out = probe_line;
    out = append_str(out, "RVMT_CYCLE_SOURCE_AVAILABLE source=perf_hw_cycles value=");
    out = append_hex64(out, probe);
    *out++ = '\n';
    write_buf(probe_line, (u64)(out - probe_line));

    for (unsigned rep = 1; rep <= reps; ++rep) {
        u64 start = 0;
        u64 after_loop = 0;
        u64 after_syscall = 0;
        if (read_counter((int)fd, &start) != 0) {
            emit_unavailable("perf_read_start_failed", -1);
            break;
        }
        busy_loop(iters);
        if (read_counter((int)fd, &after_loop) != 0) {
            emit_unavailable("perf_read_loop_failed", -1);
            break;
        }
        long pid = syscall0(SYS_getpid);
        if (read_counter((int)fd, &after_syscall) != 0) {
            emit_unavailable("perf_read_syscall_failed", -1);
            break;
        }
        emit_row(rep, after_loop - start, after_syscall - after_loop, after_syscall - start, pid);
    }
    syscall1(SYS_close, fd);
    write_str("RVMT_CYCLE_SOURCE_DONE source=perf_hw_cycles reps=5\n");
    syscall1(SYS_exit, 0);
    for (;;) {
    }
}
