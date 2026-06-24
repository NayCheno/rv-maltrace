#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t (*counter_read_fn)(void);

static sigjmp_buf g_sigill_jmp;
static volatile sig_atomic_t g_in_counter_probe;

static void sigill_handler(int signo) {
    (void)signo;
    if (g_in_counter_probe) {
        g_in_counter_probe = 0;
        siglongjmp(g_sigill_jmp, 1);
    }
    _exit(128 + SIGILL);
}

static inline uint64_t read_cycle(void) {
    uint64_t value;
    __asm__ volatile("rdcycle %0" : "=r"(value));
    return value;
}

static inline uint64_t read_time_counter(void) {
    uint64_t value;
    __asm__ volatile("rdtime %0" : "=r"(value));
    return value;
}

static inline uint64_t read_instret(void) {
    uint64_t value;
    __asm__ volatile("rdinstret %0" : "=r"(value));
    return value;
}

static uint64_t spin_work(unsigned iters) {
    volatile uint64_t sink = 0;
    for (unsigned i = 0; i < iters; ++i) {
        sink += ((uint64_t)i * 1103515245ull) ^ (sink >> 3);
    }
    return sink;
}

static void probe_counter(const char *name, counter_read_fn read_fn, unsigned reps, unsigned iters) {
    g_in_counter_probe = 1;
    if (sigsetjmp(g_sigill_jmp, 1) != 0) {
        printf("RVMT_COUNTER_ACCESS name=%s status=ILLEGAL_INSTRUCTION\n", name);
        fflush(stdout);
        return;
    }

    uint64_t first = read_fn();
    uint64_t second = read_fn();
    g_in_counter_probe = 0;
    printf(
        "RVMT_COUNTER_ACCESS name=%s status=AVAILABLE first=%" PRIu64 " second=%" PRIu64
        " immediate_delta=%" PRIu64 "\n",
        name,
        first,
        second,
        second - first);

    for (unsigned rep = 1; rep <= reps; ++rep) {
        uint64_t start = read_fn();
        uint64_t sink = spin_work(iters);
        uint64_t after_loop = read_fn();
        pid_t pid = getpid();
        uint64_t after_syscall = read_fn();
        printf(
            "RVMT_COUNTER_DELTA rep=%u name=%s loop_delta=%" PRIu64
            " syscall_delta=%" PRIu64 " total_delta=%" PRIu64 " pid=%ld sink=%" PRIu64 "\n",
            rep,
            name,
            after_loop - start,
            after_syscall - after_loop,
            after_syscall - start,
            (long)pid,
            sink);
    }
    fflush(stdout);
}

static void probe_clock(const char *name, clockid_t clock_id, unsigned reps, unsigned iters) {
    struct timespec resolution;
    if (clock_getres(clock_id, &resolution) != 0) {
        printf(
            "RVMT_CLOCK_ACCESS name=%s status=UNAVAILABLE op=clock_getres errno=%d reason=%s\n",
            name,
            errno,
            strerror(errno));
        return;
    }

    struct timespec first;
    struct timespec second;
    if (clock_gettime(clock_id, &first) != 0 || clock_gettime(clock_id, &second) != 0) {
        printf(
            "RVMT_CLOCK_ACCESS name=%s status=UNAVAILABLE op=clock_gettime errno=%d reason=%s\n",
            name,
            errno,
            strerror(errno));
        return;
    }
    int64_t immediate_ns =
        (int64_t)(second.tv_sec - first.tv_sec) * 1000000000ll + (int64_t)(second.tv_nsec - first.tv_nsec);
    printf(
        "RVMT_CLOCK_ACCESS name=%s status=AVAILABLE res_ns=%" PRId64 " immediate_delta_ns=%" PRId64 "\n",
        name,
        (int64_t)resolution.tv_sec * 1000000000ll + (int64_t)resolution.tv_nsec,
        immediate_ns);

    for (unsigned rep = 1; rep <= reps; ++rep) {
        struct timespec start;
        struct timespec after_loop;
        struct timespec after_syscall;
        if (clock_gettime(clock_id, &start) != 0) {
            continue;
        }
        uint64_t sink = spin_work(iters);
        if (clock_gettime(clock_id, &after_loop) != 0) {
            continue;
        }
        pid_t pid = getpid();
        if (clock_gettime(clock_id, &after_syscall) != 0) {
            continue;
        }
        int64_t loop_delta_ns =
            (int64_t)(after_loop.tv_sec - start.tv_sec) * 1000000000ll
            + (int64_t)(after_loop.tv_nsec - start.tv_nsec);
        int64_t syscall_delta_ns =
            (int64_t)(after_syscall.tv_sec - after_loop.tv_sec) * 1000000000ll
            + (int64_t)(after_syscall.tv_nsec - after_loop.tv_nsec);
        int64_t total_delta_ns =
            (int64_t)(after_syscall.tv_sec - start.tv_sec) * 1000000000ll
            + (int64_t)(after_syscall.tv_nsec - start.tv_nsec);
        printf(
            "RVMT_CLOCK_DELTA rep=%u name=%s loop_delta_ns=%" PRId64
            " syscall_delta_ns=%" PRId64 " total_delta_ns=%" PRId64 " pid=%ld sink=%" PRIu64 "\n",
            rep,
            name,
            loop_delta_ns,
            syscall_delta_ns,
            total_delta_ns,
            (long)pid,
            sink);
    }
    fflush(stdout);
}

int main(int argc, char **argv) {
    unsigned reps = 5;
    unsigned iters = 10000;
    if (argc > 1) {
        unsigned parsed = 0;
        if (sscanf(argv[1], "%u", &parsed) == 1 && parsed > 0) {
            reps = parsed;
        }
    }
    if (argc > 2) {
        unsigned parsed = 0;
        if (sscanf(argv[2], "%u", &parsed) == 1 && parsed > 0) {
            iters = parsed;
        }
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = sigill_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGILL, &action, NULL) != 0) {
        printf("RVMT_COUNTER_MATRIX_SETUP status=FAIL op=sigaction errno=%d reason=%s\n", errno, strerror(errno));
        return 1;
    }

    printf("RVMT_COUNTER_MATRIX_BEGIN reps=%u iters=%u\n", reps, iters);
    probe_counter("cycle", read_cycle, reps, iters);
    probe_counter("time", read_time_counter, reps, iters);
    probe_counter("instret", read_instret, reps, iters);
    probe_clock("clock_monotonic", CLOCK_MONOTONIC, reps, iters);
#ifdef CLOCK_MONOTONIC_RAW
    probe_clock("clock_monotonic_raw", CLOCK_MONOTONIC_RAW, reps, iters);
#endif
    printf("RVMT_COUNTER_MATRIX_DONE reps=%u iters=%u\n", reps, iters);
    return 0;
}
