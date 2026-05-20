#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RVMT_TRACE_WORDS 16u
#define RVMT_TRACE_STATUS_WORD 1u
#define RVMT_TRACE_COUNT_WORD 4u
#define RVMT_TRACE_DROP_WORD 5u
#define RVMT_TRACE_READ_INDEX_WORD 6u
#define RVMT_TRACE_READ_WORD_WORD 7u

typedef struct {
    const char *sample_class;
    const char *sample_id;
    const char *argv0;
    const char *argv1;
} sample_spec_t;

static const sample_spec_t samples[] = {
    {"benign", "hello", "/usr/bin/rvmt_benign_workload", "hello"},
    {"benign", "ls", "/usr/bin/rvmt_benign_workload", "ls"},
    {"benign", "cat", "/usr/bin/rvmt_benign_workload", "cat"},
    {"benign", "cp", "/usr/bin/rvmt_benign_workload", "cp"},
    {"benign", "sha256sum", "/usr/bin/rvmt_benign_workload", "sha256sum"},
    {"malware_like_synthetic", "file_scan", "/usr/bin/file_scan", NULL},
    {"malware_like_synthetic", "batch_open_read_write", "/usr/bin/batch_open_read_write", NULL},
    {"malware_like_synthetic", "self_copy_sim", "/usr/bin/self_copy_sim", NULL},
    {"malware_like_synthetic", "abnormal_syscall_sequence", "/usr/bin/abnormal_syscall_sequence", NULL},
    {"malware_like_synthetic", "illegal_trap", "/usr/bin/illegal_trap", NULL},
    {"malware_like_synthetic", "process_chain", "/usr/bin/process_chain", NULL},
    {"malware_like_synthetic", "dynamic_executable_memory", "/usr/bin/dynamic_executable_memory", NULL},
    {"malware_like_synthetic", "anti_debug_like", "/usr/bin/anti_debug_like", NULL},
};

static unsigned long parse_ulong(const char *s, const char *name) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(s, &end, 0);
    if (errno || end == s || *end != '\0') {
        fprintf(stderr, "invalid %s: %s\n", name, s);
        exit(2);
    }
    return value;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static volatile uint32_t *map_trace_csr(unsigned long base, unsigned long *map_len_out, unsigned long *page_off_out) {
    unsigned long page_size = (unsigned long)sysconf(_SC_PAGESIZE);
    unsigned long page_base = base & ~(page_size - 1u);
    unsigned long page_off = base - page_base;
    unsigned long map_len = page_off + 0x1000u;

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        exit(1);
    }

    volatile uint32_t *csr = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)page_base);
    close(fd);
    if (csr == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    *map_len_out = map_len;
    *page_off_out = page_off;
    return (volatile uint32_t *)((volatile uint8_t *)csr + page_off);
}

static void trace_set_mode(volatile uint32_t *csr, int enabled) {
    csr[0] = enabled ? 0x3u : 0x2u;
    (void)csr[RVMT_TRACE_STATUS_WORD];
    csr[0] = enabled ? 0x1u : 0x0u;
    (void)csr[RVMT_TRACE_STATUS_WORD];
}

static int run_sample(const sample_spec_t *sample) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 127;
    }
    if (pid == 0) {
        chdir("/opt/rvmt");
        setenv("RVMT_FIXTURE_ROOT", "experiments/linux_behavior/benign/fixtures", 1);
        if (sample->argv1 != NULL) {
            execl(sample->argv0, sample->argv0, sample->argv1, (char *)NULL);
        } else {
            execl(sample->argv0, sample->argv0, (char *)NULL);
        }
        perror("exec");
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 127;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 127;
}

static void dump_trace(volatile uint32_t *csr, unsigned long records) {
    uint32_t available = csr[RVMT_TRACE_COUNT_WORD];
    if (records > available) {
        records = available;
    }

    printf("RVMT_TRACE_STATUS %08" PRIx32 "\n", csr[RVMT_TRACE_STATUS_WORD]);
    printf("RVMT_TRACE_COUNT %08" PRIx32 "\n", available);
    printf("RVMT_TRACE_DROP %08" PRIx32 "\n", csr[RVMT_TRACE_DROP_WORD]);
    printf("RVMT_TRACE_RECORDS_READ %lu\n", records);
    puts("RVMT_TRACE_DUMP_BEGIN");
    for (unsigned long i = 0; i < records; ++i) {
        printf("RVMT_TRACE_RECORD %lu", i);
        for (unsigned word = 0; word < RVMT_TRACE_WORDS; ++word) {
            csr[RVMT_TRACE_READ_INDEX_WORD] = (uint32_t)(i * RVMT_TRACE_WORDS + word);
            printf(" %08" PRIx32, csr[RVMT_TRACE_READ_WORD_WORD]);
        }
        putchar('\n');
    }
    puts("RVMT_TRACE_DUMP_END");
}

static int sample_selected(const sample_spec_t *sample, int argc, char **argv, int first_index) {
    if (first_index >= argc) {
        return 1;
    }
    for (int i = first_index; i < argc; ++i) {
        if (strcmp(argv[i], sample->sample_id) == 0 || strcmp(argv[i], sample->sample_class) == 0) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <trace-csr-base> <records> <reps> <trace-on|trace-off> [sample-id|class ...]\n", argv[0]);
        return 2;
    }

    unsigned long csr_base = parse_ulong(argv[1], "trace-csr-base");
    unsigned long records = parse_ulong(argv[2], "records");
    unsigned long reps = parse_ulong(argv[3], "reps");
    int trace_on = strcmp(argv[4], "trace-on") == 0;
    if (!trace_on && strcmp(argv[4], "trace-off") != 0) {
        fprintf(stderr, "mode must be trace-on or trace-off\n");
        return 2;
    }

    unsigned long map_len = 0;
    unsigned long page_off = 0;
    volatile uint32_t *csr = map_trace_csr(csr_base, &map_len, &page_off);
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("RVMT_EXP_BEGIN mode=%s reps=%lu records=%lu csr_base=0x%08lx\n", trace_on ? "trace-on" : "trace-off", reps, records, csr_base);
    for (size_t sample_index = 0; sample_index < sizeof(samples) / sizeof(samples[0]); ++sample_index) {
        const sample_spec_t *sample = &samples[sample_index];
        if (!sample_selected(sample, argc, argv, 5)) {
            continue;
        }
        printf("RVMT_EXP_SAMPLE_BEGIN class=%s sample=%s mode=%s\n", sample->sample_class, sample->sample_id, trace_on ? "trace-on" : "trace-off");
        for (unsigned long rep = 0; rep < reps; ++rep) {
            printf("RVMT_EXP_REP_BEGIN class=%s sample=%s mode=%s rep=%lu\n", sample->sample_class, sample->sample_id, trace_on ? "trace-on" : "trace-off", rep);
            trace_set_mode(csr, trace_on);
            uint64_t start = monotonic_ns();
            int exit_code = run_sample(sample);
            uint64_t end = monotonic_ns();
            uint32_t count = csr[RVMT_TRACE_COUNT_WORD];
            uint32_t drop = csr[RVMT_TRACE_DROP_WORD];
            printf(
                "RVMT_EXP_REP_RESULT class=%s sample=%s mode=%s rep=%lu exit=%d runtime_ns=%" PRIu64 " trace_count=%" PRIu32 " drop=%" PRIu32 "\n",
                sample->sample_class,
                sample->sample_id,
                trace_on ? "trace-on" : "trace-off",
                rep,
                exit_code,
                end - start,
                count,
                drop
            );
            if (trace_on) {
                dump_trace(csr, records);
            }
            trace_set_mode(csr, 0);
            printf("RVMT_EXP_REP_END class=%s sample=%s mode=%s rep=%lu\n", sample->sample_class, sample->sample_id, trace_on ? "trace-on" : "trace-off", rep);
        }
        printf("RVMT_EXP_SAMPLE_END class=%s sample=%s mode=%s\n", sample->sample_class, sample->sample_id, trace_on ? "trace-on" : "trace-off");
    }
    puts("RVMT_EXP_END status=PASS");

    munmap((void *)((uintptr_t)csr - page_off), map_len);
    return 0;
}
