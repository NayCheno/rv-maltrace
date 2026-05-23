#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/ptrace.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RVMT_TRACE_WORDS 16u
#define RVMT_TRACE_STATUS_WORD 1u
#define RVMT_TRACE_COUNT_WORD 4u
#define RVMT_TRACE_DROP_WORD 5u
#define RVMT_TRACE_READ_INDEX_WORD 6u
#define RVMT_TRACE_READ_WORD_WORD 7u
#define RVMT_TRACE_MARKER_VALUE_WORD 8u
#define RVMT_TRACE_MARKER_EMIT_WORD 9u
#define RVMT_TRACE_CONTROL_ENABLE 0x0001u
#define RVMT_TRACE_CONTROL_CLEAR 0x0002u
#define RVMT_TRACE_CONTROL_MARKER 0x0400u
#define RVMT_TRACE_STATUS_BUSY 0x00000004u
#define RVMT_TRACE_DEFAULT_PROFILE_MASK 0x043cu
#define RVMT_MARKER_BEGIN_TAG 0xb0000000u
#define RVMT_MARKER_END_TAG 0xe0000000u

typedef struct {
    const char *sample_class;
    const char *sample_id;
    const char *argv0;
    const char *argv1;
    int default_enabled;
} sample_spec_t;

typedef struct {
    unsigned long control_mask;
    unsigned long warmup;
    int syscall_side_channel;
    int first_sample_arg;
} runner_options_t;

typedef struct {
    pid_t pid;
    int active;
    int in_syscall;
    unsigned long seq;
    unsigned long nr;
    unsigned long args[8];
} traced_pid_t;

#define RVMT_MAX_TRACED_PIDS 32
#define RVMT_SC_OPENAT 56ul
#define RVMT_SC_CLOSE 57ul
#define RVMT_SC_GETDENTS64 61ul
#define RVMT_SC_READ 63ul
#define RVMT_SC_WRITE 64ul
#define RVMT_SC_WAITID 95ul
#define RVMT_SC_CLONE 220ul
#define RVMT_SC_EXECVE 221ul

static const sample_spec_t samples[] = {
    {"benign", "hello", "/usr/bin/rvmt_benign_workload", "hello", 1},
    {"benign", "ls", "/usr/bin/rvmt_benign_workload", "ls", 1},
    {"benign", "cat", "/usr/bin/rvmt_benign_workload", "cat", 1},
    {"benign", "cp", "/usr/bin/rvmt_benign_workload", "cp", 1},
    {"benign", "sha256sum", "/usr/bin/rvmt_benign_workload", "sha256sum", 1},
    {"malware_like_synthetic", "file_scan", "/usr/bin/file_scan", NULL, 1},
    {"malware_like_synthetic", "batch_open_read_write", "/usr/bin/batch_open_read_write", NULL, 1},
    {"malware_like_synthetic", "self_copy_sim", "/usr/bin/self_copy_sim", NULL, 1},
    {"malware_like_synthetic", "abnormal_syscall_sequence", "/usr/bin/abnormal_syscall_sequence", NULL, 1},
    {"malware_like_synthetic", "illegal_trap", "/usr/bin/illegal_trap", NULL, 1},
    {"malware_like_synthetic", "process_chain", "/usr/bin/process_chain", NULL, 1},
    {"malware_like_synthetic", "dynamic_executable_memory", "/usr/bin/dynamic_executable_memory", NULL, 1},
    {"malware_like_synthetic", "anti_debug_like", "/usr/bin/anti_debug_like", NULL, 1},
    {"malware_like_synthetic", "direct_syscall_open_read", "/usr/bin/direct_syscall_open_read", NULL, 0},
    {"malware_like_synthetic", "timing_anti_analysis_loop", "/usr/bin/timing_anti_analysis_loop", NULL, 0},
    {"malware_like_synthetic", "proc_status_tracerpid_check", "/usr/bin/proc_status_tracerpid_check", NULL, 0},
    {"malware_like_synthetic", "obfuscated_syscall_wrapper", "/usr/bin/obfuscated_syscall_wrapper", NULL, 0},
    {"malware_like_synthetic", "self_modifying_code_sim", "/usr/bin/self_modifying_code_sim", NULL, 0},
    {"malware_like_synthetic", "mprotect_exec_variant", "/usr/bin/mprotect_exec_variant", NULL, 0},
    {"malware_like_synthetic", "multi_level_process_chain", "/usr/bin/multi_level_process_chain", NULL, 0},
    {"malware_like_synthetic", "loopback_network_client", "/usr/bin/loopback_network_client", NULL, 0},
    {"malware_like_synthetic", "file_encryption_sim_non_destructive", "/usr/bin/file_encryption_sim_non_destructive", NULL, 0},
    {"malware_like_synthetic", "mirai_proc_scan_sim", "/usr/bin/mirai_proc_scan_sim", NULL, 0},
    {"malware_like_synthetic", "mirai_watchdog_probe_sim", "/usr/bin/mirai_watchdog_probe_sim", NULL, 0},
    {"malware_like_synthetic", "mirai_encoded_table_sim", "/usr/bin/mirai_encoded_table_sim", NULL, 0},
    {"malware_like_synthetic", "mirai_c2_loopback_probe", "/usr/bin/mirai_c2_loopback_probe", NULL, 0},
    {"real_malware_surrogate", "darthra_elf_header_probe", "/usr/bin/darthra_elf_header_probe", NULL, 0},
    {"real_malware_surrogate", "darthra_rootkit_device_probe", "/usr/bin/darthra_rootkit_device_probe", NULL, 0},
    {"real_malware_surrogate", "darthra_virus_fixture_walk_sim", "/usr/bin/darthra_virus_fixture_walk_sim", NULL, 0},
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

static void trace_set_mode(volatile uint32_t *csr, int enabled, uint32_t control_mask, int clear) {
    uint32_t base = control_mask & ~(RVMT_TRACE_CONTROL_ENABLE | RVMT_TRACE_CONTROL_CLEAR);
    if (clear) {
        csr[0] = base | RVMT_TRACE_CONTROL_CLEAR | (enabled ? RVMT_TRACE_CONTROL_ENABLE : 0u);
        (void)csr[RVMT_TRACE_STATUS_WORD];
    }
    csr[0] = base | (enabled ? RVMT_TRACE_CONTROL_ENABLE : 0u);
    (void)csr[RVMT_TRACE_STATUS_WORD];
}

static void trace_wait_idle(volatile uint32_t *csr) {
    for (unsigned long spin = 0; spin < 1000000ul; ++spin) {
        if ((csr[RVMT_TRACE_STATUS_WORD] & RVMT_TRACE_STATUS_BUSY) == 0u) {
            return;
        }
    }
}

static uint32_t fnv1a32(const char *text) {
    uint32_t hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; ++p) {
        hash ^= (uint32_t)(*p);
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t marker_value(uint32_t tag, const sample_spec_t *sample, unsigned long rep) {
    uint32_t sample_hash = fnv1a32(sample->sample_id) & 0x0000ffffu;
    uint32_t rep_field = ((uint32_t)rep & 0xffu) << 16;
    return tag | rep_field | sample_hash;
}

static void trace_emit_marker(volatile uint32_t *csr, uint32_t value) {
    trace_wait_idle(csr);
    uint32_t before_count = csr[RVMT_TRACE_COUNT_WORD];
    uint32_t before_drop = csr[RVMT_TRACE_DROP_WORD];
    csr[RVMT_TRACE_MARKER_VALUE_WORD] = value;
    csr[RVMT_TRACE_MARKER_EMIT_WORD] = 1u;
    (void)csr[RVMT_TRACE_STATUS_WORD];
    for (unsigned long spin = 0; spin < 1000000ul; ++spin) {
        uint32_t status = csr[RVMT_TRACE_STATUS_WORD];
        uint32_t count = csr[RVMT_TRACE_COUNT_WORD];
        uint32_t drop = csr[RVMT_TRACE_DROP_WORD];
        if ((count != before_count || drop != before_drop) && (status & RVMT_TRACE_STATUS_BUSY) == 0u) {
            return;
        }
    }
}

static void strip_newline(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        --len;
    }
}

static void print_hex_text(const char *text) {
    if (text == NULL) {
        return;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; ++p) {
        printf("%02x", (unsigned int)(*p));
    }
}

static const char *syscall_name(unsigned long nr) {
    switch (nr) {
    case RVMT_SC_OPENAT:
        return "openat";
    case RVMT_SC_CLOSE:
        return "close";
    case RVMT_SC_GETDENTS64:
        return "getdents64";
    case RVMT_SC_READ:
        return "read";
    case RVMT_SC_WRITE:
        return "write";
    case RVMT_SC_WAITID:
        return "waitid";
    case RVMT_SC_CLONE:
        return "clone";
    case RVMT_SC_EXECVE:
        return "execve";
    default:
        return "unknown";
    }
}

static int syscall_side_channel_interesting(unsigned long nr) {
    return nr == RVMT_SC_OPENAT || nr == RVMT_SC_CLOSE || nr == RVMT_SC_GETDENTS64 || nr == RVMT_SC_READ ||
           nr == RVMT_SC_WRITE || nr == RVMT_SC_WAITID || nr == RVMT_SC_CLONE || nr == RVMT_SC_EXECVE;
}

static int read_child_string(pid_t pid, unsigned long addr, char *out, size_t out_len) {
    if (addr == 0 || out_len == 0) {
        if (out_len) {
            out[0] = '\0';
        }
        return -1;
    }
    size_t offset = 0;
    errno = 0;
    while (offset + 1 < out_len) {
        unsigned long word = (unsigned long)ptrace(PTRACE_PEEKDATA, pid, (void *)(addr + offset), NULL);
        if (errno != 0) {
            out[offset] = '\0';
            return offset > 0 ? 0 : -1;
        }
        for (size_t byte = 0; byte < sizeof(word) && offset + 1 < out_len; ++byte) {
            char value = (char)((word >> (byte * 8)) & 0xffu);
            out[offset++] = value;
            if (value == '\0') {
                return 0;
            }
        }
    }
    out[out_len - 1] = '\0';
    return 0;
}

static traced_pid_t *tracked_slot(traced_pid_t *tracked, pid_t pid) {
    for (size_t i = 0; i < RVMT_MAX_TRACED_PIDS; ++i) {
        if (tracked[i].active && tracked[i].pid == pid) {
            return &tracked[i];
        }
    }
    return NULL;
}

static traced_pid_t *tracked_add(traced_pid_t *tracked, pid_t pid) {
    traced_pid_t *slot = tracked_slot(tracked, pid);
    if (slot != NULL) {
        return slot;
    }
    for (size_t i = 0; i < RVMT_MAX_TRACED_PIDS; ++i) {
        if (!tracked[i].active) {
            memset(&tracked[i], 0, sizeof(tracked[i]));
            tracked[i].pid = pid;
            tracked[i].active = 1;
            return &tracked[i];
        }
    }
    return NULL;
}

static void tracked_remove(traced_pid_t *tracked, pid_t pid) {
    traced_pid_t *slot = tracked_slot(tracked, pid);
    if (slot != NULL) {
        memset(slot, 0, sizeof(*slot));
    }
}

static int tracked_count(traced_pid_t *tracked) {
    int count = 0;
    for (size_t i = 0; i < RVMT_MAX_TRACED_PIDS; ++i) {
        if (tracked[i].active) {
            ++count;
        }
    }
    return count;
}

static void emit_syscall_obs(
    const sample_spec_t *sample,
    const char *mode,
    unsigned long rep,
    int warmup,
    const char *phase,
    pid_t pid,
    unsigned long seq,
    unsigned long nr,
    const unsigned long *args,
    unsigned long ret,
    int have_ret
) {
    if (!syscall_side_channel_interesting(nr)) {
        return;
    }
    char path[256];
    path[0] = '\0';
    if (nr == RVMT_SC_OPENAT || nr == RVMT_SC_EXECVE) {
        unsigned long pointer = nr == RVMT_SC_OPENAT ? args[1] : args[0];
        (void)read_child_string(pid, pointer, path, sizeof(path));
    }
    printf(
        "RVMT_SYSCALL_OBS schema=rvmt.syscall_side_channel.v1 class=%s sample=%s mode=%s rep=%lu warmup=%d phase=%s pid=%ld seq=%lu nr=%lu name=%s a0=0x%016lx a1=0x%016lx a2=0x%016lx a3=0x%016lx a4=0x%016lx a5=0x%016lx a6=0x%016lx a7=0x%016lx",
        sample->sample_class,
        sample->sample_id,
        mode,
        rep,
        warmup,
        phase,
        (long)pid,
        seq,
        nr,
        syscall_name(nr),
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5],
        args[6],
        args[7]
    );
    if (have_ret) {
        printf(" ret=0x%016lx", ret);
    }
    printf(" path_hex=");
    print_hex_text(path);
    putchar('\n');
}

static int read_proc_link(pid_t pid, const char *name, char *out, size_t out_len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);
    ssize_t count = readlink(path, out, out_len - 1);
    if (count < 0) {
        out[0] = '\0';
        return -1;
    }
    out[count] = '\0';
    return 0;
}

static int read_proc_first_line(pid_t pid, const char *name, char *out, size_t out_len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/%s", (long)pid, name);
    FILE *handle = fopen(path, "r");
    if (handle == NULL) {
        out[0] = '\0';
        return -1;
    }
    if (fgets(out, (int)out_len, handle) == NULL) {
        fclose(handle);
        out[0] = '\0';
        return -1;
    }
    fclose(handle);
    strip_newline(out);
    return 0;
}

static long read_proc_tgid(pid_t pid) {
    char path[64];
    char line[256];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
    FILE *handle = fopen(path, "r");
    if (handle == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), handle) != NULL) {
        long tgid = -1;
        if (sscanf(line, "Tgid:%ld", &tgid) == 1) {
            fclose(handle);
            return tgid;
        }
    }
    fclose(handle);
    return -1;
}

static int emit_process_line(const char *role, pid_t pid, const char *status) {
    char comm[128];
    char exe[512];
    int comm_ok = read_proc_first_line(pid, "comm", comm, sizeof(comm)) == 0;
    int exe_ok = read_proc_link(pid, "exe", exe, sizeof(exe)) == 0;
    long tgid = read_proc_tgid(pid);
    printf(
        "RVMT_RUNTIME_PROCESS role=%s pid=%ld tgid=%ld status=%s comm_hex=",
        role,
        (long)pid,
        tgid,
        status
    );
    print_hex_text(comm_ok ? comm : "");
    printf(" exe_hex=");
    print_hex_text(exe_ok ? exe : "");
    putchar('\n');
    return comm_ok && exe_ok && tgid >= 0 ? 0 : -1;
}

static int emit_process_maps(const char *role, pid_t pid) {
    char path[64];
    char line[1024];
    int count = 0;
    snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
    FILE *handle = fopen(path, "r");
    if (handle == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), handle) != NULL) {
        unsigned long start = 0;
        unsigned long end = 0;
        unsigned long offset = 0;
        unsigned long long inode = 0;
        char perms[8] = "";
        char dev[32] = "";
        int path_offset = 0;
        int parsed = sscanf(line, "%lx-%lx %7s %lx %31s %llu %n", &start, &end, perms, &offset, dev, &inode, &path_offset);
        if (parsed < 6) {
            continue;
        }
        char *map_path = line + path_offset;
        while (*map_path == ' ' || *map_path == '\t') {
            ++map_path;
        }
        strip_newline(map_path);
        printf(
            "RVMT_RUNTIME_PROCESS_MAP_ENTRY role=%s start=0x%08lx end=0x%08lx perms=%s offset=0x%08lx dev=%s inode=%llu path_hex=",
            role,
            start,
            end,
            perms,
            offset,
            dev,
            inode
        );
        print_hex_text(map_path);
        putchar('\n');
        ++count;
    }
    fclose(handle);
    return count > 0 ? 0 : -1;
}

static void emit_static_process_owners(void) {
    puts("RVMT_RUNTIME_PROCESS role=kernel pid=0 tgid=0 status=PASS comm_hex=6b65726e656c exe_hex=");
    puts("RVMT_RUNTIME_PROCESS_MAP_ENTRY role=kernel start=0xc0000000 end=0xffffffff perms=r-xp offset=0x00000000 dev=kernel inode=0 path_hex=6c696e75785f6b65726e656c");
    puts("RVMT_RUNTIME_PROCESS role=unknown pid=-1 tgid=-1 status=PASS comm_hex=756e6b6e6f776e exe_hex=");
}

static int wait_for_stop(pid_t pid, int *status_out) {
    int status = 0;
    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    if (!WIFSTOPPED(status)) {
        return -1;
    }
    *status_out = status;
    return 0;
}

static void exec_sample_child(const sample_spec_t *sample) {
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

static pid_t start_sample_at_exec_stop(const sample_spec_t *sample, int syscall_side_channel, char *warning, size_t warning_len) {
    pid_t pid = fork();
    if (pid < 0) {
        snprintf(warning, warning_len, "fork_failed_errno_%d", errno);
        return -1;
    }
    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            _exit(126);
        }
        raise(SIGSTOP);
        exec_sample_child(sample);
    }

    int status = 0;
    if (wait_for_stop(pid, &status) != 0) {
        snprintf(warning, warning_len, "initial_ptrace_stop_failed");
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return -1;
    }
    long ptrace_options = PTRACE_O_TRACEEXEC;
    if (syscall_side_channel) {
        ptrace_options |= PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                          PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXIT;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)(uintptr_t)ptrace_options) != 0) {
        snprintf(warning, warning_len, "ptrace_setoptions_failed_errno_%d", errno);
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return -1;
    }
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        snprintf(warning, warning_len, "ptrace_cont_exec_failed_errno_%d", errno);
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return -1;
    }
    if (wait_for_stop(pid, &status) != 0) {
        snprintf(warning, warning_len, "exec_ptrace_stop_failed");
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return -1;
    }
    if (WSTOPSIG(status) != SIGTRAP || ((unsigned int)status >> 16) != PTRACE_EVENT_EXEC) {
        snprintf(warning, warning_len, "unexpected_exec_stop_status_%d", status);
        kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        return -1;
    }
    warning[0] = '\0';
    return pid;
}

static void regs_to_args(const struct user_regs_struct *regs, unsigned long *args) {
    args[0] = (unsigned long)regs->a0;
    args[1] = (unsigned long)regs->a1;
    args[2] = (unsigned long)regs->a2;
    args[3] = (unsigned long)regs->a3;
    args[4] = (unsigned long)regs->a4;
    args[5] = (unsigned long)regs->a5;
    args[6] = (unsigned long)regs->a6;
    args[7] = (unsigned long)regs->a7;
}

static int read_user_regs(pid_t pid, struct user_regs_struct *regs) {
    memset(regs, 0, sizeof(*regs));
#ifdef PTRACE_GETREGSET
    struct iovec iov;
    iov.iov_base = regs;
    iov.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == 0) {
        return 0;
    }
#endif
#ifdef PTRACE_GETREGS
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == 0) {
        return 0;
    }
#endif
    return -1;
}

static int continue_syscall(pid_t pid, int signal_to_deliver) {
    if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(uintptr_t)signal_to_deliver) != 0) {
        if (errno == ESRCH) {
            return 0;
        }
        perror("ptrace syscall");
        return -1;
    }
    return 0;
}

static int wait_sample_exit_with_syscalls(
    pid_t root_pid,
    const sample_spec_t *sample,
    const char *mode,
    unsigned long rep,
    int warmup
) {
    traced_pid_t tracked[RVMT_MAX_TRACED_PIDS];
    memset(tracked, 0, sizeof(tracked));
    traced_pid_t *root_slot = tracked_add(tracked, root_pid);
    if (root_slot != NULL) {
        root_slot->in_syscall = 1;
        root_slot->nr = RVMT_SC_EXECVE;
        root_slot->seq = 0;
    }

    if (continue_syscall(root_pid, 0) != 0) {
        kill(root_pid, SIGKILL);
        return 127;
    }

    int root_exit_code = 127;
    int root_done = 0;
    while (tracked_count(tracked) > 0) {
        int status = 0;
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == ECHILD) {
                break;
            }
            perror("waitpid");
            return 127;
        }

        traced_pid_t *slot = tracked_slot(tracked, pid);
        if (slot == NULL) {
            slot = tracked_add(tracked, pid);
        }

        if (WIFEXITED(status)) {
            if (pid == root_pid) {
                root_exit_code = WEXITSTATUS(status);
                root_done = 1;
            }
            tracked_remove(tracked, pid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (pid == root_pid) {
                root_exit_code = 128 + WTERMSIG(status);
                root_done = 1;
            }
            tracked_remove(tracked, pid);
            continue;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        int stop_signal = WSTOPSIG(status);
        unsigned int ptrace_event = ((unsigned int)status) >> 16;
        if (ptrace_event == PTRACE_EVENT_CLONE || ptrace_event == PTRACE_EVENT_FORK || ptrace_event == PTRACE_EVENT_VFORK) {
            unsigned long child_pid = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &child_pid) == 0 && child_pid > 0) {
                (void)tracked_add(tracked, (pid_t)child_pid);
            }
            if (continue_syscall(pid, 0) != 0) {
                return 127;
            }
            continue;
        }
        if (ptrace_event == PTRACE_EVENT_EXEC) {
            if (continue_syscall(pid, 0) != 0) {
                return 127;
            }
            continue;
        }
        if (ptrace_event == PTRACE_EVENT_EXIT) {
            if (continue_syscall(pid, 0) != 0) {
                return 127;
            }
            continue;
        }

        if (stop_signal == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (read_user_regs(pid, &regs) != 0) {
                perror("ptrace getregset");
                return 127;
            }
            if (slot == NULL) {
                slot = tracked_add(tracked, pid);
            }
            if (slot == NULL) {
                if (continue_syscall(pid, 0) != 0) {
                    return 127;
                }
                continue;
            }
            unsigned long args[8];
            regs_to_args(&regs, args);
            if (!slot->in_syscall) {
                slot->in_syscall = 1;
                slot->nr = (unsigned long)regs.a7;
                memcpy(slot->args, args, sizeof(slot->args));
                slot->seq += 1;
                emit_syscall_obs(sample, mode, rep, warmup, "entry", pid, slot->seq, slot->nr, slot->args, 0, 0);
            } else {
                if (slot->seq != 0) {
                    emit_syscall_obs(sample, mode, rep, warmup, "return", pid, slot->seq, slot->nr, slot->args, (unsigned long)regs.a0, 1);
                }
                slot->in_syscall = 0;
            }
            if (continue_syscall(pid, 0) != 0) {
                return 127;
            }
            continue;
        }

        int deliver = stop_signal == SIGTRAP ? 0 : stop_signal;
        if (continue_syscall(pid, deliver) != 0) {
            return 127;
        }
    }
    return root_done ? root_exit_code : 127;
}

static int wait_sample_exit(pid_t pid) {
    int status = 0;
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) != 0) {
        perror("ptrace detach");
        kill(pid, SIGKILL);
    }
    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
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

static void emit_runtime_process_map(
    const sample_spec_t *sample,
    const char *mode,
    unsigned long rep,
    int warmup,
    pid_t target_pid,
    const char *status,
    const char *warning
) {
    int target_ok = target_pid > 0;
    int runner_ok = 1;
    printf(
        "RVMT_RUNTIME_PROCESS_MAP_BEGIN schema=rvmt.runtime_process_map.v1 class=%s sample=%s mode=%s rep=%lu warmup=%d\n",
        sample->sample_class,
        sample->sample_id,
        mode,
        rep,
        warmup
    );
    if (emit_process_line("runner_parent", getpid(), "PASS") != 0 || emit_process_maps("runner_parent", getpid()) != 0) {
        runner_ok = 0;
    }
    if (target_pid > 0) {
        if (emit_process_line("target_child", target_pid, status) != 0 || emit_process_maps("target_child", target_pid) != 0) {
            target_ok = 0;
        }
    } else {
        puts("RVMT_RUNTIME_PROCESS role=target_child pid=-1 tgid=-1 status=BLOCKED comm_hex= exe_hex=");
    }
    emit_static_process_owners();
    printf("RVMT_RUNTIME_PROCESS_PROVENANCE collector=rvmt_exp_runner method=ptrace_exec_stop_procfs_snapshot proc_sample_time=post_exec_pre_detach status=%s warnings_hex=", (target_ok && runner_ok && strcmp(status, "PASS") == 0) ? "PASS" : "BLOCKED");
    print_hex_text(warning == NULL ? "" : warning);
    putchar('\n');
    printf("RVMT_RUNTIME_PROCESS_MAP_END status=%s\n", (target_ok && runner_ok && strcmp(status, "PASS") == 0) ? "PASS" : "BLOCKED");
}

static int run_sample(const sample_spec_t *sample) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 127;
    }
    if (pid == 0) {
        exec_sample_child(sample);
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
            (void)csr[RVMT_TRACE_READ_WORD_WORD];
            printf(" %08" PRIx32, csr[RVMT_TRACE_READ_WORD_WORD]);
        }
        putchar('\n');
    }
    puts("RVMT_TRACE_DUMP_END");
}

static int sample_selected(const sample_spec_t *sample, int argc, char **argv, int first_index) {
    if (first_index >= argc) {
        return sample->default_enabled;
    }
    for (int i = first_index; i < argc; ++i) {
        if (strcmp(argv[i], sample->sample_id) == 0) {
            return 1;
        }
        if (sample->default_enabled && strcmp(argv[i], sample->sample_class) == 0) {
            return 1;
        }
    }
    return 0;
}

static runner_options_t parse_runner_options(int argc, char **argv) {
    runner_options_t opts;
    opts.control_mask = RVMT_TRACE_DEFAULT_PROFILE_MASK;
    opts.warmup = 0;
    opts.syscall_side_channel = 0;
    opts.first_sample_arg = 5;

    int index = 5;
    while (index < argc) {
        if (strcmp(argv[index], "--control-mask") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "--control-mask requires a value\n");
                exit(2);
            }
            opts.control_mask = parse_ulong(argv[index + 1], "control-mask");
            index += 2;
            continue;
        }
        if (strcmp(argv[index], "--warmup") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "--warmup requires a value\n");
                exit(2);
            }
            opts.warmup = parse_ulong(argv[index + 1], "warmup");
            index += 2;
            continue;
        }
        if (strcmp(argv[index], "--syscall-side-channel") == 0) {
            opts.syscall_side_channel = 1;
            index += 1;
            continue;
        }
        break;
    }
    opts.first_sample_arg = index;
    return opts;
}

static void run_one_rep(
    volatile uint32_t *csr,
    const sample_spec_t *sample,
    unsigned long records,
    unsigned long rep,
    const char *mode,
    int trace_on,
    int warmup,
    unsigned long order_index,
    uint32_t control_mask,
    int syscall_side_channel
) {
    printf(
        "RVMT_EXP_REP_BEGIN class=%s sample=%s mode=%s rep=%lu order_index=%lu warmup=%d\n",
        sample->sample_class,
        sample->sample_id,
        mode,
        rep,
        order_index,
        warmup
    );
    trace_set_mode(csr, 0, control_mask, 1);
    char attribution_warning[128];
    attribution_warning[0] = '\0';
    pid_t traced_pid = -1;
    if (trace_on) {
        traced_pid = start_sample_at_exec_stop(sample, syscall_side_channel, attribution_warning, sizeof(attribution_warning));
        emit_runtime_process_map(
            sample,
            mode,
            rep,
            warmup,
            traced_pid,
            traced_pid > 0 ? "PASS" : "BLOCKED",
            traced_pid > 0 ? "" : attribution_warning
        );
    }

    if (trace_on) {
        trace_set_mode(csr, 1, control_mask, 0);
    }
    if (trace_on && (control_mask & RVMT_TRACE_CONTROL_MARKER)) {
        trace_emit_marker(csr, marker_value(RVMT_MARKER_BEGIN_TAG, sample, rep));
    }
    uint64_t start = monotonic_ns();
    int exit_code = traced_pid > 0
                        ? (syscall_side_channel
                               ? wait_sample_exit_with_syscalls(traced_pid, sample, mode, rep, warmup)
                               : wait_sample_exit(traced_pid))
                        : run_sample(sample);
    uint64_t end = monotonic_ns();
    if (trace_on && (control_mask & RVMT_TRACE_CONTROL_MARKER)) {
        trace_emit_marker(csr, marker_value(RVMT_MARKER_END_TAG, sample, rep));
    }
    uint32_t count = csr[RVMT_TRACE_COUNT_WORD];
    uint32_t drop = csr[RVMT_TRACE_DROP_WORD];
    trace_set_mode(csr, 0, control_mask, 0);
    printf(
        "RVMT_EXP_REP_RESULT class=%s sample=%s mode=%s rep=%lu order_index=%lu warmup=%d exit=%d runtime_ns=%" PRIu64 " trace_count=%" PRIu32 " drop=%" PRIu32 "\n",
        sample->sample_class,
        sample->sample_id,
        mode,
        rep,
        order_index,
        warmup,
        exit_code,
        end - start,
        count,
        drop
    );
    if (trace_on) {
        dump_trace(csr, records);
    }
    printf(
        "RVMT_EXP_REP_END class=%s sample=%s mode=%s rep=%lu order_index=%lu warmup=%d\n",
        sample->sample_class,
        sample->sample_id,
        mode,
        rep,
        order_index,
        warmup
    );
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <trace-csr-base> <records> <reps> <trace-on|trace-off|abba> [--control-mask hex] [--warmup n] [--syscall-side-channel] [sample-id|class ...]\n", argv[0]);
        return 2;
    }

    unsigned long csr_base = parse_ulong(argv[1], "trace-csr-base");
    unsigned long records = parse_ulong(argv[2], "records");
    unsigned long reps = parse_ulong(argv[3], "reps");
    int trace_on = strcmp(argv[4], "trace-on") == 0;
    int abba = strcmp(argv[4], "abba") == 0;
    if (!trace_on && strcmp(argv[4], "trace-off") != 0 && !abba) {
        fprintf(stderr, "mode must be trace-on, trace-off, or abba\n");
        return 2;
    }
    runner_options_t opts = parse_runner_options(argc, argv);
    uint32_t control_mask = (uint32_t)opts.control_mask;

    unsigned long map_len = 0;
    unsigned long page_off = 0;
    volatile uint32_t *csr = map_trace_csr(csr_base, &map_len, &page_off);
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf(
        "RVMT_EXP_BEGIN mode=%s reps=%lu warmup=%lu records=%lu csr_base=0x%08lx control_mask=0x%08" PRIx32 " syscall_side_channel=%d\n",
        argv[4],
        reps,
        opts.warmup,
        records,
        csr_base,
        control_mask,
        opts.syscall_side_channel
    );
    for (size_t sample_index = 0; sample_index < sizeof(samples) / sizeof(samples[0]); ++sample_index) {
        const sample_spec_t *sample = &samples[sample_index];
        if (!sample_selected(sample, argc, argv, opts.first_sample_arg)) {
            continue;
        }
        printf("RVMT_EXP_SAMPLE_BEGIN class=%s sample=%s mode=%s\n", sample->sample_class, sample->sample_id, argv[4]);
        unsigned long order_index = 0;
        if (abba) {
            for (unsigned long warm = 0; warm < opts.warmup; ++warm) {
                run_one_rep(csr, sample, records, warm, "trace-off", 0, 1, order_index++, control_mask, opts.syscall_side_channel);
                run_one_rep(csr, sample, records, warm, "trace-on", 1, 1, order_index++, control_mask, opts.syscall_side_channel);
            }
            for (unsigned long rep = 0; rep < reps; ++rep) {
                if ((rep & 1u) == 0u) {
                    run_one_rep(csr, sample, records, rep, "trace-off", 0, 0, order_index++, control_mask, opts.syscall_side_channel);
                    run_one_rep(csr, sample, records, rep, "trace-on", 1, 0, order_index++, control_mask, opts.syscall_side_channel);
                } else {
                    run_one_rep(csr, sample, records, rep, "trace-on", 1, 0, order_index++, control_mask, opts.syscall_side_channel);
                    run_one_rep(csr, sample, records, rep, "trace-off", 0, 0, order_index++, control_mask, opts.syscall_side_channel);
                }
            }
        } else {
            const char *mode = trace_on ? "trace-on" : "trace-off";
            for (unsigned long warm = 0; warm < opts.warmup; ++warm) {
                run_one_rep(csr, sample, records, warm, mode, trace_on, 1, order_index++, control_mask, opts.syscall_side_channel);
            }
            for (unsigned long rep = 0; rep < reps; ++rep) {
                run_one_rep(csr, sample, records, rep, mode, trace_on, 0, order_index++, control_mask, opts.syscall_side_channel);
            }
        }
        printf("RVMT_EXP_SAMPLE_END class=%s sample=%s mode=%s\n", sample->sample_class, sample->sample_id, argv[4]);
    }
    puts("RVMT_EXP_END status=PASS");

    munmap((void *)((uintptr_t)csr - page_off), map_len);
    return 0;
}
