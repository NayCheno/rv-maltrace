#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <unistd.h>

static int read_tracer_pid(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == NULL) {
        return -1;
    }
    char line[256];
    int tracer_pid = -1;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer_pid = atoi(line + 10);
            break;
        }
    }
    fclose(fp);
    return tracer_pid;
}

static void read_comm(pid_t pid, char *out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    snprintf(out, out_len, "unknown");
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return;
    }
    if (fgets(out, (int)out_len, fp) == NULL) {
        snprintf(out, out_len, "unreadable");
    }
    fclose(fp);
    out[out_len - 1] = '\0';
    for (size_t i = 0; out[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)out[i];
        if (ch == '\n' || ch == '\r') {
            out[i] = '\0';
            break;
        }
        if (!isalnum(ch) && ch != '_' && ch != '-' && ch != '.') {
            out[i] = '_';
        }
    }
}

int main(void) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        memset(&uts, 0, sizeof(uts));
        snprintf(uts.sysname, sizeof(uts.sysname), "unknown");
        snprintf(uts.machine, sizeof(uts.machine), "unknown");
    }

    char parent_comm[128];
    char self_comm[128];
    read_comm(getppid(), parent_comm, sizeof(parent_comm));
    read_comm(getpid(), self_comm, sizeof(self_comm));

    int tracer_pid = read_tracer_pid();
    errno = 0;
    long ptrace_rc = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    int ptrace_errno = errno;

    printf(
        "RVMT_TRACER_VISIBILITY pid=%ld ppid=%ld tracer_pid=%d "
        "ptrace_traceme_rc=%ld ptrace_errno=%d parent_comm=%s self_comm=%s "
        "uname_sysname=%s uname_machine=%s\n",
        (long)getpid(),
        (long)getppid(),
        tracer_pid,
        ptrace_rc,
        ptrace_errno,
        parent_comm,
        self_comm,
        uts.sysname,
        uts.machine);
    return 0;
}
