/*
 * safety_stubs.c — Link-time safety overrides for dangerous libc functions.
 *
 * Compiled alongside the external Mirai source to replace destructive
 * system calls with safe no-ops.  Strong definitions here override libc's
 * weak/default definitions during static linking.
 *
 * Preserved behaviors (observable syscalls):
 *   - open, read, write, close (file I/O for /proc scanning)
 *   - socket, bind, listen, connect (loopback-only network shape)
 *   - prctl (process name observation)
 *   - mmap, mprotect, munmap (memory operations)
 *
 * Disabled behaviors:
 *   - fork, setsid, chdir (daemonization)
 *   - kill (process termination)
 *   - unlink (self-deletion)
 *   - SOCK_RAW sockets (credential brute-force scanning)
 *   - Actual C2 connections (FAKE_CNC_ADDR→loopback via config)
 *   - DDoS attack vector execution (stubbed in code)
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

/* --- Daemonization stubs --- */

pid_t fork(void) {
    /* Return 0 to fake successful fork in child.
       The original Mirai code checks `if (fork() > 0) exit(0);`
       With this stub, the "child" continues and the "parent" path is skipped. */
    return 0;
}

pid_t setsid(void) {
    /* Return the current PID as if we became session leader. */
    return getpid();
}

int chdir(const char *path) {
    (void)path;
    return 0;  /* success */
}

/* --- Self-deletion stub --- */

int unlink(const char *pathname) {
    (void)pathname;
    return 0;  /* success — pretend we deleted the file */
}

/* --- Process termination stub --- */

int kill(pid_t pid, int sig) {
    (void)pid;
    (void)sig;
    return 0;  /* success — pretend we sent the signal */
}
