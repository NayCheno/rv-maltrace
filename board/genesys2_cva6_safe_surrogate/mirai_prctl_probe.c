/*
 * mirai_prctl_probe.c — Minimal prctl(PR_SET_NAME) probe for Genesys2 ILA capture.
 * Exercises the prctl syscall from the Mirai process-hiding behavior.
 */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
    prctl(PR_SET_NAME, "rvmt-mirai", 0, 0, 0);
    _exit(0);
}
