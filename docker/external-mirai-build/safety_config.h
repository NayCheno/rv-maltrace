/*
 * safety_config.h — Safety de-fanging configuration for external Mirai source.
 *
 * This header provides compile-time adaptations for RISC-V and safe defaults.
 * Dangerous function overrides are provided via safety_stubs.c at link time
 * (strong definitions override libc weak definitions).
 *
 * Reference: gbrindisi/malware/linux/mirai/mirai/bot/*
 */

#ifndef MIRAI_SAFETY_CONFIG_H
#define MIRAI_SAFETY_CONFIG_H

/* Architecture adaptation */
#define MIRAI_BOT_ARCH "riscv64"

/* Network safety: redirect FAKE_CNC_ADDR to loopback.
   Must be defined before includes.h defines its own FAKE_CNC_ADDR. */
#define FAKE_CNC_ADDR INET_ADDR(127,0,0,1)

/* Reduce CNC connection timeout (original: 30s) */
#define CNC_CONNECT_TIMEOUT 2

/* Pre-declare safety stubs so the Mirai source knows these exist */
/* These are strong definitions in safety_stubs.c that override libc */

#endif /* MIRAI_SAFETY_CONFIG_H */
