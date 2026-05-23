# 35T QEMU-Plugin Build Preflight: 35t-qemu-plugin-build-preflight-20260523

Status: QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED

Environment: `docker_linux_behavior`

## Checks

- docker_probe_command_passed: PASS
- qemu_system_available: PASS
- qemu_system_exposes_plugin_option: PASS
- qemu_user_available: PASS
- qemu_user_plugin_option_missing: PASS
- header_fetched_from_official_qemu_gitlab: PASS
- header_sha256_matches_qemu_8_2_2: PASS
- plugin_compiled: PASS
- qemu_system_loads_plugin: PASS
- qemu_system_probe_timeout_expected: PASS

## Observed

- qemu-system: `/usr/bin/qemu-system-riscv64` (QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.16))
- qemu-user: `/usr/bin/qemu-riscv64` (qemu-riscv64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.16))
- plugin SO bytes: 15672
- header: `v8.2.2` sha256 `c53a2af163e80e3f4bc6c60dbdfc84003db329d757e37cd8a16a77e1d82606ff`

## Current Condition

- qemu-system-riscv64 can load a freshly built minimal QEMU TCG plugin when the matching official QEMU 8.2.2 plugin header is fetched at probe time; qemu-riscv64 user-mode still does not expose -plugin, and no 13-sample QEMU-plugin baseline is recorded

## Remaining Work

- provide a plugin-capable RISC-V user-mode QEMU or a qemu-system harness that can execute the 13 Linux samples
- record per-sample QEMU-plugin trace output and timing for all 13 samples
- keep qemu_native and qemu_strace timing separate from QEMU-plugin trace evidence

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no completed QEMU-plugin 13-sample baseline claim

## Failures

- none
