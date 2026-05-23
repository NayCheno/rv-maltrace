# 35T Advanced Baseline Preflight: 35t-advanced-baseline-preflight-20260523

Status: BLOCKED_CURRENT_ENVIRONMENT

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Baselines

| Baseline | Status | Reason |
| --- | --- | --- |
| `ebpf_only` | `READY` | docker_linux_behavior_cap_sys_admin: eBPF kprobe baseline prerequisites are present |
| `qemu_plugin` | `BLOCKED_CURRENT_ENVIRONMENT` | docker_linux_behavior: qemu-plugin.h is not installed in the current package set; docker_linux_behavior_cap_sys_admin: qemu-plugin.h is not installed in the current package set; wsl: neither qemu-riscv64 nor qemu-system-riscv64 is available in this probe environment; neither qemu-riscv64 nor qemu-system-riscv64 exposes -plugin in the current package; qemu-plugin.h is not installed in the current package set; wsl_root: neither qemu-riscv64 nor qemu-system-riscv64 is available in this probe environment; neither qemu-riscv64 nor qemu-system-riscv64 exposes -plugin in the current package; qemu-plugin.h is not installed in the current package set |

## Checks

### ebpf_only

Environment results:
- `docker_linux_behavior`: `BLOCKED_CURRENT_ENVIRONMENT` - tracefs is not mounted in this probe environment; kprobe_events is not visible through tracefs/debugfs; kprobe_events is not writable from this probe environment; bpftrace kprobe smoke did not run or did not capture events
- `docker_linux_behavior_cap_sys_admin`: `READY` - eBPF kprobe baseline prerequisites are present
- `wsl`: `BLOCKED_CURRENT_ENVIRONMENT` - bpftool/bpftrace loader or tracer tooling is not installed; kprobe_events is not visible through tracefs/debugfs; kprobe_events is not writable from this probe environment; bpftrace kprobe smoke did not run or did not capture events
- `wsl_root`: `BLOCKED_CURRENT_ENVIRONMENT` - bpftool/bpftrace loader or tracer tooling is not installed; bpftrace kprobe smoke did not run or did not capture events

- container_command_passed: PASS
- bpf_compiler_available: PASS
- bpf_loader_or_tracer_available: PASS
- tracefs_mounted: PASS
- kprobe_events_available: PASS
- kprobe_events_writable: PASS
- bpftrace_smoke_passed: PASS

### qemu_plugin

Environment results:
- `docker_linux_behavior`: `BLOCKED_CURRENT_ENVIRONMENT` - qemu-plugin.h is not installed in the current package set
- `docker_linux_behavior_cap_sys_admin`: `BLOCKED_CURRENT_ENVIRONMENT` - qemu-plugin.h is not installed in the current package set
- `wsl`: `BLOCKED_CURRENT_ENVIRONMENT` - neither qemu-riscv64 nor qemu-system-riscv64 is available in this probe environment; neither qemu-riscv64 nor qemu-system-riscv64 exposes -plugin in the current package; qemu-plugin.h is not installed in the current package set
- `wsl_root`: `BLOCKED_CURRENT_ENVIRONMENT` - neither qemu-riscv64 nor qemu-system-riscv64 is available in this probe environment; neither qemu-riscv64 nor qemu-system-riscv64 exposes -plugin in the current package; qemu-plugin.h is not installed in the current package set

- docker_linux_behavior.container_command_passed: PASS
- docker_linux_behavior.qemu_riscv64_available: PASS
- docker_linux_behavior.qemu_system_riscv64_available: PASS
- docker_linux_behavior.qemu_user_exposes_plugin_option: FAIL
- docker_linux_behavior.qemu_system_exposes_plugin_option: PASS
- docker_linux_behavior.qemu_plugin_header_available: FAIL
- docker_linux_behavior_cap_sys_admin.container_command_passed: PASS
- docker_linux_behavior_cap_sys_admin.qemu_riscv64_available: PASS
- docker_linux_behavior_cap_sys_admin.qemu_system_riscv64_available: PASS
- docker_linux_behavior_cap_sys_admin.qemu_user_exposes_plugin_option: FAIL
- docker_linux_behavior_cap_sys_admin.qemu_system_exposes_plugin_option: PASS
- docker_linux_behavior_cap_sys_admin.qemu_plugin_header_available: FAIL
- wsl.container_command_passed: PASS
- wsl.qemu_riscv64_available: FAIL
- wsl.qemu_system_riscv64_available: FAIL
- wsl.qemu_user_exposes_plugin_option: FAIL
- wsl.qemu_system_exposes_plugin_option: FAIL
- wsl.qemu_plugin_header_available: FAIL
- wsl_root.container_command_passed: PASS
- wsl_root.qemu_riscv64_available: FAIL
- wsl_root.qemu_system_riscv64_available: FAIL
- wsl_root.qemu_user_exposes_plugin_option: FAIL
- wsl_root.qemu_system_exposes_plugin_option: FAIL
- wsl_root.qemu_plugin_header_available: FAIL

## Interpretation

- this preflight checks whether current local Docker and WSL environments can run the remaining advanced baselines
- READY or BLOCKED statuses are environment evidence, not completed baseline comparisons
- baseline prerequisites are evaluated per environment and are not combined across environments
- software instrumentation evidence is tracked separately and is not a substitute for eBPF-only or QEMU-plugin evidence

## Next Actions

- provide qemu-plugin.h plus either a plugin-capable qemu-riscv64 user-mode binary or a qemu-system-riscv64 harness before running qemu_plugin baseline

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
