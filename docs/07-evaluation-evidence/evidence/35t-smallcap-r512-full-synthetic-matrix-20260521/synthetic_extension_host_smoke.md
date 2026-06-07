# 35T Synthetic Extension Host Smoke: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED

Extension plan: `experiments/linux_behavior/malware_like/extension_plan.json`

## Host

- platform: Windows
- compile_environment: wsl
- compiler: /usr/bin/cc
- wsl_compiler: /usr/bin/cc
- compile_attempted: True
- blocked_reasons: none

## Checks

- plan_schema: PASS
- plan_status_implemented_source: PASS
- candidates_declared: PASS
- candidate_statuses_implemented: PASS
- candidate_sources_declared: PASS
- candidate_sources_exist: PASS
- network_candidates_compile_only: PASS
- no_execution_attempted: PASS
- no_35t_gating_claim: PASS

## Sources

- `direct_syscall_open_read`: `experiments/linux_behavior/malware_like/extension_programs/direct_syscall_open_read.c` (present, non_network)
- `timing_anti_analysis_loop`: `experiments/linux_behavior/malware_like/extension_programs/timing_anti_analysis_loop.c` (present, non_network)
- `proc_status_tracerpid_check`: `experiments/linux_behavior/malware_like/extension_programs/proc_status_tracerpid_check.c` (present, non_network)
- `obfuscated_syscall_wrapper`: `experiments/linux_behavior/malware_like/extension_programs/obfuscated_syscall_wrapper.c` (present, non_network)
- `self_modifying_code_sim`: `experiments/linux_behavior/malware_like/extension_programs/self_modifying_code_sim.c` (present, non_network)
- `mprotect_exec_variant`: `experiments/linux_behavior/malware_like/extension_programs/mprotect_exec_variant.c` (present, non_network)
- `multi_level_process_chain`: `experiments/linux_behavior/malware_like/extension_programs/multi_level_process_chain.c` (present, non_network)
- `loopback_network_client`: `experiments/linux_behavior/malware_like/extension_programs/loopback_network_client.c` (present, network_optional)
- `file_encryption_sim_non_destructive`: `experiments/linux_behavior/malware_like/extension_programs/file_encryption_sim_non_destructive.c` (present, non_network)

## Compile Results

- `direct_syscall_open_read`: PASS returncode=0
- `timing_anti_analysis_loop`: PASS returncode=0
- `proc_status_tracerpid_check`: PASS returncode=0
- `obfuscated_syscall_wrapper`: PASS returncode=0
- `self_modifying_code_sim`: PASS returncode=0
- `mprotect_exec_variant`: PASS returncode=0
- `multi_level_process_chain`: PASS returncode=0
- `loopback_network_client`: PASS returncode=0
- `file_encryption_sim_non_destructive`: PASS returncode=0

## Interpretation

- this is a host compile-only smoke check for repository-owned synthetic extension sources
- the checker never executes the extension binaries and does not start loopback network activity
- a PASS means the extension sources compile on this host; it is still not a 35T run
- on Windows, a WSL compiler may satisfy the host compile-only condition when the repository is mounted and gcc/clang/cc is available
- a blocked status records that the current host lacks the Linux, WSL, or compiler conditions needed for compile smoke
- expanded 35T coverage remains deferred until these candidates are explicitly enabled, built for the target, and run through the same gates

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no expanded 35T coverage claim
