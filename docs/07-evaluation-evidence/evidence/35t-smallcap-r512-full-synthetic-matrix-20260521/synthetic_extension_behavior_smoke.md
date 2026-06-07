# 35T Synthetic Extension Behavior Smoke: 35t-extension-behavior-smoke-20260523

Status: HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED

Extension plan: `experiments/linux_behavior/malware_like/extension_plan.json`
Results root: `results/experiments/35t/35t-extension-behavior-smoke-20260523`

Current condition: non-network synthetic extension candidates compile and execute under host native, host strace, QEMU native, and QEMU strace smoke paths; loopback network candidate remains skipped unless explicitly selected; no 35T board run or expanded gate pass is claimed

## Checks

- plan_schema: PASS
- candidate_count_9: PASS
- non_network_candidate_count_8: PASS
- loopback_network_candidate_skipped: PASS
- all_candidates_default_disabled: PASS
- container_command_passed: PASS
- container_json_present: PASS
- tools_available: PASS
- compile_result_count_matches: PASS
- compile_all_candidates: PASS
- executed_non_network_candidates: PASS
- expected_syscalls_observed_for_executed: PASS
- host_and_qemu_paths_recorded: PASS
- no_35t_execution_claim: PASS
- no_expanded_35t_coverage_claim: PASS

## Summary

- candidate_count: 9
- compile_pass_count: 9
- executed_candidate_count: 8
- execution_pass_count: 8
- network_skipped_count: 1

## Samples

- `direct_syscall_open_read`: compile=PASS execute=PASS observed=close, openat, read, write missing=none
- `timing_anti_analysis_loop`: compile=PASS execute=PASS observed=clock_gettime, close, openat, read missing=none
- `proc_status_tracerpid_check`: compile=PASS execute=PASS observed=close, openat, read missing=none
- `obfuscated_syscall_wrapper`: compile=PASS execute=PASS observed=close, openat, read, write missing=none
- `self_modifying_code_sim`: compile=PASS execute=PASS observed=mmap, mprotect, munmap missing=none
- `mprotect_exec_variant`: compile=PASS execute=PASS observed=mmap, mprotect, munmap missing=none
- `multi_level_process_chain`: compile=PASS execute=PASS observed=clone, execve, waitid missing=none
- `loopback_network_client`: compile=PASS execute=SKIPPED_NETWORK_OPTIONAL observed=none missing=close, connect, socket
- `file_encryption_sim_non_destructive`: compile=PASS execute=PASS observed=close, openat, read, write missing=none

## Remaining Work

- refresh the Artix-7 rootfs image with selected extension binaries if the current board image does not already contain them
- run selected extension candidates on the Artix-7 35T board with the same trace-off/trace-on ordering
- analyze extension traces and apply marker, attribution, DROP, capacity, and strong-evidence gates
- keep loopback-network extension disabled unless an explicit loopback-only fixture is selected

## Interpretation

- this smoke test upgrades the extension evidence from compile/dry-run only to host and QEMU execution evidence for non-network candidates
- QEMU strace guest syscall coverage is used only as pre-board behavior evidence
- the default 13-sample 35T matrix remains unchanged because extension candidates are still default-disabled
- expanded 35T coverage remains deferred until board execution and gate evidence are recorded

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no expanded 35T coverage claim
- no 35T execution or gate pass claim
