# 35T Extension Enablement Preflight: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED

Current condition: synthetic extension candidates are present in the 35T runner table, default-disabled, compiled by the Artix-7 rootfs build script, and selectable through explicit experiment dry-run commands; no extension candidate has been executed on the 35T board or passed the gate

## Checks

- plan_schema: PASS
- candidate_count_9: PASS
- non_network_candidates_selected: PASS
- network_candidate_remains_optional: PASS
- plan_default_disabled: PASS
- runner_declares_all_candidates: PASS
- runner_candidates_default_disabled: PASS
- runner_base_class_selection_still_default_only: PASS
- rootfs_build_compiles_extension_programs: PASS
- experiment_supports_explicit_extensions: PASS
- target_smoke_passed: PASS
- default_dry_run_passed: PASS
- default_dry_run_excludes_extensions: PASS
- explicit_dry_run_passed: PASS
- explicit_dry_run_selects_non_network_extensions: PASS
- explicit_dry_run_network_disabled: PASS
- explicit_dry_run_commands_reference_selected_ids: PASS
- no_board_execution_attempted: PASS
- no_expanded_35t_claim: PASS

## Selected Non-network Candidates

- `direct_syscall_open_read`
- `file_encryption_sim_non_destructive`
- `mprotect_exec_variant`
- `multi_level_process_chain`
- `obfuscated_syscall_wrapper`
- `proc_status_tracerpid_check`
- `self_modifying_code_sim`
- `timing_anti_analysis_loop`

## Optional Network Candidates

- `loopback_network_client`

## Dry-run Command Excerpt

```text
+ send: root
+ send: cd /opt/rvmt
+ send: /usr/bin/rvmt_exp_runner 0xf0004000 512 1 abba --control-mask 0x424 --warmup 0 direct_syscall_open_read timing_anti_analysis_loop proc_status_tracerpid_check obfuscated_syscall_wrapper self_modifying_code_sim mprotect_exec_variant multi_level_process_chain file_encryption_sim_non_destructive
```

## Remaining Work

- build or refresh the 35T rootfs image that includes the extension binaries
- run selected extension candidates on the Artix-7 35T board with trace-off/trace-on ordering
- analyze the resulting trace artifacts and apply marker, attribution, DROP, capacity, and strong-evidence gates
- keep loopback-network extension disabled unless an explicit loopback-only fixture is selected

## Interpretation

- this preflight closes the runner/rootfs/CLI enablement gap for explicit non-network extension candidates
- the default 13-sample 35T matrix remains unchanged because extension candidates are default-disabled
- this is still not expanded 35T coverage evidence and cannot replace a board gate run

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
