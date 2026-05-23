# 35T Extension Gate Check: 35t-extension-r512-nonnetwork-20260523

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv.

## Checks

- results_root_exists: PASS
- gate_report_available_or_derived: PASS
- metrics_exists: PASS
- run_config_exists: PASS
- expected_samples_present: PASS
- loopback_network_client_excluded: PASS
- all_samples_pass: PASS
- trace_records_512: PASS
- trace_profile_policy_35t_small_capacity: PASS
- runtime_order_abba: PASS
- real_malware_forbidden: PASS
- network_disabled: PASS
- include_extension_samples_explicit: PASS

## Samples

| Sample | Status | Gate | DROP median | Evidence | Matched expected |
| --- | --- | --- | ---: | --- | --- |
| `direct_syscall_open_read` | `PASS` | `PASS` | 0.0 | `semantic_trace+syscall_side_channel_auxiliary` | `direct_syscall_file_access` |
| `file_encryption_sim_non_destructive` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `non_destructive_file_encryption_simulation` |
| `mprotect_exec_variant` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `dynamic_executable_memory_variant` |
| `multi_level_process_chain` | `PASS` | `PASS` | 0.0 | `semantic_trace+syscall_side_channel_auxiliary` | `multi_level_process_creation_chain` |
| `obfuscated_syscall_wrapper` | `PASS` | `PASS` | 0.0 | `semantic_trace+syscall_side_channel_auxiliary` | `obfuscated_syscall_sequence` |
| `proc_status_tracerpid_check` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `proc_status_anti_debug_check` |
| `self_modifying_code_sim` | `PASS` | `PASS` | 0.0 | `behavior_audit` | `self_modifying_memory_simulation` |
| `timing_anti_analysis_loop` | `PASS` | `PASS` | 0.0 | `semantic_trace+syscall_side_channel_auxiliary` | `timing_anti_analysis_indicator` |

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- extension gate is reported separately from the primary 13-sample gate
