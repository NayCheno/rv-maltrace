# 35T Hardware Trace Prototype Check: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY

Trace records: 512

Trace profile policy: 35t_small_capacity

Samples PASS: 13/13

Decoded trace files: 65

## Checks

- assessment_lists_hardware_trace_gate: PASS
- results_root_exists: PASS
- gate_schema: PASS
- gate_run_id: PASS
- gate_claim_level: PASS
- gate_trace_records_512: PASS
- run_config_trace_records_512: PASS
- run_config_reps_5: PASS
- trace_profile_policy: PASS
- sample_set_exact: PASS
- sample_count_13: PASS
- per_sample_profiles: PASS
- per_sample_control_masks: PASS
- trace_controls_small_capacity: PASS
- real_malware_forbidden_network_disabled: PASS
- all_samples_gate_pass: PASS
- all_samples_marker_scope_pass: PASS
- all_samples_runtime_attribution_pass: PASS
- all_samples_unknown_corrupt_zero: PASS
- all_samples_drop_within_limit: PASS
- all_samples_no_cap_hit: PASS
- decoded_trace_artifacts_65: PASS
- decoded_trace_artifacts_nonempty: PASS

## Samples

| Sample | Class | Profile | Gate | DROP median | Decoded traces | Failures |
| --- | --- | --- | --- | ---: | ---: | --- |
| `hello` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `ls` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `cat` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `cp` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `sha256sum` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `file_scan` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `batch_open_read_write` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `self_copy_sim` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `illegal_trap` | `malware_like_synthetic` | `p0c_syscall_trap_drop` | `PASS` | 0.03067484662576687 | 5 | none |
| `process_chain` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `dynamic_executable_memory` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |
| `anti_debug_like` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | 5 | none |

## Evidence

- gate_report: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.json`
- run_config: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json`
- evidence_root: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521`

## Interpretation

- the primary 35T run is a 512-record small-capacity full-matrix hardware trace gate
- the pass result comes from per-sample minimal trace profiles, not from increasing the trace ring beyond the 35T budget
- illegal_trap alone uses the trap-enabled profile; the other 12 samples use the syscall/drop profile

## Boundaries

- 35T / LiteX / VexRiscv only; no CVA6 board claim
- decoded trace artifacts are local evidence and large raw UART logs remain outside the lightweight snapshot
- hardware trace evidence supports the prototype trace gate, not complete semantic reconstruction by itself

## Failures

- none
