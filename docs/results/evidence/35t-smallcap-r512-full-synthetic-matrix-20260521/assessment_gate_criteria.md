# 35T Assessment Gate Criteria: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: ASSESSMENT_GATE_CRITERIA_PASS

## Checks

- assessment_lists_gate_conditions: PASS
- gate_schema: PASS
- gate_run_id: PASS
- gate_claim_level: PASS
- trace_records_512: PASS
- trace_profile_policy: PASS
- sample_set_exact: PASS
- sample_count_13: PASS
- benign_malware_like_split: PASS
- sample_status_13_pass: PASS
- marker_scope_all_reps_pass: PASS
- runtime_process_attribution_all_reps_pass: PASS
- unknown_corrupt_zero_all_samples: PASS
- drop_within_limit_all_samples: PASS
- no_cap_hit_all_samples: PASS
- strong_expected_rules_all_malware_like: PASS
- ls_benign_overlap_bounded: PASS
- per_sample_profile_policy: PASS
- run_config_real_malware_forbidden: PASS
- malware_like_manifest_synthetic_non_network: PASS
- sample_matrix_summary_matches: PASS

## Samples

| Sample | Class | Profile | Gate | DROP median | Expected rule | Benign overlap | Failures |
| --- | --- | --- | --- | ---: | --- | --- | --- |
| `hello` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | none | none | none |
| `ls` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | none | many_file_scan | none |
| `cat` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | none | none | none |
| `cp` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | none | none | none |
| `sha256sum` | `benign` | `p0a_syscall_drop` | `PASS` | 0.0 | none | none | none |
| `file_scan` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | many_file_scan | none | none |
| `batch_open_read_write` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | batch_file_read_write | none | none |
| `self_copy_sim` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | self_copy_simulation | none | none |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | abnormal_syscall_sequence | none | none |
| `illegal_trap` | `malware_like_synthetic` | `p0c_syscall_trap_drop` | `PASS` | 0.03067484662576687 | illegal_instruction_trap | none | none |
| `process_chain` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | process_creation_chain | none | none |
| `dynamic_executable_memory` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | dynamic_executable_memory | none | none |
| `anti_debug_like` | `malware_like_synthetic` | `p0a_syscall_drop` | `PASS` | 0.0 | anti_analysis_indicator | none | none |

## Evidence

- gate_report: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.json`
- run_config: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json`
- sample_manifest: `experiments/linux_behavior/malware_like/manifest.json`
- sample_matrix_summary: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/sample_matrix_summary.json`

## Interpretation

- the 35T primary gate is a 512-record, 13-sample full-matrix PASS under the small-capacity profile policy
- marker scope and runtime process attribution pass for every trace-on repetition in the primary gate
- benign overlap is explicitly bounded to the ls directory traversal rule and is not a malware-detection claim

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no CVA6 board claim

## Failures

- none
