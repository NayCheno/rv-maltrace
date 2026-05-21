# 35T Semantic Failure Triage

- Run ID: `35t-smallcap-r512-full-synthetic-matrix-20260521`
- Artifact root: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521`
- Boundary: 35T/LiteX/VexRiscv synthetic behavior audit prototype only.
- Non-claims: no CVA6 board claim; no real malware detection claim; no mature detector claim.

| Sample | Gate | Failure class | Observed failure | Missing expected | Weak expected | Weak shapes | Unexpected matched | UNKNOWN/corrupt | Marker | Runtime process |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| `hello` | PASS | regression_fixed_or_not_observed | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `ls` | PASS | outside_focus_set | not classified | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `cat` | PASS | outside_focus_set | not classified | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `cp` | PASS | outside_focus_set | not classified | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `sha256sum` | PASS | outside_focus_set | not classified | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `file_scan` | PASS | expected_rule_stable | none | none | many_file_scan | many_file_scan_shape | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `batch_open_read_write` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `self_copy_sim` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `abnormal_syscall_sequence` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `illegal_trap` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `process_chain` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `dynamic_executable_memory` | PASS | expected_rule_stable | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |
| `anti_debug_like` | PASS | positive_regression_kept | none | none | none | none | none | 0/0 | PASS (5/5) | PASS (5/5) |

## Promotion Checks

- `gate_status_pass`: True
- `process_chain_strong_expected`: True
- `illegal_trap_stable_expected_rule`: True
- `unexpected_strong_matched_none`: True
- `unknown_and_corrupt_events_zero`: True
- `drop_rate_median_lte_5pct`: True
- `no_cap_hit`: True
- `marker_scope_valid`: True
- `runtime_process_attribution_proven`: True
- `full_matrix_ready`: True
- `optimized_35t_small_capacity_matrix_ready`: True

- Blocked reasons: none

## Full Matrix Blockers

- Gate blockers: none for the optimized 35T-only full synthetic matrix.
- Scope remains synthetic-only and 35T/VexRiscv-only.
- This report does not claim real malware detection, CVA6 board validation, or mature semantic recovery.
