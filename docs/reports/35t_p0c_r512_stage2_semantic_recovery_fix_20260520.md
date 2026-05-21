# 35T p0c r512 Stage 2 semantic recovery fix - 2026-05-20

- Run id: `35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5`
- Artifact root: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5`
- Scope: offline analysis/report/gate/triage only, using existing board artifacts from the run above.
- Not run: Stage 3 `process_chain`, full matrix, case study generation, new COM5/921600 board collection.
- Pre-fix aggregate backup: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/aggregate_pre_fix_backup_20260521`

## Pre-fix vs post-fix gate

| Sample | Pre gate | Pre strong | Pre weak shape | Pre missing | Post gate | Post strong | Post weak shape | Post missing | Unexpected strong |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `file_scan` | FAIL | none | none | `many_file_scan` | PASS | none | `many_file_scan_shape` 5/5 | none | none |
| `self_copy_sim` | FAIL | none | none | `self_copy_simulation` | PASS | none | `self_copy_shape_without_path_tags` 5/5 | none | none |
| `abnormal_syscall_sequence` | FAIL | none | none | `abnormal_syscall_sequence` | PASS | `abnormal_syscall_sequence` 5/5 | none | none | none |
| `dynamic_executable_memory` | FAIL | none | none | `dynamic_executable_memory` | PASS | `dynamic_executable_memory` 5/5 | none | none | none |

## Root causes

| Sample | Root cause | Recovery result |
| --- | --- | --- |
| `file_scan` | p0c consistently recovered target `openat` plus repeated `getdents64`, but did not prove `close` in the target-scoped boundary. | Weak only: `many_file_scan_shape`. Strong `many_file_scan` remains blocked because `close` is required. |
| `self_copy_sim` | p0c provides copy syscall shape, but ARG_MEM/path evidence is disabled, so `self_path` and `executable_output` are not trace-proven. One `openat` also required conservative target-argument shape recovery when `a7` was stale. | Weak only: `self_copy_shape_without_path_tags`. Strong `self_copy_simulation` remains blocked on path/tag evidence and full fd-flow proof. |
| `abnormal_syscall_sequence` | Failed returns were present as RV32-style negative errno values such as `0xfffffff7`, but the audit only decoded 64-bit negative errno before the fix. | Strong: `abnormal_syscall_sequence` 5/5 after RV32 errno decoding. |
| `dynamic_executable_memory` | target `ecall` TRAP held the useful target arguments, while the following kernel `SYSCALL_ENTRY` held the reliable syscall nr. The old recovery split these, losing `mprotect.a2 & 0x4`. | Strong: `dynamic_executable_memory` 5/5 after target-argument/kernel-number fusion. |

## Strong and weak evidence boundary

- Strong matches still require the original rule's core semantic evidence.
- Weak matches are recorded separately in `weak_expected_behavior` and `weak_rule_stability`.
- `illegal_instruction_trap` weak evidence is unrelated to these expected Stage 2 shapes and is not counted.
- `file_scan` is weak because `close` is not proven.
- `self_copy_sim` is weak because path/tag semantics are not trace-proven.
- `abnormal_syscall_sequence` and `dynamic_executable_memory` are strong.

## Per-rep stability

| Sample | Rule | Strong reps | Weak expected reps | Weak shape reps |
| --- | --- | ---: | ---: | ---: |
| `file_scan` | `many_file_scan` | 0/5 | 5/5 | `many_file_scan_shape` 5/5 |
| `self_copy_sim` | `self_copy_simulation` | 0/5 | 5/5 | `self_copy_shape_without_path_tags` 5/5 |
| `abnormal_syscall_sequence` | `abnormal_syscall_sequence` | 5/5 | 0/5 | none |
| `dynamic_executable_memory` | `dynamic_executable_memory` | 5/5 | 0/5 | none |

## Trace health

| Sample | Events median | Drop median | Drop rate median | Cap hit | UNKNOWN | Corrupt | Parser warnings |
| --- | ---: | ---: | ---: | --- | ---: | ---: | --- |
| `file_scan` | 336 | 7 | 0.020408 | none | 0 | 0 | `{}` |
| `self_copy_sim` | 343 | 7 | 0.020000 | none | 0 | 0 | `{}` |
| `abnormal_syscall_sequence` | 339 | 7 | 0.020231 | none | 0 | 0 | `{}` |
| `dynamic_executable_memory` | 358 | 7 | 0.019178 | none | 0 | 0 | `{}` |

DROP remains in the p0c low-DROP range. No trace cap hit was reported.

## Debug artifacts

- Aggregate summary: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/aggregate/rule_evidence_debug_summary.json`
- Aggregate markdown: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/aggregate/rule_evidence_debug_summary.md`
- `file_scan`: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/samples/malware_like_synthetic/file_scan/aggregate/rule_evidence_debug_post_fix`
- `self_copy_sim`: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/samples/malware_like_synthetic/self_copy_sim/aggregate/rule_evidence_debug_post_fix`
- `abnormal_syscall_sequence`: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/samples/malware_like_synthetic/abnormal_syscall_sequence/aggregate/rule_evidence_debug_post_fix`
- `dynamic_executable_memory`: `results/experiments/35t/35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5/samples/malware_like_synthetic/dynamic_executable_memory/aggregate/rule_evidence_debug_post_fix`

## Commands and return codes

| Command | Return code |
| --- | ---: |
| `uv run python -m compileall src\rv_maltrace tools` | 0 |
| `uv run python tools/recover_behavior.py --self-test` | 0 |
| `uv run python tools/audit_behavior.py --self-test` | 0 |
| `uv run python tools/check_35t_next_gate.py --self-test` | 0 |
| `uv run python tools/triage_35t_semantic_failures.py --self-test` | 0 |
| `uv run python tools/check_35t_experiment_bundle.py --self-test` | 0 |
| `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample file_scan --sample self_copy_sim --sample abnormal_syscall_sequence --sample dynamic_executable_memory` | 0 |
| `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample file_scan --sample self_copy_sim --sample abnormal_syscall_sequence --sample dynamic_executable_memory` | 0 |
| `uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5 --reps 5 --sample file_scan --sample self_copy_sim --sample abnormal_syscall_sequence --sample dynamic_executable_memory` | 0 |
| `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5 --sample file_scan --sample self_copy_sim --sample abnormal_syscall_sequence --sample dynamic_executable_memory` | 0 |
| `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-r512-malwarelike-semantic-expansion-20260520-com5 --reps 5 --sample file_scan --sample self_copy_sim --sample abnormal_syscall_sequence --sample dynamic_executable_memory` | 0 |
| In-memory Stage 1 benign strong-FP guard over `ls/cat/cp/sha256sum` existing artifacts | 0 |

## Readiness

- `allowed_to_enter_process_chain_risk`: true
- Stage 3 `process_chain`: NOT_RUN
- `staged_p0c_r512_matrix_ready`: false
- `full_matrix_ready`: false

Stage 2 is now clear to request a separate Stage 3 `process_chain` risk run, but it was not run automatically.
