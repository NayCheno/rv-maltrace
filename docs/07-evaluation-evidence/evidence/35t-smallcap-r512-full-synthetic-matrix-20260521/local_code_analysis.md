# 35T Local Code Analysis Check: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION

Complete trace-on repetitions: 65/65

## Checks

- assessment_lists_local_code_tools: PASS
- assessment_records_attribution_boundaries: PASS
- tool_provenance_exists: PASS
- results_root_exists: PASS
- sample_set_exact: PASS
- sample_count_13: PASS
- code_map_all_samples: PASS
- trace_on_rep_count_5_all_samples: PASS
- trace_code_join_all_reps: PASS
- runtime_process_map_all_reps: PASS
- behavior_recovery_all_reps: PASS
- behavior_audit_all_reps: PASS
- nonempty_semantic_payload_all_reps: PASS
- bounded_attribution_non_claims: PASS

## Samples

| Sample | Class | Code map | Complete reps | Min target events | Min process-code events | Min syscalls | Min graph nodes | Failures |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `hello` | `benign` | `rvmt.code_map.v1` | 5/5 | 13 | 13 | 26 | 61 | none |
| `ls` | `benign` | `rvmt.code_map.v1` | 5/5 | 21 | 21 | 42 | 93 | none |
| `cat` | `benign` | `rvmt.code_map.v1` | 5/5 | 17 | 17 | 33 | 76 | none |
| `cp` | `benign` | `rvmt.code_map.v1` | 5/5 | 19 | 19 | 35 | 82 | none |
| `sha256sum` | `benign` | `rvmt.code_map.v1` | 5/5 | 19 | 19 | 35 | 82 | none |
| `file_scan` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 16 | 16 | 32 | 73 | none |
| `batch_open_read_write` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 24 | 24 | 49 | 106 | none |
| `self_copy_sim` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 18 | 18 | 34 | 79 | none |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 18 | 18 | 35 | 80 | none |
| `illegal_trap` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 27 | 16 | 28 | 285 | none |
| `process_chain` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 18 | 18 | 128 | 281 | none |
| `dynamic_executable_memory` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 16 | 16 | 32 | 73 | none |
| `anti_debug_like` | `malware_like_synthetic` | `rvmt.code_map.v1` | 5/5 | 18 | 18 | 36 | 81 | none |

## Tool Provenance

- `tools/build_code_map.py`: present
- `tools/join_trace_code_map.py`: present
- `tools/recover_behavior.py`: present
- `tools/audit_behavior.py`: present

## Capabilities

- trace PC to local ELF load range, section, symbol, syscall site, and trap site metadata
- trace event to marker-scope plus runtime-process-map assisted process attribution
- trace event to recovered syscall, trap/context transition, privilege-boundary, and behavior-graph records
- semantic event and behavior graph to rule-based synthetic behavior audit results

## Boundaries

- PC-in-ELF is static code-range evidence, not complete process ownership
- stronger process ownership still depends on marker scope plus runtime process map evidence
- source-line attribution is unavailable in this evidence set
- complete semantic reconstruction is not claimed
- rule-based audit is synthetic behavior triage, not real malware detection quality evidence

## Failures

- none
