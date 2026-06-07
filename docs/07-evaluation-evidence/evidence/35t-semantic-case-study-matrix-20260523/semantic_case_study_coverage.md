# 35T Semantic Case Study Coverage

Status: PASS

## Checks

- fd_path_matrix_pass: PASS
- process_tree_matrix_pass: PASS
- behavior_only_samples_covered: PASS
- memory_anti_analysis_not_forced_into_fd_path: PASS

## Behavior-only Samples

| Sample | Status | Audit artifacts | Boundary |
| --- | --- | ---: | --- |
| `timing_anti_analysis_loop` | `covered` | 5 | not required to close fd/path or process tree |
| `proc_status_tracerpid_check` | `covered` | 5 | not required to close fd/path or process tree |
| `self_modifying_code_sim` | `covered` | 5 | not required to close fd/path or process tree |
| `mprotect_exec_variant` | `covered` | 5 | not required to close fd/path or process tree |
| `dynamic_executable_memory` | `covered` | 5 | not required to close fd/path or process tree |
| `anti_debug_like` | `covered` | 5 | not required to close fd/path or process tree |

## Failures

- none
