# 35T Next Gate Report

- Run ID: `35t-smallcap-r512-full-synthetic-matrix-20260521`
- Artifact root: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521`
- Trace profile: `p0c_syscall_trap_drop`
- Trace profile policy: `35t_small_capacity`
- Claim level: `full_matrix_ready`
- Boundary: 35T/VexRiscv only; no CVA6 board claim; no real malware claim.

| Sample | Profile | Gate | Drop median | Drop rate median | Capped reps | UNKNOWN/corrupt | Marker | Runtime process | Unexpected events | Align recall | Missing expected | Weak expected | Weak shapes | Unexpected matched |
| --- | --- | --- | ---: | ---: | --- | ---: | --- | --- | --- | ---: | --- | --- | --- | --- |
| `hello` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.2222222222222222 | none | none | none | none |
| `ls` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `cat` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `cp` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `sha256sum` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.38461538461538464 | none | none | none | none |
| `file_scan` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.45454545454545453 | none | many_file_scan | many_file_scan_shape | none |
| `batch_open_read_write` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `self_copy_sim` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `abnormal_syscall_sequence` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.5 | none | none | none | none |
| `illegal_trap` | `p0c_syscall_trap_drop` | PASS | 5.0 | 0.03067484662576687 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.3 | none | none | none | none |
| `process_chain` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.45454545454545453 | none | none | none | none |
| `dynamic_executable_memory` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.3 | none | none | none | none |
| `anti_debug_like` | `p0a_syscall_drop` | PASS | 0.0 | 0.0 | none | 0/0 | PASS (5/5) | PASS (5/5) | none | 0.46153846153846156 | none | none | none | none |

## Rule Details

### `hello`

- Expected: none
- Matched: none
- Benign expected rule overlap: none
- Stable matched expected: none
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: none
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `ls`

- Expected: none
- Matched: many_file_scan
- Benign expected rule overlap: many_file_scan
- Stable matched expected: none
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: none
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `cat`

- Expected: none
- Matched: none
- Benign expected rule overlap: none
- Stable matched expected: none
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: none
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `cp`

- Expected: none
- Matched: none
- Benign expected rule overlap: none
- Stable matched expected: none
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: none
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `sha256sum`

- Expected: none
- Matched: none
- Benign expected rule overlap: none
- Stable matched expected: none
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: none
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `file_scan`

- Expected: many_file_scan
- Matched: many_file_scan
- Benign expected rule overlap: none
- Stable matched expected: many_file_scan
- Weak matched expected: many_file_scan
- Stable weak expected shapes: none
- Satisfied expected: many_file_scan
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `batch_open_read_write`

- Expected: batch_file_read_write
- Matched: batch_file_read_write
- Benign expected rule overlap: none
- Stable matched expected: batch_file_read_write
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: batch_file_read_write
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `self_copy_sim`

- Expected: self_copy_simulation
- Matched: self_copy_simulation
- Benign expected rule overlap: none
- Stable matched expected: self_copy_simulation
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: self_copy_simulation
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `abnormal_syscall_sequence`

- Expected: abnormal_syscall_sequence
- Matched: abnormal_syscall_sequence
- Benign expected rule overlap: none
- Stable matched expected: abnormal_syscall_sequence
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: abnormal_syscall_sequence
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `illegal_trap`

- Expected: illegal_instruction_trap
- Matched: illegal_instruction_trap
- Benign expected rule overlap: none
- Stable matched expected: illegal_instruction_trap
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: illegal_instruction_trap
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `process_chain`

- Expected: process_creation_chain
- Matched: process_creation_chain
- Benign expected rule overlap: none
- Stable matched expected: process_creation_chain
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: process_creation_chain
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `dynamic_executable_memory`

- Expected: dynamic_executable_memory
- Matched: dynamic_executable_memory
- Benign expected rule overlap: none
- Stable matched expected: dynamic_executable_memory
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: dynamic_executable_memory
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

### `anti_debug_like`

- Expected: anti_analysis_indicator
- Matched: anti_analysis_indicator
- Benign expected rule overlap: none
- Stable matched expected: anti_analysis_indicator
- Weak matched expected: none
- Stable weak expected shapes: none
- Satisfied expected: anti_analysis_indicator
- Missing: none
- Unexpected matched: none
- Marker scope: PASS
- Runtime process attribution: PASS

## Gate Boundary

This report separates trace capacity, semantic recovery, and audit-rule failures. It is prototype evidence, not a mature malware detector result.
