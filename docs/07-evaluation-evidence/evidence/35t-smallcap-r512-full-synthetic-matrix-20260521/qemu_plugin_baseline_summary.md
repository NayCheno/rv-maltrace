# 35T QEMU-Plugin Baseline: 35t-qemu-plugin-baseline-20260523

Status: QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES

Source run: `35t-smallcap-r512-full-synthetic-matrix-20260521`
Results root: `results/experiments/35t/35t-qemu-plugin-baseline-20260523`

## QEMU

- binary: `results/experiments/35t/35t-qemu-plugin-baseline-20260523/qemu_user_plugin/qemu-8.2.2/build/qemu-riscv64`
- version: qemu-riscv64 version 8.2.2
- help_has_plugin: True

## Checks

- qemu_binary_exists: PASS
- qemu_help_has_plugin: PASS
- qemu_source_include_exists: PASS
- sample_manifest_count_13: PASS
- sample_binaries_present: PASS
- container_command_passed: PASS
- container_json_present: PASS
- plugin_compiled: PASS
- sample_count_13: PASS
- all_samples_passed: PASS
- all_reps_have_plugin_counts: PASS
- timing_paths_recorded: PASS
- non_claims_recorded: PASS

## Samples

| Sample | Class | Status | Reps | Syscalls | Timing |
| --- | --- | --- | --- | --- | --- |
| `hello` | `benign` | `PASS` | 3 | 9 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/benign/hello/qemu_plugin/timings.jsonl` |
| `ls` | `benign` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/benign/ls/qemu_plugin/timings.jsonl` |
| `cat` | `benign` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/benign/cat/qemu_plugin/timings.jsonl` |
| `cp` | `benign` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/benign/cp/qemu_plugin/timings.jsonl` |
| `sha256sum` | `benign` | `PASS` | 3 | 13 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/benign/sha256sum/qemu_plugin/timings.jsonl` |
| `file_scan` | `malware_like_synthetic` | `PASS` | 3 | 11 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/file_scan/qemu_plugin/timings.jsonl` |
| `batch_open_read_write` | `malware_like_synthetic` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/batch_open_read_write/qemu_plugin/timings.jsonl` |
| `self_copy_sim` | `malware_like_synthetic` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/self_copy_sim/qemu_plugin/timings.jsonl` |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `PASS` | 3 | 12 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/abnormal_syscall_sequence/qemu_plugin/timings.jsonl` |
| `illegal_trap` | `malware_like_synthetic` | `PASS` | 3 | 10 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/illegal_trap/qemu_plugin/timings.jsonl` |
| `process_chain` | `malware_like_synthetic` | `PASS` | 3 | 10 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/process_chain/qemu_plugin/timings.jsonl` |
| `dynamic_executable_memory` | `malware_like_synthetic` | `PASS` | 3 | 10 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/dynamic_executable_memory/qemu_plugin/timings.jsonl` |
| `anti_debug_like` | `malware_like_synthetic` | `PASS` | 3 | 13 | `results/experiments/35t/35t-qemu-plugin-baseline-20260523/samples/malware_like_synthetic/anti_debug_like/qemu_plugin/timings.jsonl` |

## Interpretation

- this is a QEMU user-mode TCG-plugin syscall-count baseline for the existing 13 synthetic 35T samples
- the baseline uses an upstream QEMU 8.2.2 riscv64-linux-user build configured with --enable-plugins
- per-sample plugin output and timing are recorded under the local results tree
- this simulator software baseline must not be reported as hardware trace, real malware detection, or complete semantic reconstruction

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- QEMU-plugin syscall-count evidence is a simulator software baseline, not hardware trace evidence
