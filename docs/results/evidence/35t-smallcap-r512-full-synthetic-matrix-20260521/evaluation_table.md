# 35T Bounded Evaluation Table: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN

## Checks

- metrics_13_samples: PASS
- all_samples_pass: PASS
- required_groundtruth_present: PASS
- host_qemu_strace_baselines_pass: PASS
- software_instrumentation_pass: PASS
- ebpf_baseline_pass: PASS
- qemu_plugin_baseline_pass: PASS
- trace_drop_and_cap_bounded: PASS
- overhead_report_present: PASS
- bandwidth_report_present: PASS
- resource_delta_present: PASS
- anti_debug_behavior_strong: PASS
- pointer_snapshot_deferred_recorded: PASS

## Aggregate Metrics

| Metric | Value |
| --- | ---: |
| `sample_count` | 13 |
| `host_strace_over_native_median` | 2.602458 |
| `qemu_strace_over_native_median` | 1.842839 |
| `board_trace_on_over_off_median` | 0.565744 |
| `max_drop_rate_median` | 0.030675 |
| `trace_events_median` | 46.0 |
| `cap_hit_sample_count` | 0 |

## Baseline Coverage

| Baseline | Status | Evidence |
| --- | --- | --- |
| `ebpf_only` | `PASS` | 13/13 |
| `host_native` | `PASS` | 13/13 |
| `host_strace` | `PASS` | 13/13 |
| `qemu_native` | `PASS` | 13/13 |
| `qemu_plugin` | `PASS` | 13/13 |
| `qemu_strace` | `PASS` | 13/13 |
| `rvmaltrace_event_only` | `PASS` | 13/13 |
| `rvmaltrace_helper_or_ebpf_companion` | `DEFERRED` | 0/13 |
| `rvmaltrace_pointer_snapshot` | `DEFERRED` | 0/13 |
| `software_instrumentation` | `PASS` | 13/13 |

## Anti-Debug Synthetic Evidence

- sample: `anti_debug_like`
- strong reps: 5/5
- interpretation: anti_analysis_indicator is synthetic ptrace-oriented behavior evidence, not real malware evasion quality.

## Interpretation

- available timing baselines cover host native, host strace, QEMU native, QEMU strace, source-level software instrumentation, and host eBPF/bpftrace
- QEMU-plugin syscall-count evidence is included only from the separate 13-sample plugin baseline summary
- the eBPF-only baseline is host Linux bpftrace evidence and is not a hardware trace substitute
- trace-on/off ratios are measured board runtime ratios and are not acceleration claims
- anti_debug_like provides synthetic ptrace-oriented anti-analysis behavior evidence, not real malware evasion quality evidence
- resource/timing evidence is available as routed report summaries; full raw Vivado artifacts remain outside the lightweight snapshot

## Failures

- none

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no QEMU-plugin hardware-trace or DBI equivalence claim
- no eBPF baseline hardware-trace substitution claim
- no single-trace all-gates side-channel claim
