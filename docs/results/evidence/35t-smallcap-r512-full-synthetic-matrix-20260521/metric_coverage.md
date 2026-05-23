# 35T Metric Coverage: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY

## Checks

- all_required_metrics_listed: PASS
- metrics_13_samples: PASS
- alignment_proxy_present: PASS
- return_pairing_proxy_present: PASS
- fd_case_studies_pass: PASS
- process_case_study_pass: PASS
- runtime_and_timing_present: PASS
- trace_bytes_and_drop_present: PASS
- resource_summary_present: PASS
- anti_debug_bounded_present: PASS

## Metrics

| Metric | Status | Value | Boundary |
| --- | --- | --- | --- |
| syscall precision / recall | `MEASURED_PROXY` | `{"alignment_precision_median": 0.238095, "alignment_recall_median": 0.461538}` | current aggregate reports alignment precision/recall proxies, not a full semantic syscall classifier precision/recall claim |
| return pairing accuracy | `MEASURED_PROXY` | `{"entry_return_balanced_samples": 13, "sample_count": 13}` | entry/return count balance is a pairing sanity metric; full return-pairing accuracy remains bounded by available trace alignment |
| argument reconstruction accuracy | `MEASURED_PROXY` | `{"alignment_argument_accuracy_median": 0.361111}` | aggregate argument accuracy is an alignment-level proxy and does not imply complete pointer semantic reconstruction |
| path string reconstruction accuracy | `CASE_STUDY_MEASURED` | `{"batch_open_read_write": {"closed_flow_count": 4, "pending_openat_count": 0, "status": "PASS", "unresolved_fd_count": 0}, "file_scan": {"closed_flow_count": 1, "pending_openat_count": 0, "status": "PASS", "unresolved_fd_count": 0}, "self_copy_sim": {"closed_flow_count": 2, "pending_openat_count": 0, "status": "PASS", "unresolved_fd_count": 0}}` | measured on the three assessment-prioritized fd/path case-study samples via board syscall side-channel path strings |
| fd graph accuracy | `CASE_STUDY_MEASURED` | `{"all_have_closed_flows": true, "required_samples_pass": true}` | closed fd graph evidence is case-study scoped and must not be described as full-suite fd graph accuracy |
| process graph accuracy | `CASE_STUDY_MEASURED` | `{"exec_path": true, "graph": true, "positive_child_pid": true, "wait_pid": true}` | process graph evidence is scoped to the process_chain case study with parent PID intentionally unresolved |
| runtime overhead | `MEASURED` | `{"board_trace_on_over_off_median": 0.565744}` | board trace-on/off runtime ratio is reported as measured perturbation evidence, not acceleration |
| timing perturbation | `MEASURED` | `{"host_strace_over_native_median": 2.602458, "qemu_strace_over_native_median": 1.842839}` | covers host/QEMU strace timing, host eBPF/bpftrace timing, QEMU-plugin syscall-count timing evidence, and board trace-on/off timing |
| trace bytes per syscall | `MEASURED` | `{"trace_bytes_per_syscall_median": 672.934783}` | computed from aggregate trace compact/jsonl bytes and trace event medians |
| DROP rate | `MEASURED` | `{"max_drop_rate_median": 0.030675}` | bounded by the primary 13-sample 35T run under the 512-record trace budget |
| LUT / FF / BRAM / Fmax | `MEASURED_SUMMARY` | `{"fmax_recorded": true, "trace_delta_recorded": true}` | resource/timing evidence is a routed report summary; full raw Vivado artifacts remain outside the lightweight snapshot |
| anti-debug detectability | `BOUNDED_SYNTHETIC_MEASURED` | `{"anti_debug_behavior_strong": true, "ebpf_baseline_pass": true, "qemu_plugin_baseline_pass": null}` | anti_debug_like is synthetic ptrace-oriented behavior evidence; real malware anti-evasion quality is not claimed |

## Interpretation

- the assessment's P4 metric list is explicitly enumerated and tied to current evidence
- accuracy-style metrics are bounded to existing alignment proxies and fd/process case studies unless stronger full-suite ground truth exists
- advanced baseline perturbation and semantic enrichment accuracy remain bounded to available eBPF, QEMU-plugin, pointer snapshot, and helper evidence

## Failures

- none

## Non-claims

- no complete syscall semantic precision/recall claim
- no full-suite fd graph accuracy claim
- no full-suite process ownership accuracy claim
- no QEMU-plugin hardware-trace or DBI equivalence claim
- no real malware anti-evasion detectability claim
