# 35T Baseline Evaluation Summary: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Baselines

| Baseline | Status | Samples | Evidence |
| --- | --- | ---: | --- |
| `host_native` | `PASS` | 13/13 | groundtruth median timing field in aggregate metrics |
| `host_strace` | `PASS` | 13/13 | groundtruth median timing field in aggregate metrics |
| `qemu_native` | `PASS` | 13/13 | groundtruth median timing field in aggregate metrics |
| `qemu_strace` | `PASS` | 13/13 | groundtruth median timing field in aggregate metrics |
| `ebpf_only` | `PASS` | 13/13 | docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/ebpf_baseline_summary.json |
| `qemu_plugin` | `PASS` | 13/13 | docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/qemu_plugin_baseline_summary.json |
| `software_instrumentation` | `PASS` | 13/13 | results/experiments/35t/35t-software-instrumentation-baseline-20260523/aggregate/software_instrumentation_baseline_summary.json |
| `rvmaltrace_event_only` | `PASS` | 13/13 | primary 512-record hardware trace gate and per-sample trace metrics |
| `rvmaltrace_pointer_snapshot` | `DEFERRED` | 0/13 | selective pointer snapshot route remains gated/default-disabled |
| `rvmaltrace_helper_or_ebpf_companion` | `DEFERRED` | 0/13 | optional enrichment route, not an MVP dependency |

## Per-Sample Ratios

| Sample | Class | host strace/native | qemu strace/native | board trace on/off | drop median | cap hits |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `hello` | `benign` | 2.64326 | 1.64582 | 0.592099 | 0 | 0 |
| `ls` | `benign` | 2.83535 | 1.89741 | 0.575913 | 0 | 0 |
| `cat` | `benign` | 2.34973 | 1.63832 | 0.588477 | 0 | 0 |
| `cp` | `benign` | 2.42113 | 1.56683 | 0.565744 | 0 | 0 |
| `sha256sum` | `benign` | 2.39269 | 1.60493 | 0.599186 | 0 | 0 |
| `file_scan` | `malware_like_synthetic` | 2.19784 | 1.48288 | 0.542023 | 0 | 0 |
| `batch_open_read_write` | `malware_like_synthetic` | 2.36522 | 1.71005 | 0.531706 | 0 | 0 |
| `self_copy_sim` | `malware_like_synthetic` | 2.63054 | 2.21413 | 0.585426 | 0 | 0 |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | 2.63448 | 1.87208 | 0.538565 | 0 | 0 |
| `illegal_trap` | `malware_like_synthetic` | 2.34728 | 1.84477 | 0.527802 | 0.0306748 | 0 |
| `process_chain` | `malware_like_synthetic` | 4.08455 | 1.84284 | 0.915844 | 0 | 0 |
| `dynamic_executable_memory` | `malware_like_synthetic` | 2.60246 | 1.95358 | 0.537006 | 0 | 0 |
| `anti_debug_like` | `malware_like_synthetic` | 2.69215 | 2.0994 | 0.555109 | 0 | 0 |

## Interpretation

- host native, host strace, QEMU native, and QEMU strace timing fields are present for the 13-sample 35T run
- software instrumentation baseline is reported as PASS only when its independent summary has schema, run-id, sample-count, and pass-count evidence
- eBPF-only and QEMU-plugin are reported as PASS only when their independent summaries supply 13/13 sample evidence
- board trace-on/off ratios are measured runtime ratios only and are not acceleration claims

## Limitations

- timing fields alone do not prove syscall semantic accuracy or anti-debug detectability
- QEMU-plugin syscall-count evidence is a simulator software baseline and not a hardware trace, real malware, or DBI comparison claim
- the eBPF-only baseline is host Linux bpftrace evidence and is not a hardware, QEMU-plugin, or pointer-snapshot substitute
- software instrumentation is source-level function instrumentation and does not provide syscall argument reconstruction
- no real malware detection quality or classifier accuracy is measured

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
