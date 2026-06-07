# 35T Software Instrumentation Baseline: 35t-software-instrumentation-baseline-20260523

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Instrumentation: gcc -finstrument-functions host binary.

## Samples

| Sample | Class | Status | Runtime median ns | Function entries median | Log bytes median |
| --- | --- | --- | ---: | ---: | ---: |
| `hello` | `benign` | `PASS` | 1.3071e+07 | 2 | 160 |
| `ls` | `benign` | `PASS` | 1.36086e+07 | 2 | 160 |
| `cat` | `benign` | `PASS` | 1.81499e+07 | 4 | 316 |
| `cp` | `benign` | `PASS` | 1.70785e+07 | 4 | 316 |
| `sha256sum` | `benign` | `PASS` | 1.78378e+07 | 4 | 316 |
| `file_scan` | `malware_like_synthetic` | `PASS` | 1.51565e+07 | 1 | 88 |
| `batch_open_read_write` | `malware_like_synthetic` | `PASS` | 1.76922e+07 | 1 | 88 |
| `self_copy_sim` | `malware_like_synthetic` | `PASS` | 1.23242e+07 | 1 | 88 |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `PASS` | 1.09602e+07 | 1 | 88 |
| `illegal_trap` | `malware_like_synthetic` | `PASS` | 1.13143e+07 | 2 | 88 |
| `process_chain` | `malware_like_synthetic` | `PASS` | 1.22892e+07 | 1 | 88 |
| `dynamic_executable_memory` | `malware_like_synthetic` | `PASS` | 1.20294e+07 | 1 | 88 |
| `anti_debug_like` | `malware_like_synthetic` | `PASS` | 1.14759e+07 | 1 | 88 |

## Limitations

- source-level function instrumentation is user-visible and perturbing
- function entry/exit logs are not syscall argument or path reconstruction
- this baseline is not eBPF-only, QEMU-plugin, DBI, or real malware detection evidence

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
