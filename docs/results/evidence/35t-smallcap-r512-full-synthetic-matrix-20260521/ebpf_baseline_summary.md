# 35T eBPF-only Baseline: 35t-ebpf-baseline-20260523

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Instrumentation: bpftrace tracepoint:raw_syscalls:sys_enter comm-filtered host binaries.

## Samples

| Sample | Class | Status | Events median | eBPF/native median | Expected syscalls observed |
| --- | --- | --- | ---: | ---: | --- |
| `hello` | `benign` | `PASS` | 30 | 41.4586 | yes |
| `ls` | `benign` | `PASS` | 35 | 40.7211 | yes |
| `cat` | `benign` | `PASS` | 34 | 30.3229 | yes |
| `cp` | `benign` | `PASS` | 36 | 30.3628 | yes |
| `sha256sum` | `benign` | `PASS` | 38 | 31.4472 | yes |
| `file_scan` | `malware_like_synthetic` | `PASS` | 33 | 32.2019 | yes |
| `batch_open_read_write` | `malware_like_synthetic` | `PASS` | 41 | 26.0733 | yes |
| `self_copy_sim` | `malware_like_synthetic` | `PASS` | 35 | 41.4294 | yes |
| `abnormal_syscall_sequence` | `malware_like_synthetic` | `PASS` | 35 | 44.207 | yes |
| `illegal_trap` | `malware_like_synthetic` | `PASS` | 31 | 38.1293 | yes |
| `process_chain` | `malware_like_synthetic` | `PASS` | 35 | 38.7959 | yes |
| `dynamic_executable_memory` | `malware_like_synthetic` | `PASS` | 33 | 45.0431 | yes |
| `anti_debug_like` | `malware_like_synthetic` | `PASS` | 35 | 44.2253 | yes |

## Limitations

- this is a host Linux eBPF/bpftrace baseline for the 13 synthetic samples, not a hardware trace result
- runtime ratios are conservative end-to-end bpftrace launcher measurements and not in-kernel steady-state overhead
- comm-filtered syscall counts include dynamic loader activity and should not be treated as precise semantic reconstruction
- child processes are captured only while they retain the sample comm before execve; process-tree completeness is not claimed
- this baseline is not a QEMU-plugin, DBI, pointer-snapshot, real malware, or CVA6 validation substitute

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
