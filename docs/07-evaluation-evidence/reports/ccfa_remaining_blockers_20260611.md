# CCF-A Remaining Blockers - 2026-06-11

Scope: Digilent Genesys2 + CVA6.

This report records the blockers remaining after the 2026-06-11 136-bit P0
recapture, Phase C BRAM ring trace-sink board run, safe-surrogate BRAM
marker-window rerun, and Phase D/E/F summary packaging. Repository edits and
fresh Genesys2/CVA6 board runs closed the Phase B P0 strict continuous-trace
blocker, the Phase C `hello_write` / `illegal_instruction` BRAM trace-sink
blocker, the safe-surrogate BRAM marker-window raw-trace blocker, the
captured-window drop-accounting blocker, and the disabled-mode pointer
snapshot guardrail blocker. The current controlled safe-workload gate also
closes the trusted-companion semantic reconstruction, fd/path graph,
process/ELF ownership, dynamic mapping, baseline alignment, evaluation matrix,
and behavior metrics checkers. It still does not claim hardware pointer
snapshot bytes, production runtime slowdown, statistical robustness beyond the
recorded repetitions, or real-malware validation.

## Closed On 2026-06-11

Phase B P0 continuous trace is now closed for the four safe synthetic P0
workloads.

Command:

```powershell
uv run python tools/check_genesys2_p0_continuous_trace.py --run-root results/board/genesys2_trace_validation/20260611-p0-continuous-136bit
```

Result: PASS.

Evidence root:
`results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/`

Board/programming/runtime evidence:

- Board: Digilent Genesys2.
- CPU: CVA6 RV64GC/Sv39 Linux board run.
- Bitstream:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit`
  (`sha256=f5977ac52868b9b6091865851a4cf761ef9f1c24878704c6acd4b724bbb66042`).
- LTX:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx`
  (`sha256=9f18f130142676b9d60c5a510553040e3880e9aa7928e3d2eed76b1577e14a14`).
- Bitstream source manifest:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json`.
- Programming log:
  `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/vivado_program_trace_marker_136bit.log`.
- Linux/UART log:
  `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/uart_linux_login_after_boot_2.log`.

Closed P0 evidence:

| Sample | Evidence root | Same-window marker | Raw syscall-id pairing | Runtime process attribution | Code attribution | Drop accounting | Required behavior |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hello_write` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/01_hello_write` | PASS | PASS | PASS | PASS | PASS, no DROP | PASS |
| `file_open_read_write` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/02_file_open_read_write` | PASS | PASS | PASS | PASS | PASS, no DROP | PASS |
| `fork_exec` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/03_fork_exec` | PASS | PASS | PASS | PASS | PASS, no DROP | PASS |
| `illegal_instruction` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/04_illegal_instruction` | PASS | PASS | PASS | PASS | PASS, no DROP | PASS |

The allowed claim is limited to P0 safe synthetic marker-scoped same-window
Genesys2/CVA6 board trace evidence with strict raw `syscall_id`
entry/return pairing.

Phase C BRAM trace-sink evidence is now closed for the required
`hello_write` and `illegal_instruction` repetitions.

Command:

```powershell
uv run python tools/check_genesys2_bram_trace_sink.py --root .
```

Result: PASS.

Evidence root:
`results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/`

Summary artifact:
`results/evaluation/genesys2-cva6/current/trace_sink_summary.json`

Board/programming/runtime evidence:

- Board: Digilent Genesys2.
- CPU: CVA6 RV64GC/Sv39 Linux board run.
- Bitstream:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit`
  (`sha256=5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`).
- LTX:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx`
  (`sha256=0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c`).
- Programming log:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/vivado_program_bram_trace_marker_clear_on_begin.log`.
- Linux/UART log:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/uart_linux_login_clear_on_begin_retry.log`.
- Batch run transcript:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/run_bram_reps_clear_on_begin.out.log`.

Closed BRAM trace-sink evidence:

| Sample | Repetitions | Parse success | Expected event recall | Unaccounted drop | Trace sink mode |
| --- | ---: | ---: | ---: | ---: | --- |
| `hello_write` | 10/10 | 10/10 | 100% | 0 | `bram_ring` |
| `illegal_instruction` | 10/10 | 10/10 | 100% | 0 | `bram_ring` |

Safe-surrogate BRAM marker-window evidence is now closed for one board
repetition of each of the eight safe syscall-only surrogate workloads.

Command:

```powershell
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
```

Result: PASS.

Evidence root:
`results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/`

Summary artifact:
`results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json`

Closed safe-surrogate BRAM marker-window evidence:

| Sample | Repetitions | BRAM records | Syscall entries expected/observed | Marker window | Unaccounted drop |
| --- | ---: | ---: | ---: | --- | ---: |
| `file_scan` | 1 | 40 | 7/7 | `b0000a11` -> `e0000a11` | 0 |
| `batch_open_read_write` | 1 | 40 | 7/7 | `b0000a11` -> `e0000a11` | 0 |
| `self_copy_sim` | 1 | 66 | 7/7 | `b0000a11` -> `e0000a11` | 0 |
| `abnormal_syscall_sequence` | 1 | 40 | 7/7 | `b0000a11` -> `e0000a11` | 0 |
| `illegal_trap` | 1 | 105 | 3/3 | `b0000a11` -> `e0000a11` | 0 |
| `process_chain` | 1 | 38 | 4/4 | `b0000a11` -> `e0000a11` | 0 |
| `dynamic_executable_memory` | 1 | 25 | 4/4 | `b0000a11` -> `e0000a11` | 0 |
| `anti_debug_like` | 1 | 64 | 6/6 | `b0000a11` -> `e0000a11` | 0 |

Allowed claim: all eight safe syscall-only surrogate workloads have one
Genesys2/CVA6 `bram_ring` marker-window capture with begin-marker clearing,
matching raw syscall-entry count against the build manifest, no sequence gaps,
no wrap, and zero unaccounted drop. This is not pointer semantic
reconstruction, source-line attribution, process ownership, baseline
alignment, behavior metric completeness, or real-malware validation.

Captured-window drop accounting is now closed for the four P0 traces and the
eight safe-surrogate BRAM marker-window records.

Command:

```powershell
uv run python tools/check_trace_drop_accounting.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/drop_accounting_summary.json`

Allowed claim: all listed Genesys2/CVA6 captured trace windows have zero
unaccounted `DROP` events. This does not convert safe-surrogate raw-trace
captures into pointer semantic reconstruction or full CCF-A evaluation
evidence.

Pointer snapshot guardrails are now closed in disabled mode.

Command:

```powershell
uv run python tools/check_pointer_snapshot_guardrails.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json`

Allowed claim: the current Genesys2/CVA6 traces satisfy pointer snapshot
guardrails in disabled mode: no full memory dump, no kernel memory capture, and
no default raw pointer payload release. This is not pointer semantic
reconstruction evidence.

Additional ground-truth and source-equivalent inputs were generated with the
Docker `linux-behavior` environment after the BRAM marker-window run:

- Safe-surrogate host `strace` and `qemu-riscv64 -strace` transcripts:
  `results/demo/ccfa-safe-20260611/`.
- P0 marker-ELF `qemu-riscv64 -strace` transcripts:
  `results/demo/ccfa-p0-20260611/`.
- P0 source-equivalent host/control `strace` transcripts:
  `results/demo/ccfa-p0-20260611/*/01_ground_truth/host_control.strace.log`.
- Container tools observed: `riscv64-linux-gnu-gcc` 13.3.0,
  `qemu-riscv64` 8.2.2, and `strace` 6.8.

Allowed claim: these transcripts are baseline/ground-truth inputs consumed by
the current Phase D/E/F summary packager. They do not convert the current
hardware into a user-pointer snapshot implementation.

## Phase D/E/F Gate Status

| Phase | Current evidence | Remaining boundary | Current checker |
| --- | --- | --- | --- |
| Phase D pointer semantics | PASS via `semantic_reconstruction_summary.json`, using board trace plus trusted qemu/strace companion semantics for P0 and all eight safe surrogates. | Hardware user-pointer snapshot bytes are not claimed. | `tools/check_syscall_semantic_reconstruction.py` |
| Phase D fd/path graph | PASS via `fd_path_graph_summary.json`; controlled openat/execve path reconstruction is 100% where applicable. | FD/path strings are companion-derived, not hardware ARG_MEM bytes. | `tools/check_fd_path_graph.py` |
| Phase E source attribution | PASS via `source_line_attribution_summary.json` and `source_line_sidecar.json`; board traces remain function-level and sidecar source-line scoped. | Current board ELFs do not carry DWARF source-line attribution. | `tools/check_source_line_attribution.py` |
| Phase E process/ELF ownership | PASS via `process_elf_ownership_summary.json` using P0 and safe-surrogate Genesys2 runtime process maps. | No broad SATP/ASID-backed attribution claim is made. | `tools/check_process_elf_ownership.py` |
| Phase E dynamic mapping | PASS via `dynamic_mapping_attribution_summary.json`; host/control dynamic loader cases are scoped separately from board syscall-only EXEC binaries. | PIE/shared-library evidence is host/control scoped, not current board workload scoped. | `tools/check_dynamic_mapping_attribution.py` |
| Phase F evaluation matrix | PASS via `ccfa_evaluation_matrix.json`, `workload_manifest.json`, and per-sample metric summaries. | Not a real-malware or production throughput matrix. | `tools/check_ccfa_evaluation_matrix.py` |
| Phase F baseline alignment | PASS via `baseline_alignment_summary.json` across event-only, guardrailed pointer-snapshot, trusted companion, strace, qemu-strace, and software-sidecar rows. | Pointer snapshot row is a guarded disabled route, not hardware pointer bytes. | `tools/check_baseline_alignment.py` |
| Phase F behavior metrics | PASS via `behavior_audit_metrics.json` for controlled safe workloads. | Metrics are behavior-audit metrics, not malware-family detection accuracy. | `tools/check_behavior_audit_metrics.py` |
| Phase F current quality | PASS via a strict artifact-integrity gate over the non-real-malware current evidence chain. | This does not add a hardware pointer-snapshot route or real-malware validation claim. | `tools/check_ccfa_current_quality.py` |
| Phase G containment policy | Optional real-malware containment policy is present and can be checked without introducing payloads. | Keep policy and containment separate from validation evidence. | `tools/check_real_malware_containment.py` |
| Phase G real-malware validation | Real malware is intentionally not a main-line claim, and no real-malware run artifacts are present. | Only use as optional case study after authorization, isolated execution, hash-only metadata, and sanitized reports. | `tools/check_real_malware_validation_gate.py` |

## Current Gate Audit

After the BRAM trace-sink board run, safe-surrogate busy-wait rerun, and
Phase D/E/F summary packaging, the current repository gate state is:

| Gate | Command | Result |
| --- | --- | --- |
| current Genesys2/CVA6 gate | `uv run python tools/run_check_suite.py --suite genesys2-current` | PASS 26/26, including Phase B/C/D/E/F controlled gates, current-quality integrity, and real-malware containment |
| BRAM trace sink | `uv run python tools/check_genesys2_bram_trace_sink.py --root .` | PASS |
| safe-surrogate BRAM marker-window trace | `uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .` | PASS |
| trace drop accounting | `uv run python tools/check_trace_drop_accounting.py --root .` | PASS |
| syscall semantic reconstruction | `uv run python tools/check_syscall_semantic_reconstruction.py --root .` | PASS |
| pointer snapshot guardrails | `uv run python tools/check_pointer_snapshot_guardrails.py --root .` | PASS, disabled mode only |
| fd/path graph | `uv run python tools/check_fd_path_graph.py --root .` | PASS |
| source-line attribution | `uv run python tools/check_source_line_attribution.py --root .` | PASS, sidecar-scoped source lines; board traces function-level |
| process/ELF ownership | `uv run python tools/check_process_elf_ownership.py --root .` | PASS |
| dynamic mapping attribution | `uv run python tools/check_dynamic_mapping_attribution.py --root .` | PASS |
| CCF-A evaluation matrix | `uv run python tools/check_ccfa_evaluation_matrix.py --root .` | PASS |
| baseline alignment | `uv run python tools/check_baseline_alignment.py --root .` | PASS |
| behavior audit metrics | `uv run python tools/check_behavior_audit_metrics.py --root .` | PASS |
| current-quality integrity | `uv run python tools/check_ccfa_current_quality.py --root .` | PASS |
| real-malware containment | `uv run python tools/check_real_malware_containment.py --root .` | PASS |
| real-malware validation | `uv run python tools/check_real_malware_validation_gate.py` | BLOCKED, no authorized run artifacts and no payloads in repo |

The D/E/F summaries are now explicit artifacts under
`results/evaluation/genesys2-cva6/current/`. They are bounded by the non-claims
above and must not be described as hardware user-pointer snapshot evidence,
production runtime slowdown evidence, real-malware validation, or
malware-family detection accuracy.

## Non-Claims

- P0 strict continuous trace closure does not make the project CCF-A ready.
- The new P0 recapture is not real malware validation.
- The new P0 recapture is not malware detection quality evidence.
- The BRAM trace-sink run closes only the scoped Phase C `hello_write` and
  `illegal_instruction` repetition requirement.
- Captured-window drop accounting does not prove continuous trace for
  semantic reconstruction or full safe-surrogate evaluation.
- The safe-surrogate BRAM marker-window run has one repetition per sample and
  uses safe syscall-only surrogate binaries; it is not a statistical robustness
  study and is not real-malware validation.
- Disabled-mode pointer snapshot guardrails do not prove pointer semantic
  reconstruction or argument reconstruction.
- Safe-surrogate behavior audit remains separate from real malware validation.
- Passing containment policy is not real-malware validation.
