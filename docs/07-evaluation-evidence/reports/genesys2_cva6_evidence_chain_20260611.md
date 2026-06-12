# Genesys2/CVA6 P0 Marker-Scoped Evidence Chain - 2026-06-11

## Status

Current run:
`results/board/genesys2_trace_validation/20260611-p0-continuous-136bit`

Overall status: `PASS_P0_STRICT_SYSCALL_ID_PAIRING`.

The 2026-06-11 136-bit board recapture closes the strict P0 safe synthetic
continuous-trace blocker for Digilent Genesys2 + CVA6. The four P0 traces have
same-window marker scope, raw `SYSCALL_ENTRY` / `SYSCALL_RET` pairing by
matching nonzero `syscall_id`, runtime process attribution, target ELF/code
attribution, semantic event recovery, behavior graph output, and zero
unaccounted drops.

This is still a bounded P0 claim. The separate Phase C BRAM ring trace-sink
run below closes the required `hello_write` and `illegal_instruction`
trace-sink repetitions. Captured-window drop accounting and disabled-mode
pointer snapshot guardrails are also checked below. A separate safe-surrogate
BRAM marker-window run closes one raw trace/count/drop repetition for each of
the eight safe syscall-only surrogate workloads. Phase D/E/F summaries under
`results/evaluation/genesys2-cva6/current/` now close the controlled
trusted-companion semantic, fd/path, process/ELF, dynamic mapping, baseline,
evaluation-matrix, and behavior-metric gates. The combined evidence is not
real malware validation, not hardware pointer-snapshot evidence, and not a
production runtime slowdown claim.

## Board And Runtime Evidence

- Board: Digilent Genesys2.
- CPU: CVA6, RV64GC/Sv39 Linux board run.
- UART/Linux log:
  `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/uart_linux_login_after_boot_2.log`.
- Programming log:
  `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/vivado_program_trace_marker_136bit.log`.
- Bitstream:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit`
  (`sha256=f5977ac52868b9b6091865851a4cf761ef9f1c24878704c6acd4b724bbb66042`).
- LTX:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx`
  (`sha256=9f18f130142676b9d60c5a510553040e3880e9aa7928e3d2eed76b1577e14a14`).
- Source-bound build manifest:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/rvmt_trace_marker_build_manifest.json`.

## P0 Evidence Roots

| Sample | Evidence root | Same-window marker | Raw syscall-id pairing | Runtime process attribution | Drop accounting | Blocking item |
| --- | --- | --- | --- | --- | --- | --- |
| `hello_write` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/01_hello_write` | PASS | PASS | PASS | PASS, no DROP | none |
| `file_open_read_write` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/02_file_open_read_write` | PASS | PASS | PASS | PASS, no DROP | none |
| `fork_exec` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/03_fork_exec` | PASS | PASS | PASS | PASS, no DROP | none |
| `illegal_instruction` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/04_illegal_instruction` | PASS | PASS | PASS | PASS, no DROP | none |

Each evidence root contains:

- `trace.jsonl`
- `trace_summary.json`
- `uart_run.log`
- Vivado/ILA capture CSV and logs
- `runtime_process_map.json`
- `runtime_process_map_helper.log`
- `trace_code_map/code_map.json`
- `trace_code_map/source_attribution.jsonl`
- `trace_code_map/source_attribution_summary.json`
- `semantic_events.json`
- `behavior_graph.json`
- `recovery_report.md`
- `integrated_validation.json`

The run root also contains `run_summary.json`, which records the allowed P0
claim and explicit non-claims.

## Checker Result

Strict checker:

```text
uv run python tools/check_genesys2_p0_continuous_trace.py --run-root results\board\genesys2_trace_validation\20260611-p0-continuous-136bit
```

Result: PASS.

## Drop Accounting And Pointer Guardrails

Captured-window drop accounting:

- Summary:
  `results/evaluation/genesys2-cva6/current/drop_accounting_summary.json`.
- Checker:
  `uv run python tools/check_trace_drop_accounting.py --root .`
- Result: PASS.
- Scope: four P0 traces plus eight safe-surrogate BRAM marker-window records.
- Allowed claim: all listed captured trace windows have zero unaccounted
  `DROP` events.
- Non-claim: this does not make safe-surrogate raw traces pointer semantic
  reconstruction or full CCF-A evaluation evidence.

Pointer snapshot guardrails:

- Summary:
  `results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json`.
- Checker:
  `uv run python tools/check_pointer_snapshot_guardrails.py --root .`
- Result: PASS.
- Scope: disabled-mode current Genesys2/CVA6 traces.
- Allowed claim: no full memory dump, no kernel memory capture, no default raw
  pointer payload release, and bounded future policy fields are recorded.
- Non-claim: disabled-mode guardrails are not pointer semantic reconstruction
  or argument reconstruction evidence.

Passing conditions:

- Marker begin and marker end are captured in the same ILA trace window.
- Raw `SYSCALL_ENTRY` and `SYSCALL_RET` records pair by matching nonzero
  `syscall_id`.
- Runtime process attribution is proven from board `/proc/$pid` metadata and
  maps for the target ELF path.
- Code attribution reaches target ELF/function range level where symbols are
  available.
- Required target behaviors are present in the marker scope.
- Drop accounting is zero for the P0 recapture.
- Board, CPU, bitstream, and LTX metadata are recorded.

## Phase C BRAM Ring Trace Sink

Current run:
`results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board`

Overall status: `PASS_BRAM_TRACE_SINK_HELLO_ILLEGAL`.

The Phase C trace-sink run uses the `bram_ring` sink in the trace-marker
Genesys2/CVA6 bitstream. The ring records sequence number, compact event,
drop/wrap counters, and start/end timestamps. The board was reprogrammed with
the clear-on-begin marker build before capture.

Board and artifact evidence:

- Board: Digilent Genesys2.
- CPU: CVA6, RV64GC/Sv39 Linux board run.
- UART/Linux log:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/uart_linux_login_clear_on_begin_retry.log`.
- Programming log:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/vivado_program_bram_trace_marker_clear_on_begin.log`.
- Batch transcript:
  `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/run_bram_reps_clear_on_begin.out.log`.
- Summary:
  `results/evaluation/genesys2-cva6/current/trace_sink_summary.json`.
- Bitstream:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.bit`
  (`sha256=5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`).
- LTX:
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace-marker/work-fpga/ariane_xilinx.ltx`
  (`sha256=0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c`).

BRAM trace-sink evidence:

| Sample | Evidence root | Repetitions | Parse success | Expected event recall | Unaccounted drop | Wrap count |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `hello_write` | `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/01_hello_write` | 10/10 | 10/10 | 100% | 0 | 0 |
| `illegal_instruction` | `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/04_illegal_instruction` | 10/10 | 10/10 | 100% | 0 | 0 |

Strict checker:

```text
uv run python tools/check_genesys2_bram_trace_sink.py --root .
```

Result: PASS.

## Safe-Surrogate BRAM Marker Windows

Current run:
`results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait`

Overall status: `PASS_SAFE_SURROGATE_BRAM_MARKER_WINDOW`.

The safe-surrogate BRAM run uses rebuilt safe syscall-only ELF workloads with a
common begin marker `b0000a11` and end marker `e0000a11`. The BRAM ring is
cleared by the begin marker. Each sample has one board repetition with
sequence-contiguous BRAM records, no wrap, no drop, and a raw syscall-entry
count matching its build manifest.

Summary:
`results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json`.

Strict checker:

```text
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
```

Result: PASS.

Safe-surrogate BRAM evidence:

| Sample | BRAM records | Syscall entries expected/observed | Begin/end marker | Unaccounted drop |
| --- | ---: | ---: | --- | ---: |
| `file_scan` | 40 | 7/7 | PASS | 0 |
| `batch_open_read_write` | 40 | 7/7 | PASS | 0 |
| `self_copy_sim` | 66 | 7/7 | PASS | 0 |
| `abnormal_syscall_sequence` | 40 | 7/7 | PASS | 0 |
| `illegal_trap` | 105 | 3/3 | PASS | 0 |
| `process_chain` | 38 | 4/4 | PASS | 0 |
| `dynamic_executable_memory` | 25 | 4/4 | PASS | 0 |
| `anti_debug_like` | 64 | 6/6 | PASS | 0 |

## Ground-Truth Transcript Inputs

Docker `linux-behavior` provides the local Linux ground-truth toolchain used
after the board runs:

- `riscv64-linux-gnu-gcc` 13.3.0.
- `qemu-riscv64` 8.2.2.
- `strace` 6.8.

Generated transcript roots:

- Safe-surrogate host `strace` and `qemu-riscv64 -strace`:
  `results/demo/ccfa-safe-20260611/`.
- P0 marker-ELF `qemu-riscv64 -strace`:
  `results/demo/ccfa-p0-20260611/`.
- P0 source-equivalent host/control `strace`:
  `results/demo/ccfa-p0-20260611/*/01_ground_truth/host_control.strace.log`.

These transcripts are consumed by the Phase D/E/F summary packager. They close
the controlled trusted-companion semantic and baseline gates, but they do not
claim hardware user-pointer snapshot bytes.
The packager records provenance for qemu-derived paths and host/control
fallback string prefixes when `qemu-riscv64 -strace` reports only pointer
addresses. It also handles QEMU lines that concatenate multiple syscalls, so
P0 `fork_exec` records the child `execve("/bin/true")` path in the semantic
summary.

## Phase D/E/F Controlled Evaluation Summaries

Summary root:
`results/evaluation/genesys2-cva6/current/`

Packager:

```text
uv run python tools/package_ccfa_phase_def_summaries.py
```

Gate results:

| Gate | Summary artifact | Checker | Result |
| --- | --- | --- | --- |
| syscall semantic reconstruction | `semantic_reconstruction_summary.json` | `uv run python tools/check_syscall_semantic_reconstruction.py --root .` | PASS |
| fd/path graph | `fd_path_graph_summary.json` | `uv run python tools/check_fd_path_graph.py --root .` | PASS |
| source/function attribution | `source_line_attribution_summary.json`, `source_line_sidecar.json` | `uv run python tools/check_source_line_attribution.py --root .` | PASS |
| process/ELF ownership | `process_elf_ownership_summary.json` | `uv run python tools/check_process_elf_ownership.py --root .` | PASS |
| dynamic mapping attribution | `dynamic_mapping_attribution_summary.json` | `uv run python tools/check_dynamic_mapping_attribution.py --root .` | PASS |
| evaluation matrix | `ccfa_evaluation_matrix.json` | `uv run python tools/check_ccfa_evaluation_matrix.py --root .` | PASS |
| baseline alignment | `baseline_alignment_summary.json` | `uv run python tools/check_baseline_alignment.py --root .` | PASS |
| behavior audit metrics | `behavior_audit_metrics.json` | `uv run python tools/check_behavior_audit_metrics.py --root .` | PASS |
| current evidence quality | `semantic_reconstruction_summary.json`, `ccfa_evaluation_matrix.json`, per-sample logs and maps | `uv run python tools/check_ccfa_current_quality.py --root .` | PASS |

Important boundaries:

- Pointer argument strings are recovered through the trusted qemu/strace
  companion route and aligned with Genesys2 board traces; current hardware does
  not export user-pointer snapshot bytes in the LTX.
- Board trace code maps are function-level for generated syscall-only ELFs.
  `source_line_sidecar.json` is source-equivalent sidecar evidence, not DWARF
  extracted from the board ELF.
- Runtime process ownership uses Genesys2 UART `/proc/$pid` maps for P0 and
  safe-surrogate workloads.
- Baseline and behavior metrics are controlled safe-workload metrics, not
  malware-family detection quality.
- `tools/check_ccfa_current_quality.py` verifies the non-real-malware current
  evidence chain at artifact level: matrix paths, baseline logs, semantic
  openat/execve/write provenance, source sidecar rows, runtime process maps,
  and safe BRAM/drop run-root consistency.

## Allowed Claims

- This is Genesys2/CVA6 board evidence for safe synthetic P0 workloads.
- The four P0 traces contain marker begin and marker end in the same ILA
  window.
- The four P0 traces have strict raw syscall-id entry/return pairing.
- The required target events are present inside the marker scope.
- Runtime process attribution is proven by board `/proc/$pid` metadata and
  maps for the same target ELF path.
- Code attribution reaches target ELF/function range level where symbols are
  available.
- The BRAM ring trace sink captures the required `hello_write` and
  `illegal_instruction` repetitions with 20/20 parse success, 100% expected
  event recall, and zero unaccounted drops.
- The safe-surrogate BRAM run captures one marker-window repetition for each
  of the eight safe syscall-only surrogate workloads with matching raw
  syscall-entry counts and zero unaccounted drops.
- Captured-window drop accounting is zero for the four P0 and eight
  safe-surrogate BRAM marker-window artifacts.
- Pointer snapshot guardrails are satisfied in disabled mode.
- Trusted-companion syscall semantics, fd/path graph, runtime process/ELF
  ownership, dynamic mapping attribution, baseline alignment, and controlled
  behavior-audit metrics pass for P0 plus the eight safe surrogates.
- The non-real-malware current evidence chain passes the current-quality
  integrity gate.

## Non-Claims

- This is not real malware validation.
- This is not malware detection quality evidence.
- This is not Artix-7 35T or VexRiscv evidence.
- This does not claim hardware user-pointer snapshot bytes.
- This does not claim production runtime slowdown measurements.
- This does not claim malware-family detection accuracy.
- The BRAM trace-sink claim does not imply complete pointer semantics,
  source-line attribution, process ownership, dynamic mapping, baseline
  alignment, or behavior audit metrics.
- The safe-surrogate BRAM marker-window claim has one repetition per sample and
  does not imply statistical robustness, pointer semantics, source-line
  attribution, process ownership, dynamic mapping, or baseline alignment.
- Disabled-mode pointer guardrails do not imply pointer semantic
  reconstruction.
