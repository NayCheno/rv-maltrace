# Genesys2/CVA6 P0 Marker-Scoped Evidence Chain - 2026-06-11

## Status

Current run:
`results/board/genesys2_trace_validation/20260611-p0-continuous-136bit`

Overall status: `PASS_P0_STRICT_SYSCALL_ID_PAIRING`.

Current-status note (2026-06-12): this report is retained as an intermediate
P0 evidence-chain log. The current paper-facing gate is the 82/100 controlled
safe/surrogate chain in `ccfa_readiness_matrix.md`; it is NOT CCF-A READY.

The 2026-06-11 136-bit board recapture closes the strict P0 safe synthetic
continuous-trace blocker for Digilent Genesys2 + CVA6. The four P0 traces have
same-window marker scope, raw `SYSCALL_ENTRY` / `SYSCALL_RET` pairing by
matching nonzero `syscall_id`, runtime process attribution, target ELF/code
attribution, semantic event recovery, behavior graph output, and zero
unaccounted drops.

This is still a bounded P0 claim. The separate Phase C BRAM ring trace-sink
run below closes the required `hello_write` and `illegal_instruction`
trace-sink repetitions. Captured-window drop accounting and bounded-prefix
hardware ARG_MEM pointer snapshot guardrails are also checked below. A separate
safe-surrogate BRAM marker-window run closes accepted raw trace/count/drop repetitions for each of
the eight safe syscall-only surrogate workloads. Phase D/E/F summaries under
`results/evaluation/genesys2-cva6/current/` now close the controlled
trusted-companion semantic, fd/path, process/ELF, dynamic mapping, baseline,
evaluation-matrix, behavior-metric, runtime benchmark, and reproducibility
manifest gates. A separate source-line toolchain probe now proves the
debug/no-PIE RISC-V `addr2line` path and records that current board ELFs lack
DWARF; a trace-export decision gate keeps the current route scoped to BRAM
ring plus ILA/JTAG. A local Linux benign-control audit now covers five
non-network benign workloads with strace-derived behavior graphs and
unexpected false-positive rate 0.0. A per-sample case-study manifest now links
each P0 and safe-surrogate sample to a reviewer-traceable case-study summary.
A lightweight artifact package now hashes
the current reports/checkers/summaries and provides fresh-clone reproduction
commands. A separate external-closure readiness contract fixes the required
artifacts, acceptance criteria, future checker contracts, and no-substitution
rules for the remaining non-real-malware external blockers. A paired
external-closure intake gate validates optional future external summaries and
currently remains open, and an external-closure execution plan plus operator
handoff packet records concrete runbooks, exported non-evidence templates,
local preflight checks, and per-blocker artifact-kind requirements for those same blockers. The combined evidence is not real malware
validation, not malware detection accuracy, not full
hardware-derived pointer-string evidence, not board-native DWARF source-line
attribution for current board traces, and not a production streaming/DMA
throughput claim.

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
| `hello_write` | `results/board/genesys2_trace_validation/20260702-current-p0-continuous-single-window/01_hello_write` | PASS | PASS | PASS | PASS, no DROP | none |
| `file_open_read_write` | `results/board/genesys2_trace_validation/20260702-current-p0-continuous-single-window/02_file_open_read_write` | PASS | PASS | PASS | PASS, no DROP | none |
| `fork_exec` | `results/board/genesys2_trace_validation/20260702-current-p0-continuous-single-window/03_fork_exec` | PASS | PASS | PASS | PASS, no DROP | none |
| `illegal_instruction` | `results/board/genesys2_trace_validation/20260702-current-p0-continuous-single-window/04_illegal_instruction` | PASS | PASS | PASS | PASS, no DROP | none |

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
- Scope: bounded-prefix hardware ARG_MEM current Genesys2/CVA6 traces for
  openat / execve / write.
- Allowed claim: no full memory dump, no kernel memory capture, no default raw
  pointer payload release, and no full hardware-derived pointer-string claim.
- Non-claim: trusted companion strings are not hardware-derived strings, and
  bounded ARG_MEM prefixes are not a full memory dump or full-string route.

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
cleared by the begin marker. Each sample has ten accepted board repetitions
with sequence-contiguous BRAM records, no wrap, no drop, and raw syscall-entry
counts matching its build manifest.

Summary:
`results/evaluation/genesys2-cva6/current/safe_surrogate_bram_trace_summary.json`.

Strict checker:

```text
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
```

Result: PASS.

Safe-surrogate BRAM evidence:

| Sample | Repetitions | Syscall entries expected/observed | Begin/end marker | Unaccounted drop |
| --- | ---: | ---: | --- | ---: |
| `file_scan` | 10 | 7/7 minimum per rep | PASS | 0 |
| `batch_open_read_write` | 10 | 7/7 minimum per rep | PASS | 0 |
| `self_copy_sim` | 10 | 7/7 minimum per rep | PASS | 0 |
| `abnormal_syscall_sequence` | 10 | 7/7 minimum per rep | PASS | 0 |
| `illegal_trap` | 10 | 3/3 minimum per rep | PASS | 0 |
| `process_chain` | 10 | 4/4 minimum per rep | PASS | 0 |
| `dynamic_executable_memory` | 10 | 4/4 minimum per rep | PASS | 0 |
| `anti_debug_like` | 10 | 6/6 minimum per rep | PASS | 0 |

## Ground-Truth Transcript Inputs

Docker `linux-behavior` provides the local Linux ground-truth toolchain used
after the board runs:

- `riscv64-linux-gnu-gcc` 13.3.0.
- `riscv64-linux-gnu-addr2line` / `riscv64-linux-gnu-readelf` GNU Binutils 2.42.
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
| source-line toolchain probe | `source_line_toolchain_probe.json` | `uv run python tools/check_source_line_toolchain_probe.py --root .` | PASS |
| process/ELF ownership | `process_elf_ownership_summary.json` | `uv run python tools/check_process_elf_ownership.py --root .` | PASS |
| dynamic mapping attribution | `dynamic_mapping_attribution_summary.json` | `uv run python tools/check_dynamic_mapping_attribution.py --root .` | PASS |
| evaluation matrix | `ccfa_evaluation_matrix.json` | `uv run python tools/check_ccfa_evaluation_matrix.py --root .` | PASS |
| baseline alignment | `baseline_alignment_summary.json` | `uv run python tools/check_baseline_alignment.py --root .` | PASS |
| behavior audit metrics | `behavior_audit_metrics.json` | `uv run python tools/check_behavior_audit_metrics.py --root .` | PASS |
| statistical robustness audit | `statistical_robustness_summary.json` | `uv run python tools/check_genesys2_statistical_robustness.py --root .` | PASS |
| streaming/DMA target baseline | `streaming_dma_target_summary.json` | `uv run python tools/check_genesys2_streaming_dma_target.py --root .` | PASS TARGET BASELINE |
| per-sample case-study package | `case_study_manifest.json`, `samples/*/case_study_summary.json` | `uv run python tools/check_ccfa_case_study_manifest.py --root .` | PASS |
| benign-control false-positive audit | `benign_control_summary.json` | `uv run python tools/check_benign_control_summary.py --root .` | PASS |
| current evidence quality | `semantic_reconstruction_summary.json`, `ccfa_evaluation_matrix.json`, per-sample logs and maps | `uv run python tools/check_ccfa_current_quality.py --root .` | PASS |
| hardware pointer prefix audit | `hardware_pointer_prefix_summary.json` | `uv run python tools/check_hardware_pointer_prefixes.py --root .` | PASS |
| reproducibility manifest | `reproducibility_manifest.json` | `uv run python tools/check_genesys2_reproducibility_manifest.py --root .` | PASS |
| artifact package / fresh-clone commands | `artifact_package_manifest.json`, `tools/reproduce_genesys2_current.py` | `uv run python tools/check_genesys2_artifact_package.py --root .`; `uv run python tools/reproduce_genesys2_current.py --full --dry-run` | PASS |
| external closure readiness contract | `external_closure_readiness.json` | `uv run python tools/check_genesys2_external_closure_readiness.py --root .` | PASS |
| external closure intake gate | `external_closure_intake.json` | `uv run python tools/check_genesys2_external_closure_intake.py --root .` | PASS OPEN |
| external closure execution plan | `external_closure_plan.json` | `uv run python tools/check_genesys2_external_closure_plan.py --root .` | PASS PLAN ONLY |
| external closure local preflight | `external_closure_preflight.json` | `uv run python tools/check_genesys2_external_closure_preflight.py --root .` | PASS LOCAL PREFLIGHT |
| external operator handoff packet | `external_operator_packet.json` | `uv run python tools/check_genesys2_external_operator_packet.py --root .` | PASS OPERATOR HANDOFF |
| external summary template guard | `external_closure_templates/*.template.json` | `uv run python tools/prepare_genesys2_external_summary.py --check-templates` | PASS TEMPLATE NON-EVIDENCE |
| trace-export decision boundary | `docs/02-trace-architecture/trace_export_decision.md` | `uv run python tools/check_trace_export_decision.py --root .` | PASS |

Important boundaries:

- Pointer argument strings are recovered through the trusted qemu/strace
  companion route and aligned with Genesys2 board traces; current hardware
  ARG_MEM evidence is bounded-prefix only and does not claim full strings.
- Board trace code maps are function-level for generated syscall-only ELFs.
  `source_line_sidecar.json` is source-equivalent sidecar evidence, not DWARF
  extracted from the board ELF.
- `source_line_toolchain_probe.json` proves the Docker `linux-behavior`
  debug/no-PIE `.debug_line` and `addr2line` path, and separately records that
  current generated board ELFs remain no-DWARF/function-level.
- Runtime process ownership uses Genesys2 UART `/proc/$pid` maps for P0 and
  safe-surrogate workloads.
- Hardware pointer prefix evidence is separated from companion string evidence:
  `hardware_pointer_prefix_summary.json` records bounded compact ARG_MEM bytes,
  fragment gaps, and `full_string_claimed=false`.
- Baseline and behavior metrics are controlled safe-workload metrics, not
  malware-family detection quality.
- `statistical_robustness_summary.json` audits the current controlled
  repetition evidence: 120 accepted board repetitions across 12 P0/safe
  surrogate samples, one retained failed P0 attempt, zero accepted-window
  unaccounted DROP/wrap/dropped count, 12 case studies, and five local benign
  controls. It is not randomized workload generalization, real-malware
  validation, or production long-run stability evidence.
- `streaming_dma_target_summary.json` converts the 120 accepted marker-window
  repetitions into a future non-BRAM transport target: 136-bit compact records,
  17 bytes per event, and p95 `0.01981178801386825` event bytes per
  marker-window cycle. It is target-baseline evidence only; a future
  production streaming/DMA summary still needs host receiver, timing, resource,
  noninterference, and exact clock evidence.
- `benign_control_summary.json` records five local Linux non-network benign
  controls (`hello`, `ls`, `cat`, `cp`, `sha256sum`) with semantic events,
  behavior graphs, behavior audits, documented benign rule overlaps, and
  unexpected false-positive rate 0.0.
- `tools/check_ccfa_current_quality.py` verifies the non-real-malware current
  evidence chain at artifact level: matrix paths, baseline logs, semantic
  openat/execve/write provenance, source sidecar rows, runtime process maps,
  pointer-prefix summary, benign-control summary, reproducibility manifest, and
  safe BRAM/drop run-root consistency.
- `tools/check_trace_export_decision.py` keeps the trace-sink claim scoped to
  BRAM ring buffer plus ILA/JTAG; UART streaming and AXI DMA/Ethernet streaming
  remain deferred.
- `artifact_package_manifest.json` records the lightweight current evidence
  package: report/checker/summary hashes, referenced raw board roots, raw-copy
  non-claims, and quick/full fresh-clone reproduction commands.
- `external_closure_readiness.json` records the remaining non-real-malware
  external blockers and their acceptance standards; it is a readiness contract,
  not completion evidence.
- `external_closure_intake.json` validates optional future external summaries,
  but current status is `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`, not completion
  evidence.
- `external_closure_plan.json` records executable external-closure runbooks and
  template-only summaries; the templates are not evidence and do not close the
  open intake status.
- `external_closure_preflight.json` records local script, dry-run, schema/path,
  and no-substitution readiness for those runbooks; it is preflight only and
  does not replace external execution.
- `external_closure_templates/*.template.json` files are exported operator
  scaffolding only; they are checked to remain `TEMPLATE_NOT_EVIDENCE` and do
  not close the intake gate.

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
- The safe-surrogate BRAM run captures ten marker-window repetitions for each
  of the eight safe syscall-only surrogate workloads with matching raw
  syscall-entry counts and zero unaccounted drops.
- Captured-window drop accounting is zero for the four P0 and eight
  safe-surrogate BRAM marker-window artifacts.
- The controlled statistical robustness audit records 120 accepted board
  repetitions, one retained failed P0 attempt not counted as PASS, and zero
  accepted-window unaccounted DROP/wrap/dropped count.
- Pointer snapshot guardrails are satisfied for bounded-prefix hardware ARG_MEM.
- Trusted-companion syscall semantics, fd/path graph, runtime process/ELF
  ownership, dynamic mapping attribution, baseline alignment, and controlled
  behavior-audit metrics pass for P0 plus the eight safe surrogates.
- Five local Linux benign controls have behavior graphs and behavior-audit
  output with unexpected false-positive rate 0.0.
- All P0 and safe-surrogate samples have per-sample case-study summaries that
  link hardware trace, semantic reconstruction, local code attribution,
  baseline comparison, audit decision, metrics, limitations, and reviewer
  traceability.
- The non-real-malware current evidence chain passes the current-quality
  integrity gate.
- The debug/no-PIE RISC-V source-line toolchain path is proven with
  `addr2line`, while current board traces remain function-level because their
  generated board ELFs lack DWARF.
- A lightweight artifact package and fresh-clone reproduction entrypoint are
  available for rerunning the current controlled checker gates.
- A cycle-normalized streaming/DMA target baseline is available for future
  external throughput experiments, but it does not close the throughput
  blocker.
- A machine-checkable external-closure readiness contract is available for
  board-native DWARF source lines, full hardware pointer strings, production
  streaming/DMA throughput, and Genesys2 board benign controls.
- A paired external-closure intake gate is available and rejects weak or
  substitutive optional external summaries.
- A plan-only external-closure runbook is available for the remaining board/RTL
  work.
- A machine-checkable external operator handoff packet is available, but it is
  not board/RTL/host transport execution evidence.

## Non-Claims

- This is not real malware validation.
- This is not malware detection quality evidence.
- This is not Artix-7 35T or VexRiscv evidence.
- This does not claim full hardware-derived pointer strings.
- This does not claim production streaming/DMA throughput.
- This does not claim board-native DWARF source-line attribution for the
  current board traces.
- This does not claim malware-family detection accuracy.
- This does not claim Genesys2 board trace evidence for the benign controls.
- This does not claim the artifact package copies large raw board artifacts or
  performs a new board run.
- This does not claim per-sample case-study packages are real-malware
  validation, malware detection accuracy, or family coverage.
- This does not claim the external-closure readiness contract completes the
  external board/RTL evidence it describes.
- The BRAM trace-sink claim does not imply complete pointer semantics,
  source-line attribution, process ownership, dynamic mapping, baseline
  alignment, or behavior audit metrics.
- The safe-surrogate BRAM marker-window claim has ten accepted repetitions per
  sample, but it still does not imply full pointer strings, DWARF source-line
  attribution, real-malware validation, or production streaming/DMA throughput.
- The source-line toolchain probe is not a substitute for rebuilding the exact
  board workload ELF with DWARF and rerunning or rejoining board traces.
- UART streaming and AXI DMA/Ethernet streaming are deferred trace-export
  paths, not current throughput evidence.
- The external closure intake gate is currently open and does not close the
  board-native DWARF, full hardware string, streaming/DMA, or board benign
  control blockers without accepted external summaries.
- The external closure plan, embedded templates, and exported template files are
  not external evidence and do not replace the required board/RTL execution.
- The external operator handoff packet is not external evidence and does not
  replace the required board/RTL/host transport execution.
- Bounded-prefix pointer guardrails do not imply full pointer-string
  reconstruction or raw payload release.
