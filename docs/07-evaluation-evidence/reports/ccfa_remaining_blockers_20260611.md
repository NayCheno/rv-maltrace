# CCF-A Remaining Blockers - 2026-06-11

Scope: Digilent Genesys2 + CVA6.

Current-status note (2026-06-12): this report is retained as an intermediate
blocker log. Current paper-facing status is governed by
`ccfa_readiness_matrix.md` and `ccfa_next_closure_plan.md`: 82/100, NOT CCF-A
READY, controlled safe/surrogate evidence only. As of the 2026-06-24 update,
the current non-real-malware gate is `genesys2-current` PASS 83/83.

This report records the blockers remaining after the 2026-06-11 136-bit P0
recapture, Phase C BRAM ring trace-sink board run, safe-surrogate BRAM
marker-window rerun, and Phase D/E/F summary packaging. Repository edits and
fresh Genesys2/CVA6 board runs closed the Phase B P0 strict continuous-trace
blocker, the Phase C `hello_write` / `illegal_instruction` BRAM trace-sink
blocker, the safe-surrogate BRAM marker-window raw-trace blocker, the
captured-window drop-accounting blocker, and the bounded-prefix hardware
ARG_MEM pointer snapshot guardrail blocker. The current controlled
safe-workload gate also
closes the trusted-companion semantic reconstruction, fd/path graph,
process/ELF ownership, dynamic mapping, baseline alignment, evaluation matrix,
behavior metrics, source-line toolchain probe, reproducibility manifest,
artifact-package/fresh-clone reproduction, statistical robustness/failure-retention audit,
streaming/DMA target-baseline and transport-readiness audit, full hardware
pointer-string readiness audit,
and external-closure readiness, intake, plan, preflight, operator-handoff, and summary-template boundary checkers. A local Linux benign-control false-positive
audit now covers five non-network benign workloads, and `board_benign_readiness_summary.json`
defines the future Genesys2 board benign-control collection contract. It still does not claim full hardware-derived
pointer strings, raw payload release, production streaming/DMA trace-sink
throughput, board-native DWARF source-line attribution for the existing traces,
Genesys2 board benign-control false-positive evidence,
or real-malware validation.

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

Safe-surrogate BRAM marker-window evidence is now closed for ten accepted board
repetitions of each of the eight safe syscall-only surrogate workloads.

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
| `file_scan` | 10 | see summary | 7/7 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `batch_open_read_write` | 10 | see summary | 7/7 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `self_copy_sim` | 10 | see summary | 7/7 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `abnormal_syscall_sequence` | 10 | see summary | 7/7 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `illegal_trap` | 10 | see summary | 3/3 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `process_chain` | 10 | see summary | 4/4 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `dynamic_executable_memory` | 10 | see summary | 4/4 minimum per rep | `b0000a11` -> `e0000a11` | 0 |
| `anti_debug_like` | 10 | see summary | 6/6 minimum per rep | `b0000a11` -> `e0000a11` | 0 |

Allowed claim: all eight safe syscall-only surrogate workloads have ten
Genesys2/CVA6 `bram_ring` marker-window capture with begin-marker clearing,
matching raw syscall-entry count against the build manifest, no sequence gaps,
no wrap, and zero unaccounted drop. This is not full hardware pointer-string
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

Pointer snapshot guardrails are now closed for bounded-prefix hardware ARG_MEM.

Command:

```powershell
uv run python tools/check_pointer_snapshot_guardrails.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json`

Allowed claim: the current Genesys2/CVA6 traces satisfy bounded-prefix pointer
snapshot guardrails for openat / execve / write ARG_MEM records: no full memory
dump, no kernel memory capture, no default raw pointer payload release, and no
full hardware-derived pointer-string claim. Trusted companion strings are not
reported as hardware-derived strings.

Hardware pointer byte-prefix audit is now closed for the compact BRAM ARG_MEM
records.

Command:

```powershell
uv run python tools/check_hardware_pointer_prefixes.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/hardware_pointer_prefix_summary.json`

Allowed claim: 30 board pointer-snapshot repetitions expose 51 hardware pointer
groups and 1156 compact ARG_MEM bytes for openat / write / execve. Gapped
fragments are recorded as fragments with gaps; only contiguous observed bytes
are reported as bounded hardware prefixes. `full_string_claimed=false`.

Full hardware pointer-string readiness is now closed for the local readiness
contract.

Command:

```powershell
uv run python tools/check_genesys2_pointer_string_readiness.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json`

Allowed claim: the current prefix and guardrail evidence has a machine-checkable
future full-string acceptance contract. Future `hardware_pointer_strings_summary.json`
evidence must provide contiguous bytes from offset 0 through a terminator or
documented bounded truncation, mem_last/terminator evidence, artifact hashes,
redaction policy, kernel filtering, and no companion or gapped-fragment
substitution. This is readiness only; `full_hardware_pointer_strings_claimed=false`.

Current reproducibility linkage is now closed for the controlled evidence
package.

Command:

```powershell
uv run python tools/check_genesys2_reproducibility_manifest.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/reproducibility_manifest.json`

Allowed claim: paper-facing report rows are linked to summary JSON hashes,
manifest-selected raw board roots, raw file counts, and checker commands. This
does not add real-malware validation or select dated roots by chronology.

Lightweight artifact packaging and fresh-clone reproduction commands are now
closed for the controlled evidence package.

Command:

```powershell
uv run python tools/check_genesys2_artifact_package.py --root .
uv run python tools/reproduce_genesys2_current.py --full --dry-run
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/artifact_package_manifest.json`

Allowed claim: current paper-facing reports, checker entrypoints, summary
artifacts, reproduction tools, and referenced raw board roots are hash-linked in
a lightweight package manifest. The fresh-clone entrypoint exposes quick and
full command sets for rerunning the current controlled gates. This does not
copy large raw board artifacts, perform a new board run, or replace an external
reviewer executing the commands.

Remaining non-real-malware external closure standards are now fixed in a
machine-checkable readiness contract.

Command:

```powershell
uv run python tools/check_genesys2_external_closure_readiness.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/external_closure_readiness.json`

Allowed claim: the remaining non-real-malware blockers have explicit required
artifacts, acceptance criteria, future checker contracts, and no-substitution
rules. The recorded blockers are board-native DWARF source lines, full
hardware-derived pointer strings, production streaming/DMA trace-sink
throughput, and Genesys2 board benign-control evidence. This is readiness
contract evidence only; it does not execute new board or RTL experiments and
does not mark those blockers complete.

Optional external closure summary intake is now machine-checkable.

Command:

```powershell
uv run python tools/check_genesys2_external_closure_intake.py --root .
```

Result: BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED.

Summary artifact:
`results/evaluation/genesys2-cva6/current/external_closure_intake.json`

Allowed claim: the repository now has a strict intake gate for optional future
external summaries under
`results/evaluation/genesys2-cva6/current/external_closure/`. The current
status is `BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED`, with 2 accepted, 0 open, and 2
invalid external blockers. This does not mark full hardware pointer strings or
production streaming/DMA throughput complete.

The remaining external closure work now has an executable plan.

Command:

```powershell
uv run python tools/check_genesys2_external_closure_plan.py --root .
```

Result: PASS PLAN ONLY.

Summary artifact:
`results/evaluation/genesys2-cva6/current/external_closure_plan.json`

Allowed claim: the repository now records concrete operator inputs, preflight
commands, collection commands, packaging commands, validation commands, and
template-only external summaries for the four non-real-malware blockers. The
embedded templates are not evidence, and this plan does not close
board-native DWARF source lines, full hardware pointer strings, production
streaming/DMA throughput, or Genesys2 board benign-control evidence.

External summary templates are now exported and checked as non-evidence
operator scaffolding.

Command:

```powershell
uv run python tools/prepare_genesys2_external_summary.py --check-templates
```

Result: PASS TEMPLATE NON-EVIDENCE.

Template root:
`results/evaluation/genesys2-cva6/current/external_closure_templates/`

Allowed claim: template files exist for the four non-real-malware external
summaries and still match the generator. The templates remain
`TEMPLATE_NOT_EVIDENCE`; a candidate summary must be validated and accepted by
`external_closure_intake.json` before any blocker can close.

External operator handoff is now machine-checkable.

Command:

```powershell
uv run python tools/check_genesys2_external_operator_packet.py --root .
```

Result: PASS OPERATOR HANDOFF.

Summary artifact:
`results/evaluation/genesys2-cva6/current/external_operator_packet.json`

Report:
`docs/07-evaluation-evidence/reports/ccfa_external_operator_packet.md`

Allowed claim: the remaining non-real-malware external blockers now have a
single operator packet with execution order, required evidence artifact kinds,
preflight/collection/packaging/intake steps, and no-substitution rules. This
is not board/RTL/host transport execution evidence and does not close any open
external blocker.

Source-line toolchain probing is now closed for the debug/no-PIE RISC-V Linux
toolchain path.

Command:

```powershell
uv run python tools/check_source_line_toolchain_probe.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/source_line_toolchain_probe.json`

Allowed claim: Docker `linux-behavior` can compile a RISC-V debug/no-PIE ELF
with `.debug_line` sections and resolve it through
`riscv64-linux-gnu-addr2line`. The same artifact records that the inspected
current board ELFs exist but do not carry DWARF debug sections, so current board
trace code attribution remains function-level.

Trace-export decision boundary is now closed for the current evidence route.

Command:

```powershell
uv run python tools/check_trace_export_decision.py --root .
```

Result: PASS.

Allowed claim: the current first/current hardware trace route remains BRAM ring
buffer plus ILA/JTAG dump. UART streaming and AXI DMA/Ethernet streaming are
explicitly deferred and are not production-throughput evidence.

Benign-control false-positive audit is now closed for the local Linux control
scope.

Command:

```powershell
uv run python tools/check_benign_control_summary.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/benign_control_summary.json`

Allowed claim: five non-network benign workloads have strace-derived semantic
events, behavior graphs, behavior audits, documented benign rule overlaps, and
unexpected false-positive rate 0.0. This is local Linux control evidence, not
Genesys2 board trace evidence.

Per-sample case-study packaging is now closed for the controlled P0 and
safe-surrogate evidence chain.

Command:

```powershell
uv run python tools/check_ccfa_case_study_manifest.py --root .
```

Result: PASS.

Summary artifact:
`results/evaluation/genesys2-cva6/current/case_study_manifest.json`

Allowed claim: every P0 and safe-surrogate sample now has a
`case_study_summary.json` with hardware trace, semantic reconstruction, local
code attribution, baseline comparison, audit decision, metrics, limitations,
and reviewer traceability. This is controlled safe/surrogate evidence, not
real-malware validation or malware detection accuracy.

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
| Phase D pointer semantics | PASS via `semantic_reconstruction_summary.json`, bounded-prefix hardware ARG_MEM guardrails, and trusted qemu/strace companion semantics for P0 and all eight safe surrogates. | Full hardware-derived pointer strings are not claimed. | `tools/check_syscall_semantic_reconstruction.py` |
| Phase D fd/path graph | PASS via `fd_path_graph_summary.json`; controlled openat/execve path reconstruction is 100% where applicable. | FD/path strings are companion-derived, not hardware ARG_MEM bytes. | `tools/check_fd_path_graph.py` |
| Phase E source attribution | PASS via `source_line_attribution_summary.json` and `source_line_sidecar.json`; board traces remain function-level and sidecar source-line scoped. | Current board ELFs do not carry DWARF source-line attribution. | `tools/check_source_line_attribution.py` |
| Phase E source-line toolchain probe | PASS via `source_line_toolchain_probe.json`, which proves the debug/no-PIE `addr2line` path and records no-DWARF current board ELFs. | This is not board-native source-line attribution for the already captured board traces. | `tools/check_source_line_toolchain_probe.py` |
| Phase E process/ELF ownership | PASS via `process_elf_ownership_summary.json` using P0 and safe-surrogate Genesys2 runtime process maps. | No broad SATP/ASID-backed attribution claim is made. | `tools/check_process_elf_ownership.py` |
| Phase E dynamic mapping | PASS via `dynamic_mapping_attribution_summary.json`; host/control dynamic loader cases are scoped separately from board syscall-only EXEC binaries. | PIE/shared-library evidence is host/control scoped, not current board workload scoped. | `tools/check_dynamic_mapping_attribution.py` |
| Phase F evaluation matrix | PASS via `ccfa_evaluation_matrix.json`, `workload_manifest.json`, and per-sample metric summaries. | Not a real-malware or production throughput matrix. | `tools/check_ccfa_evaluation_matrix.py` |
| Phase F baseline alignment | PASS via `baseline_alignment_summary.json` across event-only, guardrailed bounded-prefix ARG_MEM, trusted companion, strace, qemu-strace, and software-sidecar rows. | Pointer snapshot row is not a full memory dump or full hardware string route. | `tools/check_baseline_alignment.py` |
| Phase F behavior metrics | PASS via `behavior_audit_metrics.json` for controlled safe workloads. | Metrics are behavior-audit metrics, not malware-family detection accuracy. | `tools/check_behavior_audit_metrics.py` |
| Phase F statistical robustness | PASS via `statistical_robustness_summary.json`: 122 accepted controlled board repetitions across 12 P0/safe-surrogate samples, four retained failed P0 attempts, zero accepted-window unaccounted DROP/wrap/dropped count, 12 case studies, and five local benign controls with 0.0 unexpected false-positive rate. | This is not randomized workload generalization, real-malware validation, production long-run stability, or Genesys2 board benign-control evidence. | `tools/check_genesys2_statistical_robustness.py` |
| Phase F streaming/DMA target baseline | PASS via `streaming_dma_target_summary.json`: 122 accepted marker-window repetitions define p50/p95/p99 compact event-byte targets of `0.006971521218847351` / `0.01981178801386825` / `0.020308813427709585` bytes/cycle and a future `1.5 * p99` sustained transport threshold for non-BRAM transport experiments. | This is a local target baseline only; it is not production streaming/DMA throughput evidence and still requires external host receiver, timing, resource, and noninterference artifacts. | `tools/check_genesys2_streaming_dma_target.py` |
| Phase F streaming/DMA transport readiness | PASS via `streaming_dma_readiness_summary.json`: allowed non-BRAM transport kinds, exact clock conversion, host receiver fields, required artifact kinds, summary fields, and no-substitution boundaries are fixed for future external runs. | Readiness only; it does not complete production streaming/DMA throughput evidence. | `tools/check_genesys2_streaming_dma_readiness.py` |
| Phase F full hardware pointer-string readiness | PASS via `pointer_string_readiness_summary.json`: future full-string summary schema, required artifact kinds, offset-zero contiguity, terminator/mem_last evidence, redaction policy, and no-substitution boundaries are fixed for future RTL/board runs. | Readiness only; it does not complete full hardware-derived pointer-string evidence. | `tools/check_genesys2_pointer_string_readiness.py` |
| Phase F case-study package | PASS via `case_study_manifest.json` and per-sample `case_study_summary.json` files for all P0 and safe-surrogate samples. | Controlled case studies only; not real-malware validation, detection accuracy, full hardware strings, board-native DWARF, or production streaming/DMA. | `tools/check_ccfa_case_study_manifest.py` |
| Phase F benign control | PASS via `benign_control_summary.json` for five local Linux benign workloads. | This is not Genesys2 board trace evidence or real-malware detection accuracy. | `tools/check_benign_control_summary.py` |
| Phase F board benign readiness | PASS via `board_benign_readiness_summary.json`, which records the future Genesys2 board benign-control sample set, required artifacts, acceptance criteria, and no-substitution boundary. | Readiness only; it does not complete Genesys2 board benign-control false-positive evidence. | `tools/check_genesys2_board_benign_readiness.py` |
| Phase F current quality | PASS via a strict artifact-integrity gate over the non-real-malware current evidence chain. | This does not add full hardware pointer strings or real-malware validation. | `tools/check_ccfa_current_quality.py` |
| Phase F reproducibility manifest | PASS via `reproducibility_manifest.json`, which links reports to summary hashes, raw roots, raw file counts, and checker commands. | This is controlled-package reproducibility linkage, not real-malware validation. | `tools/check_genesys2_reproducibility_manifest.py` |
| Phase F artifact package | PASS via `artifact_package_manifest.json` and `tools/reproduce_genesys2_current.py`. | Lightweight manifest package only; raw board artifacts are referenced, not copied. | `tools/check_genesys2_artifact_package.py` |
| Phase F external closure readiness | PASS via `external_closure_readiness.json`, which records required artifacts, acceptance criteria, future checker contracts, and no-substitution rules for the remaining non-real-malware external blockers. | Readiness contract only; it does not complete board-native DWARF, full hardware strings, streaming/DMA throughput, or board benign-control evidence. | `tools/check_genesys2_external_closure_readiness.py` |
| Phase F external closure intake | BLOCKED via `external_closure_intake.json`, which records optional future external-summary paths and strict acceptance checks. | Current `BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED` status means three external summaries are accepted, while production streaming/DMA remains invalid and open. | `tools/check_genesys2_external_closure_intake.py` |
| Phase F external closure plan | PASS PLAN ONLY via `external_closure_plan.json`, which records executable runbooks and template-only summaries for the remaining non-real-malware external blockers. | Plan templates are not evidence and do not replace board/RTL execution. | `tools/check_genesys2_external_closure_plan.py` |
| Phase F external closure local preflight | PASS LOCAL PREFLIGHT via `external_closure_preflight.json`, which records local script, dry-run, schema/path, and no-substitution readiness for the remaining external blockers. | Preflight is not external execution and does not replace board/RTL evidence or accepted external summaries. | `tools/check_genesys2_external_closure_preflight.py` |
| Phase F external operator handoff | PASS OPERATOR HANDOFF via `external_operator_packet.json` and `ccfa_external_operator_packet.md`, which record per-blocker execution order, required artifact kinds, candidate-summary packaging, and intake acceptance steps. | Operator handoff is not external execution and does not replace board/RTL/host transport evidence or accepted external summaries. | `tools/check_genesys2_external_operator_packet.py` |
| Phase F external summary templates | PASS TEMPLATE NON-EVIDENCE via `external_closure_templates/*.template.json`, checked by `prepare_genesys2_external_summary.py`. | Templates are operator scaffolding only and cannot be copied into intake as accepted evidence. | `tools/prepare_genesys2_external_summary.py --check-templates` |
| Phase G containment policy | Optional real-malware containment policy is present and can be checked without introducing payloads. | Keep policy and containment separate from validation evidence. | `tools/check_real_malware_containment.py` |
| Phase G real-malware validation | Real malware is intentionally not a main-line claim, and no real-malware run artifacts are present. | Only use as optional case study after authorization, isolated execution, hash-only metadata, and sanitized reports. | `tools/check_real_malware_validation_gate.py` |

## Current Gate Audit

After the BRAM trace-sink board run, safe-surrogate busy-wait rerun, and
Phase D/E/F summary packaging, the current repository gate state is:

| Gate | Command | Result |
| --- | --- | --- |
| current Genesys2/CVA6 gate | `uv run python tools/run_check_suite.py --suite genesys2-current` | PASS 83/83, including Phase 4.4 baseline pass criteria, Phase B/C/D/E/F controlled gates, trace-export boundary, bounded fuzz trace invariant fixtures, directed trace-correctness corpus, local code-analysis fixture provenance, semantic provenance, source-line toolchain probe, debug ELF source-line rerun readiness, board benign-control readiness, evaluation-plan synchronization, review-closure audit, benign control, statistical robustness/failure-retention audit, streaming/DMA target-baseline and transport-readiness audit, full hardware pointer-string readiness and accepted scoped evidence audit, case-study packaging, hardware pointer prefix audit, software tracer-visibility baseline, reproducibility manifest, artifact package, local raw-artifact release archive, recursive artifact integrity, bootrom counter-delegation build artifact validation, cycle-source probe, cycle-source diagnostics, counter-access matrix, Docker Linux rebuild manifest, local boot SD-card image manifest, SD-card write-target preflight truthful-BLOCKED guard, host-side Vivado part/board preflight guard, trace-marker programming guard, read-only JTAG RAM-boot probe truthful-BLOCKED guard, current-bitstream strict-SRET board smoke guard, live SD-card Linux manifest, live kernel-config export truthful-BLOCKED guard, Linux counter-path preflight truthful-BLOCKED guard, host-side LaTeX skeleton-build guard, official-image capability/workload/runtime-map/fork-exec/ASLR-repeatability/oracle guards, external closure readiness/intake/plan/preflight/operator-handoff/template guard, current-quality integrity, and real-malware containment |
| trace-export decision boundary | `uv run python tools/check_trace_export_decision.py --root .` | PASS, BRAM ring plus ILA/JTAG selected; UART/DMA streaming deferred |
| BRAM trace sink | `uv run python tools/check_genesys2_bram_trace_sink.py --root .` | PASS |
| safe-surrogate BRAM marker-window trace | `uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .` | PASS |
| trace drop accounting | `uv run python tools/check_trace_drop_accounting.py --root .` | PASS |
| statistical robustness audit | `uv run python tools/check_genesys2_statistical_robustness.py --root .` | PASS, 122 accepted controlled board repetitions, 4 retained failed P0 attempts, zero accepted-window DROP/wrap/dropped count, and 5 local benign controls with unexpected FP rate 0.0 |
| streaming/DMA target baseline | `uv run python tools/check_genesys2_streaming_dma_target.py --root .` | PASS, p50/p95/p99 targets `0.006971521218847351` / `0.01981178801386825` / `0.020308813427709585` compact event bytes per marker-window cycle; required future sustained threshold `0.030463220141564377` event bytes/cycle before exact-clock conversion; production throughput remains external/open |
| streaming/DMA transport readiness | `uv run python tools/check_genesys2_streaming_dma_readiness.py --root .` | PASS, non-BRAM transport contract, exact clock conversion, host receiver fields, artifact kinds, and no-substitution boundary; production throughput remains external/open |
| syscall semantic reconstruction | `uv run python tools/check_syscall_semantic_reconstruction.py --root .` | PASS |
| pointer snapshot guardrails | `uv run python tools/check_pointer_snapshot_guardrails.py --root .` | PASS, bounded-prefix ARG_MEM for openat / execve / write; no full hardware strings |
| hardware pointer prefix audit | `uv run python tools/check_hardware_pointer_prefixes.py --root .` | PASS, 51 hardware pointer groups / 1156 compact ARG_MEM bytes across 30 board repetitions; no full-string claim |
| full hardware pointer-string readiness | `uv run python tools/check_genesys2_pointer_string_readiness.py --root .` | PASS, future full-string contract requires offset-zero contiguous bytes, terminator/mem_last evidence, redaction policy, artifact hashes, and no companion or gapped-fragment substitution; full-string evidence remains external/open |
| benign-control false-positive audit | `uv run python tools/check_benign_control_summary.py --root .` | PASS, five local Linux benign controls; unexpected FP rate 0.0 with documented benign overlap |
| board benign-control readiness | `uv run python tools/check_genesys2_board_benign_readiness.py --root .` | PASS, five expected future board benign workloads and artifact-backed no-substitution contract; board benign evidence remains external/open |
| fd/path graph | `uv run python tools/check_fd_path_graph.py --root .` | PASS |
| source-line attribution | `uv run python tools/check_source_line_attribution.py --root .` | PASS, sidecar-scoped source lines; board traces function-level |
| source-line toolchain probe | `uv run python tools/check_source_line_toolchain_probe.py --root .` | PASS, debug/no-PIE `.debug_line` path proven; current board ELFs no-DWARF |
| process/ELF ownership | `uv run python tools/check_process_elf_ownership.py --root .` | PASS |
| dynamic mapping attribution | `uv run python tools/check_dynamic_mapping_attribution.py --root .` | BLOCKED_BOARD_DYNAMIC_MAPPING_CASES accepted by checker; static/no-PIE/fork-exec cases remain supported, while PIE/load-bias, dynamic-loader, shared-library, and stripped-ELF board evidence still require exact board runtime maps |
| CCF-A evaluation matrix | `uv run python tools/check_ccfa_evaluation_matrix.py --root .` | PASS |
| baseline alignment | `uv run python tools/check_baseline_alignment.py --root .` | PASS |
| behavior audit metrics | `uv run python tools/check_behavior_audit_metrics.py --root .` | PASS |
| per-sample case-study package | `uv run python tools/check_ccfa_case_study_manifest.py --root .` | PASS, all 12 P0/safe-surrogate samples have traceable case-study summaries |
| current-quality integrity | `uv run python tools/check_ccfa_current_quality.py --root .` | PASS |
| reproducibility manifest | `uv run python tools/check_genesys2_reproducibility_manifest.py --root .` | PASS |
| artifact package / fresh-clone commands | `uv run python tools/check_genesys2_artifact_package.py --root .`; `uv run python tools/reproduce_genesys2_current.py --full --dry-run` | PASS, lightweight manifest package with quick/full fresh-clone command sets |
| external closure readiness contract | `uv run python tools/check_genesys2_external_closure_readiness.py --root .` | PASS, machine-checkable requirements for remaining non-real-malware external blockers; not completion evidence |
| external closure intake gate | `uv run python tools/check_genesys2_external_closure_intake.py --root .` | BLOCKED, 2 accepted and 2 invalid external summaries; invalid summaries remain blockers and are not counted as closed |
| external closure execution plan | `uv run python tools/check_genesys2_external_closure_plan.py --root .` | PASS PLAN ONLY, executable runbooks and templates are present but are not external evidence |
| external closure local preflight | `uv run python tools/check_genesys2_external_closure_preflight.py --root .` | PASS LOCAL PREFLIGHT, local scripts/dry-run hooks/schema paths/no-substitution guardrails are ready; not external evidence |
| external operator handoff packet | `uv run python tools/check_genesys2_external_operator_packet.py --root .` | PASS OPERATOR HANDOFF, per-blocker execution order and artifact-kind handoff are present; not external evidence |
| external summary templates | `uv run python tools/prepare_genesys2_external_summary.py --check-templates` | PASS TEMPLATE NON-EVIDENCE, templates are exported outside intake and remain scaffolding only |
| real-malware containment | `uv run python tools/check_real_malware_containment.py --root .` | PASS |
| real-malware validation | `uv run python tools/check_real_malware_validation_gate.py` | BLOCKED, no authorized run artifacts and no payloads in repo |

The D/E/F summaries are now explicit artifacts under
`results/evaluation/genesys2-cva6/current/`. They are bounded by the non-claims
above and must not be described as full hardware pointer-string evidence,
production streaming/DMA throughput evidence, board-native DWARF source-line
attribution for existing traces, real-malware validation, or malware-family
detection accuracy.

## Non-Claims

- P0 strict continuous trace closure does not make the project CCF-A ready.
- The new P0 recapture is not real malware validation.
- The new P0 recapture is not malware detection quality evidence.
- The BRAM trace-sink run closes only the scoped Phase C `hello_write` and
  `illegal_instruction` repetition requirement.
- Captured-window drop accounting does not prove continuous trace for
  semantic reconstruction or full safe-surrogate evaluation.
- The safe-surrogate BRAM marker-window run uses safe syscall-only surrogate
  binaries; it is not real-malware validation.
- Bounded-prefix pointer snapshot guardrails do not prove full hardware-derived
  pointer strings or raw pointer payload release.
- Full hardware pointer-string readiness is a local future-closure contract; it
  does not prove full hardware-derived pointer strings or replace RTL/board
  full-string artifacts.
- Source-line toolchain probing does not prove board-native source-line
  attribution for current traces unless the exact captured board ELF carries
  DWARF and the trace/code-map join uses that ELF.
- Benign-control false-positive evidence is local Linux strace/control evidence,
  not a Genesys2 board benign workload run.
- Artifact-package evidence is a lightweight manifest/fresh-clone command
  package; it does not copy large raw board artifacts or perform a new board
  run.
- Per-sample case-study packages are controlled safe/surrogate evidence; they
  do not claim real-malware validation or detection accuracy.
- External-closure readiness evidence is a contract for future board/RTL
  evidence; it does not complete board-native DWARF source lines, full hardware
  pointer strings, production streaming/DMA throughput, or board benign-control
  evidence.
- The current trace-export route is BRAM ring plus ILA/JTAG; UART streaming and
  AXI DMA/Ethernet streaming remain deferred and unmeasured for throughput.
- External closure intake validates future summaries but currently records
  `BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED`; it is not external evidence by itself.
- External closure plan templates are not evidence and do not substitute for
  board/RTL execution or external reviewer artifacts.
- External operator handoff is not evidence and does not substitute for
  board/RTL execution, host transport logs, or external reviewer artifacts.
- External summary templates under `external_closure_templates/` are not intake
  evidence and must be replaced by accepted board/RTL-derived summaries before
  any external blocker can close.
- Safe-surrogate behavior audit remains separate from real malware validation.
- Passing containment policy is not real-malware validation.
