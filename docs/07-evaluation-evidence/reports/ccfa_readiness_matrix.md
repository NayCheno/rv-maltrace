# CCF-A Readiness Matrix

Review date: 2026-06-11

Scope: Digilent Genesys2 + CVA6 only. Artix-7 35T / LiteX / VexRiscv evidence
is historical or tooling reference and is not part of the current Genesys2/CVA6
readiness claim.

Overall status: NOT CCF-A READY. The controlled Genesys2/CVA6 safe-synthetic
and safe-surrogate gate now passes end to end: P0 continuous trace, Phase C
BRAM trace sink, eight safe-surrogate BRAM marker windows, captured-window
drop accounting, disabled-mode pointer guardrails, trusted-companion syscall
semantics, fd/path graph summaries, runtime process/ELF ownership, bounded
source/function attribution summaries, baseline alignment, and behavior-audit
metrics are all checked by `genesys2-current`. A current-quality gate also
checks per-sample artifact paths, baseline transcripts, semantic provenance,
source-line sidecar rows, runtime process maps, and BRAM/drop root consistency.
This is still not a full
paper-ready or real-malware validation claim because hardware user-pointer
snapshot bytes, production runtime slowdown, statistical robustness beyond the
recorded repetitions, and real-malware run artifacts are not claimed.

## Claim Gates

| Gate | Current status | Allowed claims | Non-claims | Artifact root | Run id | Board / CPU / bitstream hash | Command transcript | Checker command |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| simulation claim | PASS for current simulation matrix | Vivado simulation and golden-trace comparison evidence exists for the listed tests. | Simulation evidence is not physical board evidence. | `results/vivado_sim/` | `current-summary` | Board n/a; CPU CVA6 simulation; bitstream n/a | `docs/07-evaluation-evidence/reports/sim_results.md` | `uv run python tools/check_trace_boundary.py` |
| Genesys2 board trace claim | PASS FOR CONTROLLED P0 + SAFE SURROGATES | Physical Genesys2/CVA6 board trace evidence exists for the four P0 safe synthetic Linux workloads with same-window marker scope and strict raw syscall-id entry/return pairing, plus one BRAM marker-window repetition for each of the eight safe syscall-only surrogate workloads. | The P0 ILA run and safe-surrogate BRAM run are bounded controlled workloads, not real malware validation or statistical robustness evidence. | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/` | `20260611-p0-continuous-136bit`; `20260611-safe-surrogate-bram-ring-busywait` | Board Digilent Genesys2; CPU CVA6; P0 bitstream `f5977ac52868b9b6091865851a4cf761ef9f1c24878704c6acd4b724bbb66042`; safe BRAM bitstream `5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc` | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/vivado_program_trace_marker_136bit.log`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/*/rep_01/capture.log` | `uv run python tools/run_check_suite.py --suite genesys2-current` |
| BRAM trace sink claim | PASS FOR PHASE C HELLO/ILLEGAL | `bram_ring` board trace-sink evidence exists for 10/10 `hello_write` repetitions and 10/10 `illegal_instruction` repetitions, with parse success 20/20, expected event recall 100%, sequence/event/drop/wrap/timestamp fields present, and unaccounted drop 0. | This is not full pointer semantics, source-line attribution, process ownership, dynamic mapping, baseline alignment, or behavior metric evidence. | `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/` | `20260611-phase-c-bram-ring-board` | Board Digilent Genesys2; CPU CVA6; bitstream `5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`; LTX `0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c` | `results/board/genesys2_trace_validation/20260611-phase-c-bram-ring-board/vivado_program_bram_trace_marker_clear_on_begin.log` | `uv run python tools/check_genesys2_bram_trace_sink.py --root .` |
| safe-surrogate BRAM trace claim | PASS FOR ONE MARKER-WINDOW REP/SAMPLE | All eight safe syscall-only surrogate workloads have one Genesys2/CVA6 `bram_ring` marker-window capture with begin-marker clearing, matching raw syscall-entry count against the build manifest, no sequence gaps, no wrap, and unaccounted drop 0. | One repetition per sample is not a statistical robustness study and is not real-malware validation. | `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/` | `20260611-safe-surrogate-bram-ring-busywait` | Board Digilent Genesys2; CPU CVA6; bitstream `5ab54e577456532936a117fe89c3e5800758e5e42819d8618db42622ce9447cc`; LTX `0a647dbd67f4921dc4a449f269b94caf9fa407627e840ab386d168775981467c` | `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/*/rep_01/capture.log` | `uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .` |
| trace drop accounting claim | PASS FOR CAPTURED WINDOWS | All listed Genesys2/CVA6 captured trace windows across the four P0 traces plus eight safe-surrogate BRAM marker-window records have zero unaccounted `DROP` events. | Captured-window drop accounting is not real-malware validation or a production streaming throughput claim. | `results/evaluation/genesys2-cva6/current/drop_accounting_summary.json` | `current-drop-accounting-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/` and `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/` | `uv run python tools/check_trace_drop_accounting.py --root .` |
| pointer snapshot guardrail claim | PASS IN DISABLED MODE | Current Genesys2/CVA6 traces satisfy pointer snapshot guardrails in disabled mode: no full memory dump, no kernel memory capture, no default raw pointer payload release, and bounded future policy fields are recorded. | Disabled-mode guardrails are not pointer semantic reconstruction or argument reconstruction evidence. | `results/evaluation/genesys2-cva6/current/pointer_snapshot_guardrails.json` | `current-pointer-guardrails-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/` and `results/board/genesys2_cva6_safe_surrogate/genesys2-cva6-safe-p2-20260610/` | `uv run python tools/check_pointer_snapshot_guardrails.py --root .` |
| syscall semantic / fd-path claim | PASS VIA TRUSTED COMPANION ROUTE | P0 plus eight safe surrogates have controlled syscall semantic reconstruction summaries, 100% openat/execve path reconstruction where applicable, write-prefix recovery where applicable, executable-memory and anti-analysis behavior nodes, and strace/qemu alignment. | This is not hardware user-pointer snapshot evidence; strings come from trusted qemu/strace companion alignment. | `results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json`; `results/evaluation/genesys2-cva6/current/fd_path_graph_summary.json` | `current-phase-def-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/demo/ccfa-safe-20260611/`; `results/demo/ccfa-p0-20260611/` | `uv run python tools/check_syscall_semantic_reconstruction.py --root .`; `uv run python tools/check_fd_path_graph.py --root .` |
| Linux workload claim | PASS FOR CONTROLLED P0 + SAFE SURROGATES | P0 and safe-surrogate workloads have marker-window trace evidence, runtime process maps, target ELF/function attribution, semantic events, behavior graphs, integrated validation, and current evaluation summaries. | Current board trace code maps remain function-level for generated syscall-only ELFs; source-line rate is a source-equivalent sidecar, not DWARF extracted from the board ELF. | `results/evaluation/genesys2-cva6/current/`; `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-runtime-map/` | `current-phase-def-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/evaluation/genesys2-cva6/current/source_line_sidecar.json` | `uv run python tools/check_source_line_attribution.py --root .` |
| marker-scoped runtime attribution claim | PASS FOR CONTROLLED P0 + SAFE SURROGATES | Marker-scoped runtime process/code-site attribution is proven for the four P0 safe synthetic workloads and the eight safe-surrogate runtime process-map captures. | No broad SATP/ASID-backed attribution claim is made from packed marker capture alone. | `results/board/genesys2_trace_validation/20260611-p0-continuous-136bit/`; `results/board/genesys2_trace_validation/20260611-safe-surrogate-runtime-map/` | `20260611-p0-continuous-136bit`; `20260611-safe-surrogate-runtime-map` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/board/genesys2_trace_validation/20260611-safe-surrogate-runtime-map/*/runtime_process_map_helper.log` | `uv run python tools/check_process_elf_ownership.py --root .`; `uv run python tools/check_dynamic_mapping_attribution.py --root .` |
| safe surrogate behavior audit claim | PASS WITH CONTROLLED METRICS | The eight repository-authored safe surrogate / malware-like synthetic samples have bounded hardware, local-code, behavior, integrated, baseline-alignment, evaluation-matrix, and behavior-metric artifacts. | Safe surrogate evidence is not real malware validation and is not malware-family detection quality evidence. | `results/evaluation/genesys2-cva6/current/ccfa_evaluation_matrix.json`; `results/evaluation/genesys2-cva6/current/behavior_audit_metrics.json` | `current-phase-def-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json` | `uv run python tools/check_ccfa_evaluation_matrix.py --root .`; `uv run python tools/check_baseline_alignment.py --root .`; `uv run python tools/check_behavior_audit_metrics.py --root .` |
| current evidence quality gate | PASS FOR NON-REAL-MALWARE CURRENT CHAIN | The current matrix references, baseline logs, semantic openat/execve/write provenance, source-line sidecar rows, runtime process maps, busy-wait safe BRAM root, and drop-accounting root are internally consistent. | This is an integrity gate over existing controlled evidence, not a new hardware pointer-snapshot route or real-malware validation. | `results/evaluation/genesys2-cva6/current/` | `current-quality-20260611` | Board Digilent Genesys2; CPU CVA6; bitstream inherited from source trace runs | `tools/check_ccfa_current_quality.py` | `uv run python tools/check_ccfa_current_quality.py --root .` |
| real malware claim | NOT CLAIMED; CONTAINMENT POLICY PASS | No current Genesys2/CVA6 real-malware validation claim is allowed. The repository has a containment policy for an optional future case study without storing payloads. | Real malware validation, payload execution, malware detection quality, family coverage, and network-enabled malware execution are not demonstrated. Passing containment policy is not validation evidence. | `results/evaluation/genesys2-cva6/current/real_malware_containment.json` | containment-policy-20260611 | Board n/a; CPU n/a; bitstream n/a | `docs/ethics/real_malware_policy.md` | `uv run python tools/check_real_malware_containment.py` |

## Required Report Fields

Every new paper-facing evidence report for this scope must explicitly include:

- allowed claims
- non-claims
- artifact root
- run id
- board / CPU / bitstream hash
- command transcript
- checker command

## Current Blocking Items

- P0 strict continuous trace is closed for the 2026-06-11 136-bit recapture.
- Phase C BRAM trace-sink evidence is closed for 10 `hello_write` and 10
  `illegal_instruction` repetitions, with zero unaccounted drops in those
  windows.
- Safe-surrogate BRAM marker-window trace evidence is closed for one
  repetition of each of the eight safe syscall-only surrogate workloads in
  `results/board/genesys2_trace_validation/20260611-safe-surrogate-bram-ring-busywait/`.
- Captured-window drop accounting is closed for P0 plus safe-surrogate BRAM
  marker-window records.
- Pointer snapshot guardrails are closed in disabled mode. Hardware
  user-pointer snapshot bytes are still not claimed.
- Trusted-companion syscall semantic reconstruction and fd/path graphs are
  closed for P0 plus all eight safe surrogate samples via
  `results/evaluation/genesys2-cva6/current/semantic_reconstruction_summary.json`
  and `fd_path_graph_summary.json`.
- Runtime process/ELF ownership and dynamic mapping summaries are closed for
  the controlled workload scope via
  `process_elf_ownership_summary.json` and
  `dynamic_mapping_attribution_summary.json`.
- Source/function attribution is closed for the controlled gate with a
  source-equivalent debug/no-PIE sidecar and function-level board code maps.
  Current board trace rows still do not claim DWARF source lines.
- Baseline alignment, ablation coverage, behavior-audit metrics, and resource
  timing summaries are closed for the controlled safe-workload gate via
  `ccfa_evaluation_matrix.json`, `baseline_alignment_summary.json`, and
  `behavior_audit_metrics.json`.
- Current-quality integrity is closed for the non-real-malware evidence chain
  via `tools/check_ccfa_current_quality.py`.
- Remaining non-claims: no hardware pointer snapshot route, no production
  runtime slowdown claim, no real-malware validation, no malware-family
  detection accuracy, and no statistical robustness beyond the recorded
  repetitions.

## Current Validation Commands

```powershell
uv run python tools/run_check_suite.py --suite genesys2-current
uv run python tools/run_check_suite.py --suite genesys2-artifacts
uv run python tools/run_check_suite.py --suite genesys2-p0-continuous
uv run python tools/check_ccfa_claim_boundaries.py --root .
uv run python tools/check_genesys2_p0_continuous_trace.py --run-root results/board/genesys2_trace_validation/20260611-p0-continuous-136bit
uv run python tools/check_genesys2_bram_trace_sink.py --root .
uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .
uv run python tools/check_trace_drop_accounting.py --root .
uv run python tools/check_pointer_snapshot_guardrails.py --root .
uv run python tools/check_syscall_semantic_reconstruction.py --root .
uv run python tools/check_fd_path_graph.py --root .
uv run python tools/check_source_line_attribution.py --root .
uv run python tools/check_process_elf_ownership.py --root .
uv run python tools/check_dynamic_mapping_attribution.py --root .
uv run python tools/check_ccfa_evaluation_matrix.py --root .
uv run python tools/check_baseline_alignment.py --root .
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_current_quality.py --root .
uv run python tools/check_real_malware_containment.py
```
