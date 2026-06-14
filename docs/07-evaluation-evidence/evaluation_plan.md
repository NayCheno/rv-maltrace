# Evaluation Plan

This document turns `docs/09-planning/next-plan.md` Section 9 and Stage 3 into a checkable
evaluation plan and current-evidence index. It is an artifact-routing document,
not evaluation evidence by itself. Status rows below describe the scoped
Genesys2/CVA6 evidence currently accepted by the checker suite; they do not make
the project CCF-A paper-ready.

## Scope

The evaluation target is RV-MalScope: hardware-assisted semantic behavior
tracing on RISC-V/CVA6. The MVP evaluation covers committed syscall,
control-flow, trap, CSR, privilege, and drop accounting events. Paper-level
evaluation adds syscall return correlation, pointer semantic reconstruction,
behavior graph recovery, evasion-resistance tests, hardware cost measurement,
and comparisons against software or simulator baselines.

## Research Questions

| ID | Question | Required Evidence | Status |
| --- | --- | --- | --- |
| RQ1 | Correctness: can committed syscall/control-flow/trap/context events be captured accurately? | `results/evaluation/genesys2-cva6/current/latest_manifest.json`, P0 continuous traces, BRAM marker-window summaries, golden comparison logs, and `genesys2-current` gates | PASS_CURRENT_GENESYS2_CONTROLLED |
| RQ2 | Semantic reconstruction: can syscall arguments, return values, paths, fd behavior, and behavior graphs be recovered? | `semantic_reconstruction_summary.json`, `fd_path_graph_summary.json`, bounded hardware `ARG_MEM` prefix summaries, trusted companion alignment, semantic JSON, graph JSON, and reports | PASS_CURRENT_BOUNDED_SEMANTICS |
| RQ3 | Low perturbation: how much runtime and timing perturbation is introduced compared with software tracing? | `production_runtime_benchmark.json`, `resource_timing_summary.json`, paired trace-off/event-only/BRAM runs, and baseline alignment summaries | PASS_CURRENT_RUNTIME_BENCHMARK |
| RQ4 | Evasion resistance: are anti-debug, timing, direct-syscall, and packed-code samples less able to detect or bypass tracing? | controlled safe malware-like suite manifests, per-sample traces, expected behaviors, behavior audits, and baseline notes | PASS_CONTROLLED_SAFE_SURROGATE |
| RQ5 | Hardware cost: what are LUT, FF, BRAM, Fmax, trace bandwidth, and drop-rate costs? | Vivado utilization/timing reports, `docs/07-evaluation-evidence/reports/resource_report.md`, trace bandwidth summaries, drop accounting, and external streaming/DMA readiness | PASS_CURRENT_BRAM_COST_OPEN_STREAMING_DMA |
| RQ6 | Malware behavior usefulness: are key malware-like behaviors reconstructed clearly enough for audit or rules? | `case_study_manifest.json`, per-sample behavior graph evidence, and manually reviewable semantic summaries | PASS_SAFE_CASE_STUDIES_NON_REAL |

## Baselines

Each baseline must be recorded as a separate run configuration. Performance
claims must not reuse a perturbed ground-truth run as the uninstrumented runtime.

| Baseline | Purpose | Required Artifact | Status |
| --- | --- | --- | --- |
| `strace` / `ptrace` | syscall semantic ground truth and perturbation comparison | command transcript, syscall log, paired no-`strace` run metadata in `baseline_alignment_summary.json` | PASS_CURRENT_STRACE_ALIGNMENT |
| eBPF-only | software kernel-side semantic comparison when kernel support exists | program, kernel config, helper log, overhead summary | OPTIONAL_DEFERRED_EBPF |
| QEMU plugin | simulator trace comparison | qemu/strace transcript and timing note in current baseline logs; full QEMU-plugin baseline remains optional | PASS_CURRENT_QEMU_STRACE_ONLY |
| software instrumentation | detectability and overhead comparison | source-equivalent sidecar, binary/source hash, and trace output | PASS_SOURCE_SIDECAR_BASELINE |
| RV-MalScope event-only | hardware MVP ablation | BRAM/ILA event trace JSONL, summary, resource row | PASS_CURRENT_EVENT_ONLY |
| RV-MalScope + pointer snapshot | hardware semantic enrichment ablation | bounded hardware `ARG_MEM` prefix trace, guardrails, bandwidth/drop summary | PASS_BOUNDED_ARG_MEM_PREFIX_OPEN_FULL_STRINGS |
| RV-MalScope + kernel helper/eBPF companion | fallback semantic enrichment ablation | helper log, hardware trace, alignment report | PASS_TRUSTED_COMPANION_OPTIONAL_EBPF |

## Datasets

| Class | Contents | Required Manifest | Status |
| --- | --- | --- | --- |
| Class A | microbenchmarks for syscall correctness, trap correctness, control-flow correctness, and pointer reconstruction | `experiments/linux_behavior/recovery_targets.json` plus matching simulation or board traces | PASS_CURRENT_P0_CONTROLLED |
| Class B | benign Linux programs such as busybox/coreutils-like file, process, memory, and non-network workloads | `experiments/linux_behavior/benign/manifest.json` plus `benign_control_summary.json`; Genesys2 board benign control remains external | PASS_LOCAL_LINUX_BENIGN_OPEN_BOARD_BENIGN |
| Class C | controlled malware-like programs for anti-debug, timing checks, direct syscall, packed code, mmap/mprotect executable memory, fork/exec chains, file scanning, and self-copy/dropper-like behavior | `experiments/linux_behavior/malware_like/manifest.json` plus current case-study package | PASS_SAFE_SURROGATE_NON_REAL |

Real malware samples are optional and must stay isolated from the main success
criteria until legal, ethical, and containment procedures are documented.

### 35T/VexRiscv Matrix Route

The 35T line has a separate LiteX/VexRiscv experiment route so paper artifacts
do not blur into CVA6 production RTL claims. The route is invoked with
`uv run rvmt exp:35t --stage all --run-id <run-id> --port COM5 --baud 921600 --reps 5`
and writes to `results/experiments/35t/<run-id>/`. It covers five non-network
benign workloads and eight malware-like synthetic samples, excludes
`small_network_client`, and labels the rule result as malware-like behavior
audit accuracy rather than real malware detection accuracy.

## Metrics

| Metric | Definition | Gate |
| --- | --- | --- |
| syscall precision / recall | match between RV-MalScope syscall sequence and the expected or ground-truth sequence | controlled tests target exact match; Linux workload differences require explanation |
| argument reconstruction accuracy | recovered scalar arguments and return values compared with expected behavior | controlled tests target exact match |
| path string reconstruction accuracy | recovered `openat`/`execve`/similar pointer strings compared with expected paths | controlled tests target exact match |
| fd graph accuracy | recovered fd-to-file/socket relationships compared with known program behavior | mismatches require triage notes |
| runtime overhead | application runtime compared with baseline run | report median, spread, and configuration |
| cycle-level perturbation | cycle or timestamp delta introduced by trace mode | report method and limitations |
| trace drop rate | dropped event count and bytes per event/run | correctness mode requires zero unaccounted drops |
| trace bytes per syscall | trace volume normalized by syscall count | report per workload and mode |
| LUT / FF / BRAM overhead | post-synthesis or post-implementation resource delta | report absolute and percentage deltas |
| Fmax degradation | timing delta between baseline and trace-enabled builds | report clock target and slack |
| anti-analysis detection outcome | whether the sample detects or bypasses the tracer | report per sample and baseline |

## Artifact Gates

| Gate | Required Artifacts | Status |
| --- | --- | --- |
| simulation correctness | `results/vivado_sim/summary.json`, per-test `trace.jsonl`, golden comparison logs | PASS_REPOSITORY_SIM |
| direct-core CVA6 smoke | `results/vivado_sim/cva6_*` traces and logs from `uv run rvmt sim:cva6-smoke` | PASS_DIRECT_CORE |
| board baseline | `results/board/genesys2_baseline/<run-id>/` transcript, bitstream metadata, UART/tohost evidence | PASS_GENESYS2_BASELINE |
| board trace | `results/board/genesys2_trace_validation/<run-id>/` BRAM/ILA/UART dump, decoded JSONL, expected comparison | PASS_CURRENT_BRAM_MARKER_WINDOW |
| Linux syscall trace | workload logs, hardware traces, `strace`/qemu ground-truth run, and alignment report under the current evaluation root | PASS_CONTROLLED_TRACE_ALIGNMENT |
| semantic reconstruction | `semantic_events.json`, `behavior_graph.json`, and recovery summaries per workload | PASS_CURRENT_SEMANTIC_SUMMARIES |
| evasion suite | per-sample manifest row, trace, baseline comparison, and controlled detection outcome | PASS_SAFE_SURROGATE_AUDIT |
| hardware cost | Vivado utilization/timing reports and generated resource summary | PASS_CURRENT_RESOURCE_TIMING |
| ablation study | event-only, pointer snapshot, and helper/companion results compared under the same workload manifest | PASS_CURRENT_BASELINE_ALIGNMENT |
| case studies | manually reviewable safe malware-like or audit-oriented behavior graph narratives with trace references | PASS_CURRENT_CASE_STUDIES |
| artifact package | scripts, manifests, expected outputs, and reproduction notes | PASS_CURRENT_REPRO_PACKAGE |

## Current Evidence Index

The current non-real-malware Genesys2/CVA6 evidence is accepted through these
machine-checked artifacts:

| Artifact | Role | Checker |
| --- | --- | --- |
| `results/evaluation/genesys2-cva6/current/ccfa_evaluation_matrix.json` | sample-to-artifact matrix, baselines, ablations, trace paths, metric paths | `uv run python tools/check_ccfa_evaluation_matrix.py --root .` |
| `results/evaluation/genesys2-cva6/current/baseline_alignment_summary.json` | strace, qemu-strace, event-only, bounded pointer snapshot, trusted companion, and sidecar baseline alignment | `uv run python tools/check_baseline_alignment.py --root .` |
| `results/evaluation/genesys2-cva6/current/behavior_audit_metrics.json` | controlled safe-workload behavior audit metrics and benign false-positive boundary | `uv run python tools/check_behavior_audit_metrics.py --root .` |
| `results/evaluation/genesys2-cva6/current/statistical_robustness_summary.json` | controlled board repetition counts, retained failed attempt audit, workload class coverage, and non-generalization boundary | `uv run python tools/check_genesys2_statistical_robustness.py --root .` |
| `results/evaluation/genesys2-cva6/current/streaming_dma_target_summary.json` | cycle-normalized p95 compact event-byte production target for future streaming/DMA throughput evidence | `uv run python tools/check_genesys2_streaming_dma_target.py --root .` |
| `results/evaluation/genesys2-cva6/current/streaming_dma_readiness_summary.json` | future non-BRAM production streaming/DMA transport collection readiness and no-substitution boundary | `uv run python tools/check_genesys2_streaming_dma_readiness.py --root .` |
| `results/evaluation/genesys2-cva6/current/pointer_string_readiness_summary.json` | future gap-free full hardware pointer-string collection readiness and no-substitution boundary | `uv run python tools/check_genesys2_pointer_string_readiness.py --root .` |
| `results/evaluation/genesys2-cva6/current/debug_elf_readiness_summary.json` | 12-sample debug/no-PIE ELF, `.debug_line`, and code-map readiness for a future board source-line rerun | `uv run python tools/check_genesys2_debug_elf_readiness.py --root .` |
| `results/evaluation/genesys2-cva6/current/board_benign_readiness_summary.json` | future Genesys2 board benign-control collection readiness and no-substitution boundary | `uv run python tools/check_genesys2_board_benign_readiness.py --root .` |
| `results/evaluation/genesys2-cva6/current/case_study_manifest.json` | per-sample controlled case-study package for P0 and safe-surrogate workloads | `uv run python tools/check_ccfa_case_study_manifest.py --root .` |
| `results/evaluation/genesys2-cva6/current/production_runtime_benchmark.json` | trace-off/event-only/BRAM/pointer-disabled board runtime comparison | `uv run python tools/check_ccfa_current_quality.py --root .` |
| `results/evaluation/genesys2-cva6/current/reproducibility_manifest.json` | current report, summary, raw-root, and checker linkage | `uv run python tools/check_genesys2_reproducibility_manifest.py --root .` |
| `results/evaluation/genesys2-cva6/current/artifact_package_manifest.json` | lightweight fresh-clone artifact-package manifest | `uv run python tools/check_genesys2_artifact_package.py --root .` |
| `results/evaluation/genesys2-cva6/current/external_closure_readiness.json` | remaining non-real external blocker contracts | `uv run python tools/check_genesys2_external_closure_readiness.py --root .` |
| `results/evaluation/genesys2-cva6/current/external_closure_intake.json` | optional external-summary intake gate | `uv run python tools/check_genesys2_external_closure_intake.py --root .` |
| `results/evaluation/genesys2-cva6/current/external_closure_plan.json` | executable plan and template-only runbooks for remaining non-real external blockers | `uv run python tools/check_genesys2_external_closure_plan.py --root .` |
| `results/evaluation/genesys2-cva6/current/external_closure_preflight.json` | local script/schema/dry-run preflight for remaining non-real external blockers | `uv run python tools/check_genesys2_external_closure_preflight.py --root .` |
| `results/evaluation/genesys2-cva6/current/external_operator_packet.json` | operator handoff packet linking remaining external blocker execution steps, required artifact kinds, and intake gates | `uv run python tools/check_genesys2_external_operator_packet.py --root .` |

External summary templates under
`results/evaluation/genesys2-cva6/current/external_closure_templates/` are
checked by `uv run python tools/prepare_genesys2_external_summary.py --check-templates`.
They are scaffolding only and are not PASS evidence rows. Future accepted
external summaries must include `evidence_artifacts` rows for the required
artifact kinds, and those rows must point to existing files with matching
sha256 values.

## Remaining External Closure Items

These items are not real-malware validation, but they still require new board,
RTL, or external-reviewer artifacts before the corresponding broad paper claim
can be made. Each closure gate is artifact-backed: a summary alone is
insufficient unless its `evidence_artifacts` rows cover the required artifact
kinds and pass path/sha256 validation.

| Item | Current Status | Closure Gate |
| --- | --- | --- |
| `board_native_dwarf_source_lines` | EXTERNAL_SUMMARY_ACCEPTED | `results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json` |
| `full_hardware_pointer_strings` | EXTERNAL_SUMMARY_ACCEPTED | `results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json` |
| `production_streaming_dma_trace_sink` | EXTERNAL_SUMMARY_PRESENT_INVALID | `results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json` |
| `genesys2_board_benign_control` | EXTERNAL_SUMMARY_ACCEPTED | `results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json` |

## Non-Goals

- Do not treat the committed-event MVP alone as sufficient for a CCF-A
  submission.
- Do not treat syscall numbers without pointer or return-value semantics as full
  malware behavior reconstruction.
- Do not treat eBPF or a kernel helper as a replacement for RTL committed
  behavior tracing.
- Do not claim board or Linux validation from simulation-only artifacts.
- Do not enable full memory trace or load/store payloads without a separate
  timing, bandwidth, and noninterference gate.
- Do not treat the scoped PASS_CURRENT/PASS_SAFE statuses above as CCF-A
  paper-ready acceptance, real malware validation, board-native DWARF source
  lines, full hardware pointer strings, or production streaming/DMA throughput.

## Validation Command

Run this document gate after editing the evaluation plan:

```powershell
uv run python tools/check_evaluation_plan.py
```
