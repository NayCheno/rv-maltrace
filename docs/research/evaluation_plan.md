# Evaluation Plan

This document turns `docs/planning/next-plan.md` Section 9 and Stage 3 into a checkable
evaluation plan. It is a research design and artifact gate, not evaluation
evidence. All rows remain TODO until the required simulation, board, Linux, or
paper-study artifacts exist under the documented results paths.

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
| RQ1 | Correctness: can committed syscall/control-flow/trap/context events be captured accurately? | `sim:trace-unit`, `sim:cva6-smoke`, golden JSONL comparisons, and explained mismatches | TODO |
| RQ2 | Semantic reconstruction: can syscall arguments, return values, paths, fd behavior, and behavior graphs be recovered? | recovery target specs, synthetic traces, Linux trace outputs, semantic JSON, graph JSON, and reports | TODO |
| RQ3 | Low perturbation: how much runtime and timing perturbation is introduced compared with software tracing? | paired hardware-only/software-baseline runs, cycle or wall-time measurements, and perturbation summaries | TODO |
| RQ4 | Evasion resistance: are anti-debug, timing, direct-syscall, and packed-code samples less able to detect or bypass tracing? | controlled malware-like suite manifests, per-sample traces, expected behaviors, and comparison notes | TODO |
| RQ5 | Hardware cost: what are LUT, FF, BRAM, Fmax, trace bandwidth, and drop-rate costs? | Vivado utilization/timing reports, `docs/reports/resource_report.md`, trace bandwidth summaries, and drop accounting | TODO |
| RQ6 | Malware behavior usefulness: are key malware-like behaviors reconstructed clearly enough for audit or rules? | case studies with behavior graph evidence and manually reviewable semantic summaries | TODO |

## Baselines

Each baseline must be recorded as a separate run configuration. Performance
claims must not reuse a perturbed ground-truth run as the uninstrumented runtime.

| Baseline | Purpose | Required Artifact | Status |
| --- | --- | --- | --- |
| `strace` / `ptrace` | syscall semantic ground truth and perturbation comparison | command transcript, syscall log, paired no-`strace` run metadata | TODO |
| eBPF-only | software kernel-side semantic comparison when kernel support exists | program, kernel config, helper log, overhead summary | TODO |
| QEMU plugin | simulator trace comparison | plugin version, trace output, timing note | TODO |
| software instrumentation | detectability and overhead comparison | instrumentation method, binary hash, trace output | TODO |
| RV-MalScope event-only | hardware MVP ablation | trace JSONL, summary, resource row | TODO |
| RV-MalScope + pointer snapshot | hardware semantic enrichment ablation | pointer snapshot trace, reconstructed strings, bandwidth/drop summary | TODO |
| RV-MalScope + kernel helper/eBPF companion | fallback semantic enrichment ablation | helper log, hardware trace, alignment report | TODO |

## Datasets

| Class | Contents | Required Manifest | Status |
| --- | --- | --- | --- |
| Class A | microbenchmarks for syscall correctness, trap correctness, control-flow correctness, and pointer reconstruction | `experiments/linux_behavior/recovery_targets.json` plus matching simulation or board traces | TODO |
| Class B | benign Linux programs such as busybox/coreutils-like file, process, memory, and network workloads | `experiments/linux_behavior/benign/manifest.json` | TODO |
| Class C | controlled malware-like programs for anti-debug, timing checks, direct syscall, packed code, mmap/mprotect executable memory, fork/exec chains, file scanning, and self-copy/dropper-like behavior | `experiments/linux_behavior/malware_like/manifest.json` | TODO |

Real malware samples are optional and must stay isolated from the main success
criteria until legal, ethical, and containment procedures are documented.

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
| simulation correctness | `results/vivado_sim/summary.json`, per-test `trace.jsonl`, golden comparison logs | TODO |
| direct-core CVA6 smoke | `results/vivado_sim/cva6_*` traces and logs from `uv run rvmt sim:cva6-smoke` | TODO |
| board baseline | `results/board/genesys2_baseline/<run-id>/` transcript, bitstream metadata, UART/tohost evidence | TODO(BOARD) |
| board trace | `results/board/genesys2_trace_validation/<run-id>/` BRAM/ILA/UART dump, decoded JSONL, expected comparison | TODO(BOARD) |
| Linux syscall trace | `results/linux/syscall_trace/<run-id>/` workload logs, hardware traces, `strace` ground-truth run, alignment report | TODO(LINUX) |
| semantic reconstruction | `semantic_events.json`, `behavior_graph.json`, and `recovery_report.md` per workload | TODO |
| evasion suite | per-sample manifest row, trace, baseline comparison, and detection outcome | TODO |
| hardware cost | Vivado utilization/timing reports and generated resource summary | TODO |
| ablation study | event-only, pointer snapshot, and helper/eBPF companion results compared under the same workload manifest | TODO |
| case studies | manually reviewable malware-like or audit-oriented behavior graph narratives with trace references | TODO |
| artifact package | scripts, manifests, expected outputs, and reproduction notes | TODO |

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

## Validation Command

Run this document gate after editing the evaluation plan:

```powershell
uv run python tools/check_evaluation_plan.py
```
