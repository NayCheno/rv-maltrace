# RV-MalTrace Documentation Architecture

This tree is organized by system architecture layer and evidence lifecycle.
Keep new files in the closest layer instead of recreating the old topic
directories.

## 02 Trace Architecture

Trace-facing design contracts: event format, signal attachment, timing rules,
and hardware export decisions.

- `02-trace-architecture/trace_format.md`
- `02-trace-architecture/signal_map.md`
- `02-trace-architecture/timing_principles.md`
- `02-trace-architecture/trace_export_decision.md`

## 03 Platform Architecture

Board-specific bring-up, constraints, and hardware source archives.

- `03-platform-architecture/genesys2/`
- `03-platform-architecture/genesys2/source-archive/`
- `03-platform-architecture/artix7-35t/`

## 04 Runtime Linux

Linux behavior experiments, workload datasets, recovery targets, and behavior
demo evidence.

- `04-runtime-linux/behavior_demo.md`
- `04-runtime-linux/linux_behavior_experiment_principles.md`
- `04-runtime-linux/linux_benign_dataset.md`
- `04-runtime-linux/linux_malware_like_dataset.md`

## 05 Semantic Analysis

Semantic enrichment, threat-model, pointer-snapshot, portability, and
lightweight trace-analysis research notes.

- `05-semantic-analysis/semantic_enrichment_strategy.md`
- `05-semantic-analysis/semantic_enrichment_routes.md`
- `05-semantic-analysis/semantic_enrichment_rationale.md`
- `05-semantic-analysis/semantic_threat_model.md`
- `05-semantic-analysis/pointer_snapshot_design_review.md`

## 06 Validation Gates

Cross-cutting validation plans and gates that are not owned by a single board.

- `06-validation-gates/fuzz_trace_validation.md`
- `06-validation-gates/noninterference_resource_gate.md`

## 07 Evaluation Evidence

Evaluation plans, generated reports, and reproducible evidence bundles.

- `07-evaluation-evidence/evaluation_plan.md`
- `07-evaluation-evidence/reports/`
- `07-evaluation-evidence/evidence/`

## 08 Publication

Paper-facing result summaries, claim boundaries, examples, and report outlines.

- `08-publication/rv_maltrace_35t_paper_evidence.md`
- `08-publication/rv_maltrace_35t_application_closure.md`
- `08-publication/rv_maltrace_35t_report_outline.md`

## 09 Planning

Project plans, staged work breakdowns, and archived planning notes.

- `09-planning/plan.md`
- `09-planning/next-plan.md`
- `09-planning/two-week-plan.md`

## 10 Process

Repository workflow, toolchain notes, version locks, runtime maps, and risk
tracking.

- `10-process/uv_workflow.md`
- `10-process/version_lock.md`
- `10-process/risk_log.md`
- `10-process/docker_toolchain.md`

## 11 User

User-facing interface notes.

- `11-user/35t_explain_interface.md`

## 12 Presentations

Slide decks and presentation source artifacts.

- `12-presentations/weekly_20260524/`
