# RV-MalTrace Documentation Index

This directory is grouped by evidence type and project stage. Keep new documents
inside the closest matching subdirectory instead of adding more root-level
Markdown files.

## architecture

Trace schema, signal attachment, timing rules, and export-path decisions.

- `architecture/trace_format.md`
- `architecture/signal_map.md`
- `architecture/timing_principles.md`
- `architecture/trace_export_decision.md`

## board

Physical-board plans, board-specific constraints, and board evidence gates.
Board documents must keep simulation evidence separate from physical board
evidence.

- `board/board_bringup.md`
- `board/baseline_bringup_runbook.md`
- `board/baseline_pass_criteria.md`
- `board/board_trace_minimal.md`
- `board/board_trace_validation.md`
- `board/vivado_authorization.md`
- `board/artix7_35t_bringup.md`

## linux

Linux behavior experiments, datasets, recovery targets, and behavior-demo
evidence.

- `linux/linux_behavior_experiment_principles.md`
- `linux/linux_benign_dataset.md`
- `linux/linux_malware_like_dataset.md`
- `linux/linux_behavior_recovery_targets.md`
- `linux/linux_behavior_audit.md`
- `linux/behavior_demo.md`

## planning

Project plans and research-stage work breakdowns.

- `planning/plan.md`
- `planning/next-plan.md`
- `planning/two-week-plan.md`
- `planning/two-week-plan-2.md`

## process

Repository workflow, reproducibility anchors, risk tracking, and toolchain notes.

- `process/uv_workflow.md`
- `process/version_lock.md`
- `process/risk_log.md`
- `process/docker_toolchain.md`

## reports

Simulation and synthesis summaries that describe existing artifacts.

- `reports/sim_results.md`
- `reports/resource_report.md`

## research

Paper-level evaluation design, portability analysis, and NCScope/RV-MalScope
research notes.

- `research/evaluation_plan.md`
- `research/diff-22.md`
- `research/lightweight_trace_analysis.md`
- `research/isa_behavior_portability.md`
- `research/semantic/semantic_enrichment_rationale.md`
- `research/semantic/semantic_enrichment_routes.md`
- `research/semantic/semantic_enrichment_strategy.md`

## validation

Validation plans and gates that are not tied to one board.

- `validation/fuzz_trace_validation.md`
- `validation/noninterference_resource_gate.md`
