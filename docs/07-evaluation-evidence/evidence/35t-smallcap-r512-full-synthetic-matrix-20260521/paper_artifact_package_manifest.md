# 35T Paper Artifact Package Manifest: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED

Package dir: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_artifact_package`

Readiness: `LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED` from `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/artifact_package_readiness.json`

## Release Policy Summary

- public classes: 7
- summary/hash classes: 13
- local-only classes: 3

## Validation Commands

- `uv run --no-sync python tools/check_35t_application_closure.py --repo-root . --no-write`
- `uv run --no-sync python tools/check_35t_paper_evidence.py --no-write`
- `uv run --no-sync python tools/check_35t_fd_path_case_studies.py --no-write`
- `uv run --no-sync python tools/check_35t_process_tree_case_study.py --no-write`
- `uv run --no-sync python tools/check_35t_metric_coverage.py --no-write`
- `uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --no-write`
- `uv run --no-sync python tools/check_35t_pointer_semantics_preflight.py --no-write`
- `uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --no-write`
- `uv run --no-sync python tools/check_35t_threat_model.py --no-write`
- `uv run --no-sync python tools/check_35t_helper_alignment.py --no-write`
- `uv run --no-sync python tools/check_35t_evaluation_table.py --no-write`
- `uv run --no-sync python tools/check_35t_baseline_evaluation.py --no-write`
- `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --no-write`
- `uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test`
- `uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --self-test`
- `uv run --no-sync python tools/run_35t_ebpf_baseline.py --self-test`
- `uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --no-write`
- `uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --no-write`
- `uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --no-write`
- `uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --no-write`
- `uv run --no-sync python tools/check_35t_extension_35t_enablement.py --no-write`
- `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write`
- `uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write`
- `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --no-write`
- `uv run --no-sync python tools/check_35t_assessment_closure.py --no-write`
- `uv run --no-sync python tools/check_35t_assessment_traceability.py --no-write`
- `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write`
- `uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write`
- `uv run --no-sync python tools/check_35t_paper_positioning.py --no-write`
- `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --no-write`
- `uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --no-write`
- `uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --no-write`
- `uv run --no-sync python tools/check_35t_local_code_analysis.py --no-write`
- `uv run --no-sync python tools/check_35t_malware_behavior_audit.py --no-write`
- `uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write`

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
