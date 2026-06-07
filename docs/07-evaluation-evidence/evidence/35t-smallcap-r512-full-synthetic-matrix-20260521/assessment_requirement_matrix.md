# 35T Assessment Requirement Matrix: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## High-Level Checks

- all_requirements_pass: PASS
- requirement_count: PASS
- bounded_external_records_complete: PASS
- bounded_satisfied_conditions_complete: PASS
- no_row_upgrades_external_work: PASS

## Requirements

| ID | Section | Status | Current Status | Evidence | Boundary |
| --- | --- | --- | --- | --- | --- |
| `R1_overall_claim_boundary` | 1 总体结论 | `PASS` | `BOUNDED_PROTOTYPE_CLAIM_FROZEN` | `evidence_manifest.json`, `assessment_closure.json`, `assessment_traceability.json`, `paper_positioning.json`, `paper_evidence_check.json` | The matrix preserves the assessment claim boundary and does not upgrade 35T evidence to real malware, CVA6, or complete semantic reconstruction. |
| `R2_primary_35t_evidence_chain` | 2 当前 35T 已经成立的证据链 | `PASS` | `PRIMARY_FULL_MATRIX_GATE_PASS` | `evidence_manifest.json`, `assessment_gate_criteria.json`, `hardware_trace_prototype.json`, `sample_matrix_summary.json` | The evidence chain is a 35T-only synthetic matrix under the fixed 512-record budget. |
| `R3_sample_matrix_and_gate_conditions` | 2.2-2.3 matrix and gate | `PASS` | `GATE_CRITERIA_PASS` | `assessment_gate_criteria.json`, `malware_behavior_audit.json` | The rule gate explains synthetic expected behavior and does not claim classifier quality or false-positive rate on real malware. |
| `R4_hardware_trace_target` | 3.1 硬件 trace | `PASS` | `HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY` | `hardware_trace_prototype.json`, `assessment_gate_criteria.json` | This is a 35T / LiteX / VexRiscv hardware trace prototype, not CVA6 validation. |
| `R5_local_code_analysis_target` | 3.2 本地代码分析 | `PASS` | `LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION` | `local_code_analysis.json`, `paper_evidence_check.json` | Local code analysis is bounded to prototype attribution; source-line and complete process ownership remain non-claims. |
| `R6_malware_behavior_audit_boundary` | 3.3 Malware 分析 | `PASS` | `SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED` | `malware_behavior_audit.json`, `assessment_gate_criteria.json` | The malware-facing result is a controlled synthetic behavior audit, not real malware execution or detector accuracy. |
| `R7_fd_path_and_process_case_studies` | 4.1-4.2 fd/path and process tree shortfalls | `PASS` | `REPRESENTATIVE_CASE_STUDIES_PASS_BOUNDED` | `fd_path_case_studies.json`, `process_tree_case_study.json`, `assessment_reconciliation.json` | P1/P2 are stronger than the original snapshot for representative case studies, but they are not full-suite hardware pointer semantic reconstruction. |
| `R8_pointer_semantics_external_work` | 4.3 and P3 pointer semantics | `PASS` | `PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS` | `pointer_semantics_preflight.json`, `pointer_snapshot_enablement_gate.json`, `pointer_snapshot_design_review.json`, `threat_model_boundary.json`, `helper_alignment.json`, `remaining_external_work.json` | P3 has representative trusted-helper alignment and pointer snapshot design-review evidence, but cannot be marked complete until enabled hardware pointer snapshot or broader pointer semantic reconstruction evidence exists. |
| `R9_baseline_evaluation_external_work` | 4.4 and P4 baseline evaluation | `PASS` | `HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS` | `baseline_evaluation_summary.json`, `baseline_execution_spec_check.json`, `evaluation_table.json`, `metric_coverage.json`, `advanced_baseline_preflight.json`, `qemu_plugin_build_preflight.json`, `qemu_plugin_baseline_summary.json`, `remaining_external_work.json` | P4 has bounded host/QEMU/strace, software-instrumentation, host eBPF, and QEMU-plugin simulator coverage; none of these substitute for hardware pointer snapshots, DBI, or real malware evaluation. |
| `R10_synthetic_suite_extension_boundary` | P5 synthetic suite extension | `PASS` | `IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING` | `synthetic_suite_extension_check.json`, `synthetic_extension_host_smoke.json`, `synthetic_extension_target_smoke.json`, `synthetic_extension_behavior_smoke.json`, `extension_35t_enablement_preflight.json`, `remaining_external_work.json`, `extension_plan.json` | Implemented extension sources now have compile, host/QEMU behavior smoke, and explicit runner/rootfs/CLI preflight evidence, but remain outside the claimed 35T matrix until board gate evidence exists. |
| `R11_artifact_package_boundary` | 4.5 and P6 artifact package | `PASS` | `LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED` | `raw_artifact_sanitization.json`, `raw_artifact_sanitization.md`, `raw_artifact_escrow.json`, `raw_artifact_escrow.md`, `artifact_package_readiness.json`, `paper_artifact_package_manifest.json`, `paper_artifact_release_policy.json`, `remaining_external_work.json` | The lightweight package, hashes, sanitized excerpts, and local raw escrow package are ready; public or external raw release still needs approval or a controlled-release destination. |
| `R12_ccfa_positioning` | 5 CCF-A positioning | `PASS` | `BOUNDED_FEASIBILITY_POSITIONING_READY` | `paper_positioning.json`, `paper_evidence_check.json`, `remaining_external_work.json` | 35T may support a feasibility subsection or constrained-board case study, not the full CCF-A main contribution by itself. |
| `R13_recommended_paper_organization` | 7 推荐论文组织方式 | `PASS` | `PAPER_ORGANIZATION_BOUNDARY_RECORDED` | `paper_positioning.json`, `metric_coverage.json`, `paper_evidence_check.json` | The recommended organization is supported only with bounded feasibility wording and deferred anti-evasion/semantic completeness claims. |
| `R14_final_judgment` | 8-9 final judgment | `PASS` | `FINAL_ASSESSMENT_RECONCILED_WITH_CURRENT_EVIDENCE` | `assessment_closure.json`, `assessment_traceability.json`, `assessment_reconciliation.json`, `remaining_external_work.json` | The final answer is a bounded current-scope pass, not completion of real-malware, CVA6, complete semantics, or full raw-artifact release goals. |

## Interpretation

- the source assessment is covered section-by-section by current evidence rows
- current-scope 35T hardware trace, local code analysis, and synthetic malware-like audit evidence pass under bounded claims
- P3/P4/P5/P6 external conditions remain explicit and are not silently treated as completed work

## Failures

- none
