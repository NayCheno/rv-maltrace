# 35T Assessment Traceability: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS_WITH_BOUNDED_REMAINING_WORK

Assessment source: `D:\Download\rv_maltrace_35t_assessment.md`

Closure: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_closure.json`

## Closure Checks

- closure_schema: PASS
- closure_status: PASS
- closure_claim_level: PASS
- all_goals_mapped: PASS
- no_goal_trace_failures: PASS

## Goal Traceability

| Goal | Status | Completion Kind | Evidence Keys | Remaining Boundary |
| --- | --- | --- | --- | --- |
| `P0_claim_boundary` | `PASS` | `closed_current_scope` | application_closure_check, hardware_trace_prototype, local_code_analysis, malware_behavior_audit, manifest, paper_evidence_check, paper_positioning | keep the 35T result phrased as a synthetic malware-like behavior audit prototype; do not infer CVA6, real malware, classifier accuracy, or complete reconstruction claims |
| `P1_fd_path_flow` | `PASS` | `closed_representative_case_studies` | case_studies, summary | broaden from the three prioritized case-study samples to full-suite fd/path graph coverage; keep trace-proven, inferred, and missing links separated |
| `P2_process_tree` | `PASS` | `closed_representative_case_study` | case_study, summary | resolve target parent PID only when PID/SATP/ASID or equivalent runtime ownership evidence exists; do not describe the representative graph as complete OS process ownership |
| `P3_pointer_argument_semantics` | `PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS` | `bounded_helper_alignment_with_deferred_hardware_pointer_snapshot` | helper_alignment, pointer_preflight, pointer_snapshot_design_review, pointer_snapshot_gate, routes, strategy, threat_model | implement gated selective user-pointer snapshot before claiming hardware pointer capture; extend trusted helper alignment beyond representative case studies before claiming broad pointer semantic reconstruction |
| `P4_baseline_evaluation` | `HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS` | `bounded_ebpf_and_qemu_plugin_pass` | advanced_preflight, check, evaluation_table, execution_spec, metric_coverage, qemu_plugin_baseline, summary | extend advanced baselines beyond the current simulator/host software evidence only if the paper claim requires it; keep QEMU-plugin evidence separated from hardware trace, DBI, and real malware claims |
| `P5_synthetic_suite_extension` | `IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING` | `source_implemented_35t_gating_deferred` | behavior_smoke, enablement_preflight, extension_check, extension_plan, host_smoke, manifest, target_smoke | refresh the board image if needed, then run the source-implemented synthetic extension candidates through the same 35T gates before claiming expanded coverage; keep real malware legal, ethical, containment, and sanitization policy outside the current 35T success claim |
| `P6_artifact_package` | `LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED` | `lightweight_release_ready_full_raw_deferred` | artifact_readiness, paper_package_manifest, raw_artifact_escrow, raw_artifact_sanitization, snapshot_manifest | turn the lightweight release-candidate package into a full release after raw traces and UART logs are approved for public or controlled external release; keep generated bitstreams, board build directories, ELF binaries, and large raw artifacts out of the lightweight committed snapshot unless explicitly approved |

## Interpretation

- P0-P2 are closed under the current 35T prototype boundary
- P3, P4, P5, and P6 remain bounded or deferred where current hardware, baseline, extension-run, or raw-artifact conditions are unavailable
- this traceability report maps the assessment document requirements to concrete evidence without upgrading bounded statuses to completed external work

## Failures

- none
