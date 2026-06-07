# 35T Assessment Closure: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS_WITH_BOUNDED_REMAINING_WORK

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

All assessment goals are either closed with current 35T evidence or explicitly bounded as partial/deferred where hardware, baseline, or artifact conditions are not yet available.

## Goals

| Goal | Status | Evidence | Remaining boundary |
| --- | --- | --- | --- |
| `P0_claim_boundary` | `PASS` | manifest=evidence_manifest.json, application_closure_check=application_closure_check.json, paper_evidence_check=paper_evidence_check.json, paper_positioning=paper_positioning.json, hardware_trace_prototype=hardware_trace_prototype.json, local_code_analysis=local_code_analysis.json, malware_behavior_audit=malware_behavior_audit.json | keep the 35T result phrased as a synthetic malware-like behavior audit prototype; do not infer CVA6, real malware, classifier accuracy, or complete reconstruction claims |
| `P1_fd_path_flow` | `PASS` | summary=fd_path_flow_summary.json, sample=file_scan, closed_flow_count=1, case_studies=fd_path_case_studies.json | broaden from the three prioritized case-study samples to full-suite fd/path graph coverage; keep trace-proven, inferred, and missing links separated |
| `P2_process_tree` | `PASS` | summary=process_tree_summary.json, sample=process_chain, edge_count=2, case_study=process_tree_case_study.json | resolve target parent PID only when PID/SATP/ASID or equivalent runtime ownership evidence exists; do not describe the representative graph as complete OS process ownership |
| `P3_pointer_argument_semantics` | `PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS` | routes=experiments/linux_behavior/semantic_enrichment_routes.json, strategy=experiments/linux_behavior/semantic_enrichment_strategy.json, paper_evidence=paper_evidence_check.json, pointer_preflight=pointer_semantics_preflight.json, pointer_snapshot_gate=pointer_snapshot_enablement_gate.json, pointer_snapshot_design_review=pointer_snapshot_design_review.json, threat_model=threat_model_boundary.json, helper_alignment=helper_alignment.json | implement gated selective user-pointer snapshot before claiming hardware pointer capture; extend trusted helper alignment beyond representative case studies before claiming broad pointer semantic reconstruction |
| `P4_baseline_evaluation` | `HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS` | plan=docs/07-evaluation-evidence/evaluation_plan.md, metrics=results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/metrics.json, groundtruth_sample_count=13, summary=baseline_evaluation_summary.json, check=baseline_evaluation_check.json, execution_spec=baseline_execution_spec_check.json, advanced_preflight=advanced_baseline_preflight.json, qemu_plugin_build_preflight=qemu_plugin_build_preflight.json, qemu_plugin_baseline=qemu_plugin_baseline_summary.json, evaluation_table=evaluation_table.json, metric_coverage=metric_coverage.json | extend advanced baselines beyond the current simulator/host software evidence only if the paper claim requires it; keep QEMU-plugin evidence separated from hardware trace, DBI, and real malware claims |
| `P5_synthetic_suite_extension` | `IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING` | manifest=experiments/linux_behavior/malware_like/manifest.json, extension_plan=experiments/linux_behavior/malware_like/extension_plan.json, extension_check=synthetic_suite_extension_check.json, candidate_count=9, implemented_candidate_count=9, host_smoke=synthetic_extension_host_smoke.json, host_smoke_status=HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED, host_smoke_compiled_candidate_count=9, target_smoke=synthetic_extension_target_smoke.json, target_smoke_status=TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED, target_smoke_compiled_candidate_count=9, behavior_smoke=synthetic_extension_behavior_smoke.json, behavior_smoke_status=HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED, enablement_preflight=extension_35t_enablement_preflight.json, enablement_preflight_status=EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED | refresh the board image if needed, then run the source-implemented synthetic extension candidates through the same 35T gates before claiming expanded coverage; keep real malware legal, ethical, containment, and sanitization policy outside the current 35T success claim |
| `P6_artifact_package` | `LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED` | snapshot_manifest=evidence_manifest.json, committed_artifact_count=114, validation_bundle_status=PASS, artifact_readiness=artifact_package_readiness.json, artifact_readiness_status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED, artifact_class_count=23, paper_package_manifest=paper_artifact_package_manifest.json, paper_package_status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED, raw_artifact_sanitization=raw_artifact_sanitization.json, raw_artifact_sanitization_status=RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED, raw_artifact_escrow=raw_artifact_escrow.json, raw_artifact_escrow_status=LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED | turn the lightweight release-candidate package into a full release after raw traces and UART logs are approved for public or controlled external release; keep generated bitstreams, board build directories, ELF binaries, and large raw artifacts out of the lightweight committed snapshot unless explicitly approved |

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim

## Warnings

- side-channel semantic capture has strict gate failures and is not used as the trace-gate channel

## Failures

- none
