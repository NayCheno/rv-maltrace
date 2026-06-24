# CCF-A Review Closure Audit

Status: `PASS`
Closure status: `PASS_LOCAL_SCOPE_EXTERNAL_AND_BOARD_DYNAMIC_OPEN`

This audit maps the 2026-06 review requirements onto the current Genesys2/CVA6 evidence package. It excludes real malware validation by objective, and it does not convert external readiness contracts into completion evidence.

## Summary

- Local/current items closed: 10
- Non-real external items accepted: 3
- Non-real external items still blocked: 1
- Objective exclusions: real_malware_validation

## Requirement Rows

| Requirement | Review section | Status | Evidence | Checker |
| --- | --- | --- | --- | --- |
| `phase_a_claim_boundary_convergence` | Phase A | `PASS_CURRENT` | `ccfa_readiness_matrix`, `ccfa_next_closure_plan`, `ccfa_remaining_blockers`, `evaluation_plan` | `uv run python tools/check_ccfa_claim_boundaries.py --root .`<br>`uv run python tools/check_evaluation_plan.py --root .` |
| `phase_a_baseline_board_acceptance` | Phase A | `PASS_CURRENT` | `baseline_pass_criteria`, `board_bringup` | `uv run python tools/check_baseline_pass_criteria.py --root .` |
| `phase_b_p0_and_safe_surrogate_hardware_trace` | Phase B | `PASS_CURRENT_CONTROLLED` | `p0_bram_trace`, `safe_surrogate_bram_trace`, `trace_sink`, `drop_accounting`, `statistical_robustness` | `uv run python tools/check_genesys2_p0_bram_trace.py --root .`<br>`uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .`<br>`uv run python tools/check_trace_drop_accounting.py --root .`<br>`uv run python tools/check_genesys2_statistical_robustness.py --root .` |
| `phase_b_bounded_pointer_semantics` | Phase B | `PASS_CURRENT_BOUNDED_PREFIX` | `pointer_snapshot_guardrails`, `hardware_pointer_prefixes` | `uv run python tools/check_pointer_snapshot_guardrails.py --root .`<br>`uv run python tools/check_hardware_pointer_prefixes.py --root .` |
| `phase_b_full_hardware_pointer_strings` | Phase B | `EXTERNAL_SUMMARY_ACCEPTED` | `pointer_string_readiness`, `external_closure_readiness`, `external_closure_intake`, `external_closure_plan`, `external_closure_preflight`, `external_operator_packet`, `external_template_hardware_pointer_strings` | `uv run python tools/check_genesys2_pointer_string_readiness.py --root .`<br>`uv run python tools/check_genesys2_external_closure_intake.py --root .`<br>`uv run python tools/check_genesys2_external_closure_preflight.py --root .`<br>`uv run python tools/check_genesys2_external_operator_packet.py --root .`<br>`uv run python tools/prepare_genesys2_external_summary.py --check-templates` |
| `phase_c_function_process_elf_attribution` | Phase C | `BLOCKED_BOARD_DYNAMIC_MAPPING_CASES` | `source_line_attribution`, `source_line_toolchain_probe`, `debug_elf_readiness`, `process_elf_ownership`, `dynamic_mapping_attribution` | `uv run python tools/check_source_line_attribution.py --root .`<br>`uv run python tools/check_source_line_toolchain_probe.py --root .`<br>`uv run python tools/check_genesys2_debug_elf_readiness.py --root .`<br>`uv run python tools/check_process_elf_ownership.py --root .`<br>`uv run python tools/check_dynamic_mapping_attribution.py --root .` |
| `phase_c_board_native_dwarf_source_lines` | Phase C | `EXTERNAL_SUMMARY_ACCEPTED` | `debug_elf_readiness`, `external_closure_readiness`, `external_closure_intake`, `external_closure_plan`, `external_closure_preflight`, `external_operator_packet`, `external_template_board_native_source_lines` | `uv run python tools/check_genesys2_debug_elf_readiness.py --root .`<br>`uv run python tools/check_genesys2_external_closure_intake.py --root .`<br>`uv run python tools/check_genesys2_external_closure_preflight.py --root .`<br>`uv run python tools/check_genesys2_external_operator_packet.py --root .`<br>`uv run python tools/prepare_genesys2_external_summary.py --check-templates` |
| `phase_d_safe_surrogate_behavior_case_studies` | Phase D | `PASS_CURRENT_SAFE_SURROGATE` | `semantic_reconstruction`, `semantic_provenance`, `fd_path_graph`, `behavior_audit_metrics`, `case_study_manifest` | `uv run python tools/check_syscall_semantic_reconstruction.py --root .`<br>`uv run python tools/check_fd_path_graph.py --root .`<br>`uv run python tools/check_behavior_audit_metrics.py --root .`<br>`uv run python tools/check_ccfa_case_study_manifest.py --root .` |
| `phase_d_local_benign_control` | Phase D | `PASS_CURRENT_LOCAL_LINUX_CONTROL` | `benign_control` | `uv run python tools/check_benign_control_summary.py --root .` |
| `phase_d_genesys2_board_benign_control` | Phase D | `EXTERNAL_SUMMARY_ACCEPTED` | `board_benign_readiness`, `external_closure_readiness`, `external_closure_intake`, `external_closure_plan`, `external_closure_preflight`, `external_operator_packet`, `external_template_board_benign_control` | `uv run python tools/check_genesys2_board_benign_readiness.py --root .`<br>`uv run python tools/check_genesys2_external_closure_intake.py --root .`<br>`uv run python tools/check_genesys2_external_closure_preflight.py --root .`<br>`uv run python tools/check_genesys2_external_operator_packet.py --root .`<br>`uv run python tools/prepare_genesys2_external_summary.py --check-templates` |
| `phase_e_evaluation_matrix_and_baselines` | Phase E | `PASS_CURRENT_CONTROLLED` | `ccfa_evaluation_matrix`, `baseline_alignment`, `behavior_audit_metrics`, `statistical_robustness` | `uv run python tools/check_ccfa_evaluation_matrix.py --root .`<br>`uv run python tools/check_baseline_alignment.py --root .`<br>`uv run python tools/check_behavior_audit_metrics.py --root .`<br>`uv run python tools/check_genesys2_statistical_robustness.py --root .` |
| `phase_e_statistical_robustness_audit` | Phase E | `PASS_CURRENT_BOUNDED_STATISTICS` | `statistical_robustness`, `p0_bram_trace`, `safe_surrogate_bram_trace`, `benign_control` | `uv run python tools/check_genesys2_statistical_robustness.py --root .`<br>`uv run python tools/check_genesys2_p0_bram_trace.py --root .`<br>`uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .`<br>`uv run python tools/check_benign_control_summary.py --root .` |
| `phase_e_artifact_package_and_reproduction` | Phase E | `PASS_CURRENT_LIGHTWEIGHT_PACKAGE` | `reproduce_genesys2_current`, `reproducibility_manifest_checker`, `artifact_package_checker` | `uv run python tools/check_genesys2_reproducibility_manifest.py --root .`<br>`uv run python tools/check_genesys2_artifact_package.py --root .`<br>`uv run python tools/reproduce_genesys2_current.py --full` |
| `phase_e_streaming_dma_target_baseline` | Phase E | `PASS_CURRENT_TARGET_BASELINE` | `streaming_dma_target`, `p0_bram_trace`, `safe_surrogate_bram_trace` | `uv run python tools/check_genesys2_streaming_dma_target.py --root .`<br>`uv run python tools/check_genesys2_p0_bram_trace.py --root .`<br>`uv run python tools/check_genesys2_safe_surrogate_bram_trace.py --root .` |
| `phase_e_production_streaming_dma_trace_sink` | Phase E | `OPEN_EXTERNAL_ARTIFACTS_REQUIRED` | `streaming_dma_target`, `streaming_dma_readiness`, `external_closure_readiness`, `external_closure_intake`, `external_closure_plan`, `external_closure_preflight`, `external_operator_packet`, `external_template_streaming_dma_throughput` | `uv run python tools/check_genesys2_streaming_dma_target.py --root .`<br>`uv run python tools/check_genesys2_streaming_dma_readiness.py --root .`<br>`uv run python tools/check_genesys2_external_closure_intake.py --root .`<br>`uv run python tools/check_genesys2_external_closure_preflight.py --root .`<br>`uv run python tools/check_genesys2_external_operator_packet.py --root .`<br>`uv run python tools/prepare_genesys2_external_summary.py --check-templates` |
| `phase_g_real_malware_validation` | Phase G | `EXCLUDED_BY_OBJECTIVE` | `real_malware_containment` | `uv run python tools/check_real_malware_containment.py --root .`<br>`uv run python tools/check_real_malware_validation_gate.py` |

## Remaining Non-Real External Items

| External id | Intake status | Expected summary |
| --- | --- | --- |
| `production_streaming_dma_trace_sink` | `EXTERNAL_SUMMARY_PRESENT_INVALID` | `results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json` |

## Non-Claims

- Real malware validation is excluded from the current objective.
- External items are closed only when their live intake record is EXTERNAL_SUMMARY_ACCEPTED; invalid external summaries remain blockers.
- Local Linux benign controls, source-equivalent sidecars, bounded hardware prefixes, and BRAM/JTAG marker-window traces are not substitutes for the open external evidence.
