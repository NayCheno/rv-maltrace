# 35T Remaining External Work: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED

## Checks

- closure_status_bounded: PASS
- traceability_status_bounded: PASS
- p3_status_bounded: PASS
- p4_status_bounded: PASS
- p5_status_bounded: PASS
- p6_status_bounded: PASS
- traceability_goal_statuses_match: PASS
- all_records_have_evidence: PASS
- all_record_evidence_paths_exist: PASS
- all_records_have_required_conditions: PASS
- all_records_have_unblock_criteria: PASS
- all_records_have_no_substitution_rules: PASS
- satisfied_conditions_have_no_substitution_rules: PASS
- helper_alignment_passed_or_recorded: PASS
- qemu_plugin_build_preflight_passed_or_recorded: PASS
- qemu_plugin_baseline_passed_or_recorded: PASS
- pointer_snapshot_still_default_disabled: PASS
- pointer_snapshot_design_review_passed_or_recorded: PASS
- advanced_baselines_not_silently_passed: PASS
- ebpf_pass_has_summary_evidence: PASS
- baseline_spec_has_blocked_rows: PASS
- extension_sources_no_35t_claim: PASS
- raw_artifact_hash_excerpt_ready: PASS
- raw_artifact_escrow_passed_or_recorded: PASS
- host_compile_smoke_passed_or_recorded: PASS
- target_compile_smoke_passed_or_recorded: PASS
- extension_behavior_smoke_passed_or_recorded: PASS
- extension_enablement_preflight_passed_or_recorded: PASS
- artifact_release_deferred: PASS

## Records

| Item | Goal | Current Status | Current Condition | Unblock Criteria |
| --- | --- | --- | --- | --- |
| `p3_hardware_user_pointer_snapshot` | `P3_pointer_argument_semantics` | `DEFERRED_NOT_ENABLED` | POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED; design_review=POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED | pointer gate no longer reports POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED; pointer preflight no longer reports hardware_user_pointer_snapshot=DEFERRED |
| `p5_extension_35t_gating` | `P5_synthetic_suite_extension` | `DEFERRED_35T_RUN_REQUIRED` | 9 source candidates implemented, host_compiled=9/9, target_compiled=9/9, behavior_smoke=8/8, enablement=EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED, no expanded 35T coverage claim | new 35T run records selected extension samples in the matrix; gate report passes for enabled extension samples |
| `p6_full_raw_artifact_release` | `P6_artifact_package` | `HASH_EXCERPT_READY_FULL_RAW_DEFERRED` | raw_sanitization_status=RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED; raw_escrow_status=LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED; escrow_payload_files=66; local_only=['raw_uart_log', 'decoded_trace_jsonl', 'raw_artifact_escrow_package']; release_local_only=['raw_uart_log', 'decoded_trace_jsonl', 'raw_artifact_escrow_package'] | paper package status no longer reports full raw deferred; raw/local-only artifact classes have release approval or sanitized public replacements |

## Satisfied Conditions

- `p5_extension_host_compile_smoke`: `HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED` (compiled=9/9)
- `p4_qemu_plugin_baseline`: `PASS` (13-sample QEMU-plugin syscall-count baseline recorded)
- `p5_extension_riscv_target_compile_smoke`: `TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED` (compiled=9/9)
- `p5_extension_host_qemu_behavior_smoke`: `HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED` (executed_non_network=8/8; network_skipped=1; host native, host strace, QEMU native, and QEMU strace smoke recorded)
- `p5_extension_35t_enablement_preflight`: `EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED` (synthetic extension candidates are present in the 35T runner table, default-disabled, compiled by the Artix-7 rootfs build script, and selectable through explicit experiment dry-run commands; no extension candidate has been executed on the 35T board or passed the gate)
- `p3_trusted_helper_or_ebpf_alignment`: `TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL` (representative fd/path and process-tree helper evidence is aligned with 35T hardware trace evidence through the targeted dual-channel board validation bundle)
- `p4_qemu_plugin_system_build_load_preflight`: `QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED` (qemu-system-riscv64 can load a freshly built minimal QEMU TCG plugin when the matching official QEMU 8.2.2 plugin header is fetched at probe time; qemu-riscv64 user-mode still does not expose -plugin, and no 13-sample QEMU-plugin baseline is recorded)
- `p4_ebpf_only_baseline`: `PASS` (13-sample host eBPF/bpftrace baseline recorded)
- `p3_pointer_snapshot_design_review`: `POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED` (bounded openat/execve pointer snapshot design, allowlist, limits, default-disabled policy, guardrails, artifact policy, and non-substitution rules recorded; hardware capture remains disabled)
- `p6_local_raw_artifact_escrow`: `LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED` (local escrow payload files=66; bytes=3681202; public release remains deferred)

## No-Substitution Rules

- `p3_hardware_user_pointer_snapshot`: synthetic ARG_MEM fixtures or syscall side-channel paths cannot be substituted for enabled hardware pointer snapshot evidence
- `p5_extension_35t_gating`: source implementation and host/QEMU behavior smoke cannot be substituted for expanded 35T coverage
- `p6_full_raw_artifact_release`: lightweight summaries and hashes are not a full raw artifact release
- `p5_extension_host_compile_smoke`: host compile smoke is not execution evidence and is not a 35T gate pass
- `p4_qemu_plugin_baseline`: QEMU-plugin syscall-count evidence is simulator software evidence, not hardware trace, DBI, or real malware evidence
- `p5_extension_riscv_target_compile_smoke`: target compile smoke is not execution evidence and is not a 35T gate pass
- `p5_extension_host_qemu_behavior_smoke`: host/QEMU behavior smoke is not 35T board execution and is not a gate pass
- `p5_extension_35t_enablement_preflight`: extension enablement preflight is not a 35T execution or gate pass
- `p3_trusted_helper_or_ebpf_alignment`: helper/eBPF companion evidence must not be reported as hardware-only tracing
- `p4_qemu_plugin_system_build_load_preflight`: QEMU-plugin build/load preflight is not a 13-sample QEMU-plugin trace baseline
- `p4_ebpf_only_baseline`: host eBPF/bpftrace evidence must not be reported as hardware-only tracing or QEMU-plugin evidence
- `p3_pointer_snapshot_design_review`: design review is not enabled hardware pointer snapshot evidence
- `p6_local_raw_artifact_escrow`: local escrow is not a public raw artifact release and does not remove the P6 full-release condition

## Interpretation

- P3-P6 have external or deferred conditions that are explicitly recorded rather than treated as completed work
- current bounded PASS statuses remain valid only under the 35T synthetic prototype claim boundary
- each record lists the evidence that explains the current condition and the criteria required before the status can be upgraded

## Failures

- none
