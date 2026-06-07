# 35T Baseline Execution Spec Check: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

Spec: `experiments/linux_behavior/baseline_execution_spec.json`

## Checks

- spec_schema: PASS
- spec_run_id: PASS
- spec_scope: PASS
- spec_claim_level: PASS
- summary_schema: PASS
- summary_sample_count: PASS
- advanced_preflight_schema: PASS
- pointer_preflight_schema: PASS
- threat_model_schema: PASS
- assessment_baselines_covered: PASS
- required_baseline_ids_present: PASS
- coverage_map_targets_declared_rows: PASS
- current_statuses_allowed: PASS
- current_statuses_match_summary: PASS
- pass_rows_have_artifacts_and_commands: PASS
- blocked_or_deferred_rows_have_gates: PASS
- substitution_rules_present: PASS
- substitution_rules_strict: PASS
- non_claims_present: PASS

## Baseline Statuses

- `ebpf_only`: spec=PASS, summary=PASS, family=ebpf_only
- `host_native`: spec=PASS, summary=PASS, family=host_native
- `host_strace`: spec=PASS, summary=PASS, family=strace_ptrace
- `qemu_native`: spec=PASS, summary=PASS, family=qemu_native
- `qemu_plugin`: spec=PASS, summary=PASS, family=qemu_plugin
- `qemu_strace`: spec=PASS, summary=PASS, family=strace_ptrace
- `rvmaltrace_event_only`: spec=PASS, summary=PASS, family=rvmaltrace_event_only
- `rvmaltrace_helper_or_ebpf_companion`: spec=DEFERRED, summary=DEFERRED, family=rvmaltrace_pointer_snapshot_or_helper
- `rvmaltrace_pointer_snapshot`: spec=DEFERRED, summary=DEFERRED, family=rvmaltrace_pointer_snapshot_or_helper
- `software_instrumentation`: spec=PASS, summary=PASS, family=software_instrumentation_or_dbi

## Interpretation

- the spec maps the assessment's required baseline families to concrete current evidence rows
- blocked or deferred rows have preflight or enablement gates and cannot silently become PASS
- substitution rules prevent strace, software instrumentation, QEMU timing, or side-channel evidence from replacing missing eBPF/QEMU-plugin/pointer evidence

## Failures

- none
