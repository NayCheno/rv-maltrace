# 35T Pointer Snapshot Design Review: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED

Design: `experiments/linux_behavior/pointer_snapshot_design_review.json`

Design note: `docs/research/semantic/pointer_snapshot_design_review.md`

## Checks

- design_schema: PASS
- design_status: PASS
- design_run_id: PASS
- design_scope: PASS
- design_claim_level: PASS
- route_selective_memory_snapshot: PASS
- current_policy_default_disabled: PASS
- current_policy_trace_mem_none: PASS
- current_policy_hardware_deferred: PASS
- required_allowlist_present: PASS
- allowlist_limits_bounded: PASS
- required_guardrails_present: PASS
- required_measurement_gates_present: PASS
- measurement_gates_pre_enablement: PASS
- artifact_policy_deferred: PASS
- non_claims_present: PASS
- non_substitution_rules_present: PASS
- gate_design_review_required: PASS
- routes_still_deferred: PASS
- strategy_allows_design_review_only: PASS
- p2_profile_arg_mem_disabled: PASS
- small_capacity_profiles_arg_mem_disabled: PASS
- design_note_tokens_present: PASS

## Current Policy

- default_enabled: False
- hardware_user_pointer_snapshot: DEFERRED
- small_capacity_profiles: ARG_MEM_DISABLED
- trace_mem_mode: TRACE_MEM_MODE_NONE

## Allowlist

| Syscall | Argument | Max Bytes | Payload |
| --- | --- | ---: | --- |
| `openat` | `a1` | 64 | `pathname_prefix` |
| `execve` | `a0` | 64 | `pathname_prefix` |

## Safety Guardrails

- default_disabled_control_path
- page_boundary_clipping
- fault_timeout_handling
- no_load_store_payload_trace_mode
- no_core_backpressure
- drop_record_on_overflow

## Interpretation

- bounded pointer snapshot design review is recorded for openat and execve pathname prefixes
- the current 35T policy still keeps hardware user-pointer snapshots default-disabled and deferred
- this design review is not timing, bandwidth, noninterference, semantic accuracy, or enabled-board evidence

## Non-claims

- no 35T hardware user-pointer snapshot PASS claim
- no default memory payload tracing
- no complete syscall argument reconstruction claim
- no malicious-kernel or kernel-rootkit resistance claim
- no real malware detection claim

## Failures

- none
