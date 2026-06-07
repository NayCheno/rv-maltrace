# 35T Pointer Semantics Preflight: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED

## Checks

- sim_pointer_string_pass: PASS
- sim_pointer_guardrails_pass: PASS
- rtl_arg_mem_tap_instantiated: PASS
- trace_mem_default_none: PASS
- board_minimal_mem_mode_none: PASS
- p2_profile_gated_but_disabled: PASS
- small_capacity_35t_profiles_arg_mem_disabled: PASS
- routes_remain_deferred: PASS
- strategy_keeps_pointer_snapshot_optional: PASS
- side_channel_semantic_closure_present: PASS

## Evidence

- sim_results: `docs/07-evaluation-evidence/reports/sim_results.md`
- trace_profiles: `src/rv_maltrace/trace_profiles.py`
- trace_pkg: `rtl/trace/trace_pkg.sv`
- trace_top: `rtl/trace/trace_top.sv`
- board_minimal_top: `rtl/trace/trace_board_minimal_top.sv`
- semantic_routes: `experiments/linux_behavior/semantic_enrichment_routes.json`
- semantic_strategy: `experiments/linux_behavior/semantic_enrichment_strategy.json`
- side_channel: `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_syscall_side_channel_smoke.json`

## Current 35T Pointer Semantics

- hardware_user_pointer_snapshot: DEFERRED
- trace_mem_mode: TRACE_MEM_MODE_NONE
- small_capacity_profiles: ARG_MEM_DISABLED
- side_channel_scope: fd/path and process representative closure only

## Interpretation

- synthetic ARG_MEM simulation covers pointer string and guardrail behavior
- the current 35T small-capacity evidence does not enable hardware user-pointer memory snapshots
- board syscall side-channel evidence closes representative fd/path and process-tree semantics without changing the hardware pointer claim
- P3 remains bounded until gated selective memory snapshot or trusted helper alignment is implemented and measured

## Failures

- none

## Non-claims

- no 35T hardware user-pointer snapshot PASS claim
- no default ARG_MEM enablement claim
- no complete syscall argument reconstruction claim
- no real malware detection claim
