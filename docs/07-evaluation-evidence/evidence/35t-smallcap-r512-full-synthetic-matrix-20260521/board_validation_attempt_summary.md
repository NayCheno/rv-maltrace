# 35T Board Validation Attempt: 35t-targeted-board-validation-20260522

Status: BOARD_VALIDATION_PASS

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Hardware validated: true

Validation mode: dual_channel

strict dual-channel validation bundle passed: the trace-gate channel passes the full matrix and the side-channel channel supplies selected semantic closure

## Phases

- groundtruth: PASS
- rootfs: PASS
- board: PASS
- analyze: PASS
- report: PASS

## Next Gate

- claim_level: full_matrix_ready
- trace_gate_run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
- sample_status: 13/13 PASS
- sample_gate_status: 13/13 PASS
- strict_sample_gate: PASS
- trace_records: 512
- trace_profile_policy: 35t_small_capacity

## Bundle

- status: PASS
- checker_status: PASS
- fd_path_flow: PASS
- process_tree: PASS
- source_attribution: PARTIAL

## Side-Channel Gate

- semantic_run_id: 35t-targeted-board-validation-20260522
- claim_level: prototype_only
- sample_gate_status: 9/13 PASS
- strict_sample_gate: FAIL

## Side-Channel Sample-Gate Failures

- batch_open_read_write: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution
- illegal_trap: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution
- process_chain: failures=missing_strong_expected, marker_scope, drop_rate_median_gt_5pct; blockers=trace_record_cap_hit, runtime_process_attribution
- dynamic_executable_memory: failures=missing_strong_expected; blockers=none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
