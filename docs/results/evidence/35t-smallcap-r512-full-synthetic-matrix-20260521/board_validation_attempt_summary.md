# 35T Board Validation Attempt: 35t-targeted-board-validation-20260522

Status: BOARD_RUN_COMPLETE_VALIDATION_PARTIAL

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Hardware validated: false

actual 35T board run completed and full-matrix gate passed, but strict fd/path and process-tree validation remain partial

## Phases

- groundtruth: PASS
- rootfs: PASS
- board: PASS
- analyze: PASS
- report: PASS

## Next Gate

- claim_level: full_matrix_ready
- samples: 13/13 PASS
- trace_records: 512
- trace_profile_policy: 35t_small_capacity

## Bundle

- status: CANDIDATE_PARTIAL
- checker_status: RESULTS_PARTIAL
- fd_path_flow: PARTIAL
- process_tree: PARTIAL
- source_attribution: PARTIAL

## Checker Failures

- board validation result content check failed: fd_path_flow
- board validation result content check failed: process_tree

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
