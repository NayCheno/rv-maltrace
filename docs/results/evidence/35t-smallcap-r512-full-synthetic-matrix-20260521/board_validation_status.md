# 35T Board Validation Status: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: AWAITING_BOARD_RUN

Scope: Artix-7 35T / LiteX / VexRiscv only.

Hardware validated: false

## Plan Check

- schema: PASS
- source_run_id: PASS
- scope: PASS
- claim_level: PASS
- status: PASS
- board_validation_required: PASS
- hardware_validated_false_until_results: PASS
- non_claims: PASS

## Result Artifacts

- not checked: no board validation results root was provided

## Result Content Checks

- not checked

## Required Capture

- target-scoped marker begin/end around each sample repetition
- runtime process map for runner_parent, target_child, kernel, and unknown roles
- reliable target syscall entry/return pairing for fd operations
- openat and execve path strings or a board-side/runner-side path side channel tied to target syscall events
- clone/fork return value from the parent side and wait PID in the same evidence window
- child runtime process ownership evidence across exec
- exact board runtime ELF/code-map identity
- DWARF/debug-line metadata or an addr2line-compatible source-location side channel if source-line attribution is claimed

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
