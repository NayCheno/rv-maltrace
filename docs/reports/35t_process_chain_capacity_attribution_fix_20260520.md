# 35T Process Chain Capacity and Attribution Fix

Generated: 2026-05-21 Asia/Shanghai

## Scope

This report covers only the Stage 3 `process_chain` risk path on real 35T/LiteX/VexRiscv. It does not run or claim a full matrix, a case study, CVA6 evidence, real malware detection, or a mature detector result.

## Run Configuration

| Field | p0c pre-fix run | p0a sweep run |
| --- | --- | --- |
| Run ID | `35t-p0c-r512-process-chain-risk-20260520-com5` | `35t-p0a-r512-process-chain-risk-20260520-com5` |
| Board | real 35T/LiteX/VexRiscv | real 35T/LiteX/VexRiscv |
| Port/baud | `COM5` / `921600` | `COM5` / `921600` |
| Trace profile | `p0c_syscall_trap_drop` | `p0a_syscall_drop` |
| Trace records | `512` | `512` |
| Runtime order | `abba` | `abba` |
| Warmup | `1` | `1` |
| Reps | `5` | `5` |
| Sample | `process_chain` only | `process_chain` only |
| Artifact root | `results/experiments/35t/35t-p0c-r512-process-chain-risk-20260520-com5` | `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5` |

COM5 was re-enumerated before the p0a board run and recorded as `USB-SERIAL CH340 (COM5)`, manufacturer `wch.cn`, status `OK`.

Serial and prerequisite logs:

- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/serial_port_enumeration.log`
- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/serial_port_enumeration.json`
- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/prerequisite_sources.json`

The p0a groundtruth was generated in this run via `experiment_35t --stage groundtruth`. The local rootfs prerequisite binaries were the pre-existing 35T overlay binaries under `build/board/artix7_35t/rootfs_exp_overlay/usr/bin/`. The p0a `board/raw_uart.log` was collected fresh for this run; no old board artifacts were copied.

## p0c Pre-Fix Blocker Recap

The prior p0c process-chain risk run produced weak `process_chain_shape` in 5/5 reps, but strong `process_creation_chain` in 0/5 reps. The blocker was capacity and attribution:

- `trace_records=512` cap hit in 5/5 reps.
- Median DROP rate was `0.6471399035148173`.
- Event totals were dominated by TRAP: `TRAP=2279`, `SYSCALL_ENTRY=142`, `SYSCALL_RET=139`, `DROP_STATUS=4761`.
- The dominant TRAP source was `kernel_or_loader_trap` in every rep.
- Clone, execve, and wait-like ordering was visible, but parent/child boundary did not close.
- Semantic clone parent return candidates did not overlap wait pid arguments.
- UNKNOWN/corrupt/parser warning remained zero.

The p0c capacity debug artifacts are:

- `results/experiments/35t/35t-p0c-r512-process-chain-risk-20260520-com5/aggregate/process_chain_capacity_debug.json`
- `results/experiments/35t/35t-p0c-r512-process-chain-risk-20260520-com5/aggregate/process_chain_capacity_debug.md`

## p0a Result

p0a removed the TRAP flood from the ring and resolved the capacity symptom:

| Metric | p0c | p0a |
| --- | ---: | ---: |
| Gate status | `BLOCKED` | `FAIL` |
| Captured events median | `512.0` | `160.0` |
| Capped reps | `5/5` | `0/5` |
| DROP median | `939.0` | `0.0` |
| DROP rate median | `0.6471399035148173` | `0.0` |
| DROP rate worst | `0.6579826319305278` | `0.0` |
| SYSCALL_ENTRY total | `142` | `400` |
| SYSCALL_RET total | `139` | `395` |
| TRAP total | `2279` | `5` |
| Dominant TRAP source | `kernel_or_loader_trap` | `target_ecall_boundary` |
| UNKNOWN events | `0` | `0` |
| Corrupt records | `0` | `0` |
| Parser warning counts | `{}` | `{}` |
| Strong `process_creation_chain` | `0/5` | `0/5` |
| Weak `process_chain_shape` | `5/5` | `5/5` |
| Bundle checker | `PASS` | `PASS` |

The p0a gate still fails for two separate reasons:

1. Strong `process_creation_chain` is still not proven because clone parent return pid and waitid pid argument do not close.
2. The p0a profile allowed events are `DROP`, `SYSCALL_ENTRY`, and `SYSCALL_RET`, but one target ecall-boundary `TRAP` appears in each rep. This is not a TRAP flood, but the strict gate flags `TRAP` as unexpected for p0a.

The p0a capacity debug artifacts are:

- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/process_chain_capacity_debug.json`
- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/process_chain_capacity_debug.md`

Rule evidence debug artifacts are:

- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/aggregate/rule_evidence_debug_summary.json`
- `results/experiments/35t/35t-p0a-r512-process-chain-risk-20260520-com5/samples/malware_like_synthetic/process_chain/aggregate/rule_evidence_debug_post_fix/`

## Gate Table

| Run | Gate | DROP rate median | Capped reps | Unexpected events | Missing expected | Weak expected | Weak shape | Unexpected strong matched |
| --- | --- | ---: | --- | --- | --- | --- | --- | --- |
| `p0c` | `BLOCKED` | `0.6471399035148173` | `rep_00..rep_04` | none | none | `process_creation_chain` | `process_chain_shape` | none |
| `p0a` | `FAIL` | `0.0` | none | `TRAP` | none | `process_creation_chain` | `process_chain_shape` | none |

## Per-Rep Rule Stability

| Run | Strong `process_creation_chain` | Weak `process_creation_chain` | Weak behavior shape | Boundary closed |
| --- | ---: | ---: | --- | ---: |
| `p0c` | `0/5` | `5/5` | `process_chain_shape=5/5` | `0/5` |
| `p0a` | `0/5` | `5/5` | `process_chain_shape=5/5` | `0/5` |

The p0a gate report records `weak_rule_stability.process_creation_chain = 5/5` and `weak_behavior_stability.process_chain_shape = 5/5`. Strong rule stability remains `0/5`.

## Process-Chain Evidence

Strict strong evidence remains separated from weak evidence:

- Strong `process_creation_chain` requires target-scoped clone, execve, and waitid/wait-like evidence plus a positive clone parent return pid that is the same value used as the wait pid argument.
- Weak `process_chain_shape` only records the visible clone -> execve -> wait-like syscall shape. It is kept in `weak_expected_behavior` / `weak_rule_stability` and is not counted as strong.
- Unrelated weak `illegal_instruction_trap` is not counted for this sample. `illegal_instruction_trap` matched `0/5` in p0a.

p0a semantic recovery sees process syscalls but still decodes the parent/child boundary incorrectly or incompletely. For every rep, the strict semantic boundary has no overlap:

| Rep | Semantic clone parent return candidates | Semantic wait pid args | Raw pid-like debug hints | Strict closure |
| --- | --- | --- | --- | --- |
| `rep_00` | `[18874385, 659564, 416004, 416004]` | `[2635918376, 0]` | clone-like `[443]`, wait-like `[444, 445]` | no |
| `rep_01` | `[18874385, 659564, 416004, 416004]` | `[2635918376, 0]` | clone-like `[446]`, wait-like `[447, 448]` | no |
| `rep_02` | `[18874385, 659564, 416004, 416004]` | `[2635918376, 0]` | clone-like `[455]`, wait-like `[456, 457]` | no |
| `rep_03` | `[18874385, 659564, 416004, 416004]` | `[2635918376, 0]` | clone-like `[458]`, wait-like `[459, 460]` | no |
| `rep_04` | `[18874385, 659564, 416004, 416004]` | `[2635918376, 0]` | clone-like `[467]`, wait-like `[468, 469]` | no |

The raw pid-like hints show that process activity is present in the trace, but they are not sufficient for strong matching because they are ambiguous register snapshots until syscall role, argument ownership, and parent-return semantics are proven in recovery.

## Precise Root Cause

p0a answers the capacity question: the p0c failure was substantially caused by broad TRAP capture filling the 512-entry ring. With `p0a_syscall_drop`, the run has no cap and zero DROP.

The remaining blocker is not ring depth. The current blocker is process-boundary attribution and argument/return recovery:

- `clone -> execve -> waitid` shape is stable enough for weak evidence in 5/5 reps.
- Strong evidence fails because the recovered positive clone parent return candidates are not actual child pids, and recovered waitid pid arguments are pointer or zero values.
- Raw target snapshots contain pid-like values, but the inferred clone-like and wait-like values do not match under strict ownership.
- Therefore the precise blocker is `missing parent return / waitid arg recovery`, with a secondary `p0a profile gate mismatch` caused by a single target ecall-boundary TRAP per rep.

This is not currently classified as `capacity insufficient` or `hardware ring depth insufficient`, because p0a has DROP rate `0.0` and no cap hits.

## Narrow Profile / Filtering Plan

A narrower profile such as `p0d_syscall_user_ecall_trap_drop` is still useful if target ecall TRAP boundaries are required for future recovery, but it cannot be implemented as a pure profile entry with the current hardware control mask. The current profile mechanism only enables or disables all TRAP events. `rtl/trace/trace_filter.sv` has event-type, PC, and privilege filters, but no trap-subtype filter for ecall-like traps, and `board/artix7_35t/linux/rvmt_exp_runner.c` only writes the existing control mask.

Implementation plan:

1. Extend the trace filter/control path with a trap subtype filter bit, for example `enable_trap_ecall_only_i`.
2. Pass all syscall entry/return and DROP events.
3. For TRAP events, pass only ecall-like traps, using `instr == 0x00000073` and cause/priv fields where reliable.
4. Keep target attribution in the post-join code map layer unless runtime target PC ranges are also wired into the hardware filter.
5. Add `p0d_syscall_user_ecall_trap_drop` to `src/rv_maltrace/trace_profiles.py` only after the RTL/control bit exists, so the profile name maps to real hardware behavior.
6. Add a gate rule that expects the p0d event envelope, without allowing unrelated illegal-instruction TRAP evidence to count as process-chain weak evidence.

Self-test plan:

- Unit-test `trace_filter.sv` with syscall/drop pass cases, kernel/general TRAP reject cases, and ecall-like TRAP accept cases.
- Add profile self-test coverage for the p0d control mask and allowed event set after the new control bit is wired.
- Keep `tools/debug_process_chain_capacity.py --self-test` to validate capacity/debug classification.
- Keep `tools/audit_behavior.py --self-test` to ensure weak process evidence cannot become strong without parent/child closure.

Dry-run plan:

- Do not run a p0d board test until the RTL/control bit is implemented and timing/resource reports exist.
- After implementation, first dry-run only:

```powershell
uv run python tools/experiment_35t.py --stage board --run-id dryrun-p0d-r512-process-chain-risk-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0d_syscall_user_ecall_trap_drop --runtime-order abba --warmup 1 --sample process_chain --dry-run
```

Resource impact expectation:

- A trap subtype filter should add a small comparator/control path for `instr == 0x00000073` and optional cause/priv checks.
- It should not require increasing ring depth or BRAM use by itself.
- If target PC range filtering is pushed into hardware, it needs runtime range configuration and must be checked for timing impact.
- A r1024/ring-depth bitstream is not triggered by the current evidence because p0a eliminated cap and DROP.

## Commands and Return Codes

| Command | RC | Notes |
| --- | ---: | --- |
| `uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --runtime-order abba --warmup 1 --sample process_chain` | 0 | Generated p0a groundtruth prerequisite. |
| `uv run python tools/experiment_35t.py --stage board --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --runtime-order abba --warmup 1 --sample process_chain` | 0 | Fresh real board capture for process_chain only. |
| `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --runtime-order abba --warmup 1 --sample process_chain` | 0 | Offline analyze rerun. |
| `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0a_syscall_drop --runtime-order abba --warmup 1 --sample process_chain` | 0 | Offline report rerun. |
| `uv run python tools/check_35t_next_gate.py --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --reps 5 --sample process_chain` | 0 | Wrote gate report. Gate status is `FAIL`. |
| `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --sample process_chain` | 0 | Wrote triage. Promotion remains blocked. |
| `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --reps 5 --sample process_chain` | 0 | Bundle checker PASS. |
| `uv run python tools/debug_rule_evidence.py --run-id 35t-p0a-r512-process-chain-risk-20260520-com5 --sample process_chain` | 0 | Rule evidence debug PASS. |
| `uv run python tools/debug_process_chain_capacity.py --run-id 35t-p0c-r512-process-chain-risk-20260520-com5` | 0 | Wrote p0c capacity debug. |
| `uv run python tools/debug_process_chain_capacity.py --run-id 35t-p0a-r512-process-chain-risk-20260520-com5` | 0 | Wrote p0a capacity debug. |
| `uv run python -m compileall src\rv_maltrace tools` | 0 | Compile check PASS. |
| `uv run python tools/recover_behavior.py --self-test` | 0 | PASS. |
| `uv run python tools/audit_behavior.py --self-test` | 0 | PASS. |
| `uv run python tools/check_35t_next_gate.py --self-test` | 0 | PASS. |
| `uv run python tools/triage_35t_semantic_failures.py --self-test` | 0 | PASS. |
| `uv run python tools/check_35t_experiment_bundle.py --self-test` | 0 | PASS. |
| `uv run python tools/debug_process_chain_capacity.py --self-test` | 0 | PASS. |

## Decision Flags

| Flag | Value |
| --- | --- |
| `process_chain_capacity_fixed` | `true` |
| `process_chain_risk_passed` | `false` |
| `process_chain_risk_partially_passed` | `true` |
| `allowed_to_enter_staged_summary_gate` | `false` |
| `staged_p0c_r512_matrix_ready` | `false` |
| `full_matrix_ready` | `false` |

Partial pass means only that p0a produced low DROP, no cap, and weak `process_chain_shape` in 5/5 reps. It does not promote process-chain risk to passed, because strong `process_creation_chain` remains unproven and the p0a strict gate still fails.

## Stop Condition

Stop here. Do not run full matrix or case study. Do not claim mature detection. Next work, if requested, should focus on process-boundary recovery for clone parent return and waitid argument ownership, plus resolving the single unexpected p0a target ecall-boundary TRAP without broadening unrelated TRAP acceptance.
