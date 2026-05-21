# 35T Illegal Trap Attribution Fix Status

Date: 2026-05-20
Run ID: `35t-p0c-abba-r512-20260520-com5`
Scope: existing p0c 512 ABBA artifacts only; four samples `hello`, `batch_open_read_write`, `illegal_trap`, `anti_debug_like`.

## Boundary

- Board boundary: 35T/LiteX/VexRiscv synthetic behavior audit prototype only.
- Non-claims: no CVA6 board claim; no real malware detection claim; no mature detector claim.
- Not run in this pass: full matrix, case study, COM5/921600 board microbench.

## Root Cause

`illegal_trap_stable_expected_rule=false` had two offline attribution causes:

1. Code-map input mismatch: analyze used the QEMU groundtruth ELF64 code map (`illegal_trap.riscv`) whose illegal site is `0x00000000000104c4/main+0x30`. The board trace is from the rootfs overlay ELF32 `/usr/bin/illegal_trap`, whose illegal site is `0x000000000001056c/main+0x44`.
2. Syscall recovery gap: in some reps, the handler `write` appears as a target `syscall_site` `ecall` recorded as a TRAP-shaped event with raw register snapshot (`a7=0x40`), not as a normal `SYSCALL_ENTRY`. Recovery now treats only target code-map `syscall_site` + `ecall` trap evidence as a syscall boundary.

This was fixed without weakening `illegal_instruction_trap`: the rule still requires target illegal-instruction site evidence and `write` evidence.

## Changes

- `experiment_35t.py`: analyze now prefers board rootfs overlay runtime ELFs under `build/board/artix7_35t/rootfs_exp_overlay/usr/bin` before falling back to groundtruth `.riscv`.
- `build_code_map.py`: records `binary_role` and `runtime_path`; board code maps now show `board_rootfs_overlay` and `/usr/bin/<sample>`.
- `cli.py`: raw trace decoder preserves `a0..a7` snapshots for `SYSCALL_RET` and `TRAP`, plus raw metadata.
- `recover_behavior.py`: recovers return-only syscall snapshots and target `syscall_site` ecall traps as syscall boundary evidence.
- `debug_trap_attribution.py`: new per-rep trap/syscall/priv attribution debug report with pc, cause, priv, owner, symbol, nearest illegal site, pc_delta, parser warnings, and raw words.
- `compress_trace.py`: round-trip preservation updated for new `SYSCALL_RET`/`TRAP` metadata fields.

## Final Offline Result

| Check | Result |
| --- | --- |
| `hello` unexpected matched | none |
| `illegal_trap` stable expected `illegal_instruction_trap` | true, 10/10 reps |
| `batch_open_read_write` weak `batch_file_read_write` | true |
| UNKNOWN/corrupt events | 0/0 for all four samples |
| bundle checker | PASS |
| ready_for_35t_microbench | true, offline gate only |

`batch_open_read_write` still does not claim full strong `batch_file_read_write`; it remains weak shape evidence only, which satisfies this blocker pass.

## Artifact Paths

- Gate report: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/gate_report.json`
- Gate markdown: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/gate_report.md`
- Semantic triage: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/semantic_failure_triage.json`
- Semantic triage markdown: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/semantic_failure_triage.md`
- Pre-fix trap debug: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/illegal_trap/aggregate/trap_attribution_debug_pre_fix_groundtruth/trap_attribution_debug.json`
- Post-fix trap debug: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/illegal_trap/aggregate/trap_attribution_debug_post_fix_board/trap_attribution_debug.json`
- Post-fix trap debug CSV: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/illegal_trap/aggregate/trap_attribution_debug_post_fix_board/trap_attribution_debug.csv`
- Board code map: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/illegal_trap/build/illegal_trap.code_map.json`

## Key Evidence

- Pre-fix debug diagnosis: `ILLEGAL_CAUSE_PRESENT_WITHOUT_CURRENT_CODE_SITE_MATCH_ALL_REPS`
- Pre-fix illegal hits: `0/10` reps with current groundtruth code site.
- Note: the pre-fix debug command was run before analyze regenerated `illegal_trap.code_map.json`; the pre-fix artifact preserves the ELF64 groundtruth metadata it used.
- Board rootfs illegal site: `0x000000000001056c/main+0x44`.
- Post-fix debug diagnosis: `MATCHED_EXPECTED_ILLEGAL_INSTRUCTION_SITE_ALL_REPS`
- Post-fix illegal hits: `10/10` reps, each with `pc_delta=0`.
- Example handler write recovery in a previously failing rep: `rep_02`, source event `TRAP`, `pc=0x000000000001834c`, `callsite_kind=syscall_site`, `a7=0x40`, recovered as `write`.

## Commands

| Command | RC |
| --- | ---: |
| `uv run python -m compileall src\rv_maltrace tools` | 0 |
| `uv run python tools/build_code_map.py --self-test` | 0 |
| `uv run python tools/join_trace_code_map.py --self-test` | 0 |
| `uv run python tools/recover_behavior.py --self-test` | 0 |
| `uv run python tools/audit_behavior.py --self-test` | 0 |
| `uv run python tools/debug_trap_attribution.py --self-test` | 0 |
| `uv run python tools/check_35t_next_gate.py --self-test` | 0 |
| `uv run python tools/triage_35t_semantic_failures.py --self-test` | 0 |
| `uv run python tools/experiment_35t.py --stage self-test` | 0 |
| `uv run python tools/check_35t_experiment_bundle.py --self-test` | 0 |
| `uv run python tools/check_artix7_raw_trace.py` | 0 |
| `uv run python tools/analyze_trace_lightweight.py --self-test` | 0 |
| `uv run python tools/compress_trace.py results\experiments\35t\35t-p0c-abba-r512-20260520-com5\samples\malware_like_synthetic\illegal_trap\board\trace-on\rep_00\trace.jsonl --check-roundtrip --stats` | 0 |
| `uv run python tools/debug_trap_attribution.py --run-id 35t-p0c-abba-r512-20260520-com5 --sample-class malware_like_synthetic --sample-id illegal_trap --code-map results\experiments\35t\35t-p0c-abba-r512-20260520-com5\samples\malware_like_synthetic\illegal_trap\build\illegal_trap.code_map.json --out-dir results\experiments\35t\35t-p0c-abba-r512-20260520-com5\samples\malware_like_synthetic\illegal_trap\aggregate\trap_attribution_debug_pre_fix_groundtruth` | 0 |
| `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0c-abba-r512-20260520-com5 --port COM5 --baud 921600 --reps 10 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 |
| `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0c-abba-r512-20260520-com5 --port COM5 --baud 921600 --reps 10 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 |
| `uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 |
| `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-abba-r512-20260520-com5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 |
| `uv run python tools/debug_trap_attribution.py --run-id 35t-p0c-abba-r512-20260520-com5 --sample-class malware_like_synthetic --sample-id illegal_trap --out-dir results\experiments\35t\35t-p0c-abba-r512-20260520-com5\samples\malware_like_synthetic\illegal_trap\aggregate\trap_attribution_debug_post_fix_board` | 0 |
| `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10` | 0 |

## Board Status

- `ready_for_35t_microbench`: true based on offline promotion checks.
- `board_microbench_run`: not run in this blocker-only pass.
- Next allowed command, if explicitly proceeding to board microbench: `uv run python tools/experiment_35t.py --stage board --run-id <new-run-id> --port COM5 --baud 921600 --reps 512 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like`
