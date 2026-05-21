# 35T Targeted Board Validation Plan

Status: AWAITING_BOARD_RUN

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Source Run

`35t-smallcap-r512-full-synthetic-matrix-20260521`

## Objectives

- Close fd/path flow only when `openat(path) -> fd -> read/write/getdents64/close` evidence is paired and target-scoped.
- Close `process_chain` parent-child explanation only when clone/fork return PID, wait PID, exec boundary, and runtime ownership agree.
- Add function/source attribution without claiming complete semantic reconstruction.
- Keep benign overlap separate from synthetic malware-like behavior evidence.

## Required Capture

- Target-scoped marker begin/end around each sample repetition.
- Runtime process map for `runner_parent`, `target_child`, `kernel`, and `unknown`.
- Reliable target syscall entry/return pairing for fd operations.
- `openat` and `execve` path strings, or a board-side/runner-side path side channel tied to target syscall events.
- Parent-side clone/fork return value and wait PID in the same evidence window.
- Child runtime process ownership evidence across exec.
- Exact board runtime ELF/code-map identity.
- DWARF/debug-line metadata or an `addr2line`-compatible source-location side channel if source-line attribution is claimed.

## Required Outputs

- `run_config.json`
- `gate_report.json` and `gate_report.md`
- `fd_path_flow_summary.json` and `fd_path_flow_summary.md`
- `process_tree_summary.json` and `process_tree_summary.md`
- `source_attribution_summary.json` and `source_attribution_summary.md`
- `command_log.md`

## Packaging And Check

Use `tools/package_35t_board_validation.py` to turn a local 35T run root into a flat result bundle. The packager preserves `PARTIAL` or `UNAVAILABLE` statuses; it must not upgrade old evidence into a board-validation PASS.

```bash
uv run python tools/package_35t_board_validation.py --repo-root .
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results
```

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
