# 35T Board Validation Runbook: 35t-targeted-board-validation-20260522

Status: READY_TO_RUN_ON_35T_BOARD

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Source run: `35t-smallcap-r512-full-synthetic-matrix-20260521`

Results root: `results/experiments/35t/35t-targeted-board-validation-20260522`

Validation mode: `dual_channel`

Trace-gate run: `35t-targeted-board-validation-20260522-trace-gate`

Trace-gate results root: `results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate`

Semantic side-channel run: `35t-targeted-board-validation-20260522-side-channel`

Semantic results root: `results/experiments/35t/35t-targeted-board-validation-20260522-side-channel`

Bundle root: `results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle`

## Capture Requirements

- target-scoped marker begin/end around each sample repetition
- runtime process map for runner_parent, target_child, kernel, and unknown roles
- reliable target syscall entry/return pairing for fd operations
- openat and execve path strings or a board-side/runner-side path side channel tied to target syscall events
- clone/fork return value from the parent side and wait PID in the same evidence window
- child runtime process ownership evidence across exec
- exact board runtime ELF/code-map identity
- DWARF/debug-line metadata or an addr2line-compatible source-location side channel if source-line attribution is claimed

## Commands

### groundtruth-trace-gate

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-targeted-board-validation-20260522-trace-gate --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate/samples`

Pass condition: required host/qemu baselines complete or failures are recorded explicitly

### groundtruth-side-channel

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-targeted-board-validation-20260522-side-channel --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-side-channel/samples`

Pass condition: required host/qemu baselines complete or failures are recorded explicitly for the side-channel pass

### rootfs

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage rootfs --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `build/board/artix7_35t`

Pass condition: 35T LiteX/VexRiscv rootfs experiment overlay is rebuilt

### board-trace-gate

Hardware required: yes

```bash
uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522-trace-gate --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0 --board-runner-path /usr/bin/rvmt_exp_runner
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate/board/raw_uart.log`

Pass condition: UART capture contains target-scoped markers and trace dumps for the full 13-sample matrix without syscall side-channel perturbation

### analyze-trace-gate

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage analyze --run-id 35t-targeted-board-validation-20260522-trace-gate --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate/samples`

Pass condition: strict trace-gate semantic recovery, behavior audit, alignment, and trace-code joins are regenerated

### report-trace-gate

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage report --run-id 35t-targeted-board-validation-20260522-trace-gate --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate/aggregate`

Pass condition: strict trace-gate aggregate reports are regenerated and failures remain explicit

### board-side-channel

Hardware required: yes

```bash
uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522-side-channel --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0 --board-runner-path /usr/bin/rvmt_exp_runner --syscall-side-channel
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-side-channel/board/raw_uart.log`

Pass condition: UART capture contains syscall side-channel observations needed for fd/path and process-tree semantic closure

### analyze-side-channel

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage analyze --run-id 35t-targeted-board-validation-20260522-side-channel --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-side-channel/samples`

Pass condition: side-channel semantic recovery and trace-code joins are regenerated

### report-side-channel

Hardware required: no

```bash
uv run python tools/experiment_35t.py --stage report --run-id 35t-targeted-board-validation-20260522-side-channel --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522-side-channel/aggregate`

Pass condition: side-channel aggregate reports are regenerated and failures remain explicit

### package

Hardware required: no

```bash
uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522-side-channel --trace-gate-results-root results/experiments/35t/35t-targeted-board-validation-20260522-trace-gate --semantic-results-root results/experiments/35t/35t-targeted-board-validation-20260522-side-channel --validation-run-id 35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle
```

Expected output: `results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle/bundle_manifest.json`

Pass condition: bundle is PASS only if strict trace gate, fd/path summary, process-tree summary, and function-level attribution checks pass

### check

Hardware required: no

```bash
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results
```

Expected output: `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_status.json`

Pass condition: status is PASS only when required artifacts and content checks pass

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
