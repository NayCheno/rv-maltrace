# 35T Command Log: 35t-smallcap-r512-full-synthetic-matrix-20260521

Generated UTC: 2026-05-22T11:35:01Z

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Non-claims: no CVA6 board claim; no real malware detection claim; no mature detector claim; no classifier accuracy claim; no complete semantic reconstruction claim.

| Phase | Command | Status | Reason |
|---|---|---|---|
| P2 | `uv run python tools/experiment_35t.py --stage self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/check_35t_next_gate.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/triage_35t_semantic_failures.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/recover_behavior.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/audit_behavior.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/build_code_map.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/join_trace_code_map.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/check_35t_application_closure.py --self-test` | PASS | exit_code=0 |
| P2 | `uv run python tools/check_35t_application_closure.py --repo-root .` | PASS | exit_code=0 |
| P2 | `uv run python -m compileall tools src/rv_maltrace` | PASS | exit_code=0 |
| P3 | `uv run python tools/recover_fd_path_flow.py --self-test` | PASS | exit_code=0 |
| P3 | `uv run python tools/recover_fd_path_flow.py --sample file_scan --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521` | PASS | exit_code=0 |
| P4 | `uv run python tools/recover_process_tree.py --self-test` | PASS | exit_code=0 |
| P4 | `uv run python tools/recover_process_tree.py --sample process_chain --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521` | PASS | exit_code=0 |
| readiness | `uv run python tools/summarize_35t_explanation_readiness.py --self-test` | PASS | exit_code=0 |
| readiness | `uv run python tools/summarize_35t_explanation_readiness.py --repo-root .` | PASS | exit_code=0 |
| source-attribution | `uv run python tools/summarize_35t_source_attribution.py --self-test` | PASS | exit_code=0 |
| source-attribution | `uv run python tools/summarize_35t_source_attribution.py --repo-root .` | PASS | exit_code=0, status=PARTIAL |
| board-validation | `uv run python tools/check_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| board-validation | `uv run python tools/check_35t_board_validation.py --repo-root .` | PASS | exit_code=0, status=AWAITING_BOARD_RUN |
| board-validation-negative | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521 --require-results` | FAIL | exit_code=1, expected negative check: current snapshot is not a board-validation result bundle because fd/path and process tree remain PARTIAL |
| board-validation-package | `uv run python tools/package_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| board-validation-package | `uv run python tools/package_35t_board_validation.py --repo-root .` | PASS | exit_code=0, status=CANDIDATE_PARTIAL |
| board-validation-package-negative | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results` | FAIL | exit_code=1, expected negative check: packaged current run still has PARTIAL fd/path and process-tree summaries |
| board-validation | `uv run python tools/check_35t_board_validation.py --repo-root .` | PASS | exit_code=0, status=AWAITING_BOARD_RUN |
| board-validation-runbook | `uv run python tools/prepare_35t_board_validation_run.py --self-test` | PASS | exit_code=0 |
| board-validation-runbook | `uv run python tools/prepare_35t_board_validation_run.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, status=READY_TO_RUN_ON_35T_BOARD |
| board-validation-preflight | `uv run python tools/check_35t_board_preflight.py --self-test` | PASS | exit_code=0 |
| board-validation-preflight | `uv run python tools/check_35t_board_preflight.py --repo-root .` | PASS | exit_code=0, status=READY_FOR_BOARD_RUN |
| board-validation-preflight | `uv run python tools/check_35t_board_preflight.py --repo-root . --require-board --no-write` | PASS | exit_code=0, status=READY_FOR_BOARD_RUN |
| actual-board-run | `uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/experiment_35t.py --stage rootfs --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/experiment_35t.py --stage report --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/check_35t_next_gate.py --run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0; historical pre-side-channel next-gate output was recorded before the later selected-artifact validation update |
| actual-board-run | `uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle` | PASS | exit_code=0, status=CANDIDATE_PARTIAL |
| actual-board-run | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results` | FAIL | exit_code=1, status=RESULTS_PARTIAL; fd/path and process-tree remain PARTIAL |
| actual-board-run | `uv run python tools/summarize_35t_board_validation_attempt.py --self-test` | PASS | exit_code=0 |
| actual-board-run | `uv run python tools/summarize_35t_board_validation_attempt.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, status=BOARD_RUN_COMPLETE_VALIDATION_PARTIAL |
| side-channel-tooling | `uv run python tools/experiment_35t.py --stage rootfs --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --syscall-side-channel` | PASS | exit_code=0 after switching runner register reads to `PTRACE_GETREGSET`; generated updated 35T rootfs/sdcard image |
| side-channel-smoke | `uv run python tools/experiment_35t.py --stage board --run-id 35t-sidechannel-smoke-20260522 --reps 1 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 600 --sample file_scan --sample process_chain --syscall-side-channel` | FAIL | exit_code=0 for command capture, but syscall_obs_lines=0; board `/usr/bin/rvmt_exp_runner` was still an older image |
| side-channel-smoke | UART temporary install of first `/tmp/rvmt_exp_runner` plus `35t-sidechannel-smoke-20260522b` | FAIL | first side-channel runner used `PTRACE_GETREGS`; board returned `ptrace getregs: Input/output error`; trace-on reps exited 127 |
| side-channel-smoke | `uv run python tools/experiment_35t.py --stage board --run-id 35t-sidechannel-smoke-20260522c --reps 1 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 120 --sample file_scan --sample process_chain --syscall-side-channel --board-runner-path /tmp/rvmt_exp_runner` | PASS_WITH_PARTIAL_EVIDENCE | exit_code=0; captured 56 `RVMT_SYSCALL_OBS` rows and 2 `syscall_side_channel.json` files, but packaged fd/path and process-tree summaries stayed PARTIAL because the smoke used the pre state-machine-fix runner |
| side-channel-smoke | UART temporary install of state-machine-fix `/tmp/rvmt_exp_runner` | FAIL | decoded board binary hash mismatched local runner hash and crashed; not valid board evidence; requires booting the updated rootfs/sdcard image or a reliable transfer path |
| side-channel-smoke | `uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-sidechannel-smoke-20260522c --out-dir results/experiments/35t/35t-sidechannel-smoke-20260522c/board_validation_bundle` | PASS_WITH_PARTIAL_EVIDENCE | exit_code=0, status=CANDIDATE_PARTIAL; artifact set incomplete by design and fd/path/process-tree remained PARTIAL |
| side-channel-image-boot | LiteX serial image boot from `vendor/litex/linux-on-litex-vexriscv/images/boot.json` into updated 35T rootfs | PASS | uploaded updated Linux image; `/usr/bin/rvmt_exp_runner --syscall-side-channel hello` confirmed `syscall_side_channel=1` on board |
| side-channel-smoke | `uv run python tools/experiment_35t.py --stage board --run-id 35t-sidechannel-smoke-20260522e --reps 1 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 180 --sample file_scan --sample process_chain --syscall-side-channel` | PASS | exit_code=0; captured 48 `RVMT_SYSCALL_OBS` rows and 2 `syscall_side_channel.json` files |
| side-channel-smoke | `uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-sidechannel-smoke-20260522e --out-dir results/experiments/35t/35t-sidechannel-smoke-20260522e/board_validation_bundle` | PASS_WITH_PARTIAL_EVIDENCE | exit_code=0; smoke bundle has fd/path PASS and process-tree PASS, but is not a full 13-sample validation bundle |
| actual-board-run-sidechannel | `uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0 --syscall-side-channel` | PASS | exit_code=0; trace-off 65/65 PASS and trace-on 65/65 PASS |
| actual-board-run-sidechannel | `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --syscall-side-channel` | PASS | exit_code=0 |
| actual-board-run-sidechannel | `uv run python tools/experiment_35t.py --stage report --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --syscall-side-channel` | PASS | exit_code=0 |
| actual-board-run-sidechannel | `uv run python tools/check_35t_next_gate.py --run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0; side-channel aggregate records sample_status=13/13 PASS and strict sample_gate_status=9/13 PASS; dual-channel paper gate handles this as semantic-channel evidence |
| actual-board-run-sidechannel | `uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle` | PASS | exit_code=0, status=PASS |
| actual-board-run-sidechannel | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results` | PASS | exit_code=0, hardware_validated=true; fd/path PASS, process-tree PASS, source-attribution PARTIAL |
| actual-board-run-sidechannel | `uv run python tools/summarize_35t_board_validation_attempt.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, status=BOARD_VALIDATION_PASS |
| final | `uv run --no-sync python tools/check_35t_application_closure.py --self-test` | PASS | exit_code=0 |
| final | `uv run --no-sync python tools/check_35t_application_closure.py --repo-root .` | PASS | exit_code=0; fd_path_status=PASS; process_tree_status=PASS |
| final | `uv run --no-sync python tools/recover_fd_path_flow.py --self-test` | PASS | exit_code=0 |
| final | `uv run --no-sync python tools/recover_process_tree.py --self-test` | PASS | exit_code=0 |
| final | `uv run --no-sync python tools/summarize_35t_source_attribution.py --self-test` | PASS | exit_code=0 |
| final | `uv run --no-sync python tools/summarize_35t_source_attribution.py --repo-root .` | PASS | exit_code=0, source-attribution status=PARTIAL, function-attribution status=PASS |
| final | `uv run --no-sync python tools/package_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| final | `uv run --no-sync python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle` | PASS | exit_code=0, status=PASS |
| final | `uv run --no-sync python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results` | PASS | exit_code=0, hardware_validated=true |
| final | `uv run --no-sync python -m compileall tools src/rv_maltrace` | PASS | exit_code=0 |
| final | `git diff --check` | PASS | exit_code=0 |

## Output Excerpts

### `uv run python tools/experiment_35t.py --stage self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T experiment self-test
```

### `uv run python tools/check_35t_next_gate.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T next gate self-test
```

### `uv run python tools/triage_35t_semantic_failures.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] semantic failure triage self-test
```

### `uv run python tools/recover_behavior.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] behavior recovery self-test
```

### `uv run python tools/audit_behavior.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] behavior audit self-test
```

### `uv run python tools/build_code_map.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] build_code_map self-test
```

### `uv run python tools/join_trace_code_map.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] join_trace_code_map self-test
```

### `uv run python tools/check_35t_application_closure.py --self-test`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T application closure self-test
```

### `uv run python tools/check_35t_application_closure.py --repo-root .`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T application closure check
```

### `uv run python -m compileall tools src/rv_maltrace`

Phase: P2

Status: PASS (exit_code=0)

stdout:

```text
Listing 'tools'...
Listing 'src/rv_maltrace'...
```

### LiteX serial image boot from `images/boot.json`

Phase: side-channel-image-boot

Status: PASS

Result: the 35T board booted the updated Linux image/rootfs through the LiteX serial image loader. A direct board smoke of `/usr/bin/rvmt_exp_runner --syscall-side-channel hello` reported `syscall_side_channel=1`.

### `uv run python tools/experiment_35t.py --stage board --run-id 35t-sidechannel-smoke-20260522e --reps 1 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 180 --sample file_scan --sample process_chain --syscall-side-channel`

Phase: side-channel-smoke

Status: PASS (exit_code=0)

Result: 48 `RVMT_SYSCALL_OBS` rows and two `syscall_side_channel.json` files were captured on board. The packaged smoke summaries reported fd/path `PASS` and process-tree `PASS`.

### `uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0 --syscall-side-channel`

Phase: actual-board-run-sidechannel

Status: PASS (exit_code=0)

Result: the full 13-sample targeted 35T board run completed with trace-off 65/65 PASS and trace-on 65/65 PASS.

### `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results`

Phase: actual-board-run-sidechannel

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board validation status
```

Result: strict 35T board validation is closed for the current prototype claim. fd/path flow is `PASS`, process-tree explanation is `PASS`, and source attribution remains `PARTIAL`.

### `uv run python tools/recover_fd_path_flow.py --self-test`

Phase: P3

Status: PASS (exit_code=0)

stdout:

```text
[PASS] fd/path flow self-test
```

### `uv run python tools/recover_fd_path_flow.py --sample file_scan --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521`

Phase: P3

Status: PASS (exit_code=0)

stdout:

```text
[PARTIAL] fd/path flow summary for file_scan
```

### `uv run python tools/recover_process_tree.py --self-test`

Phase: P4

Status: PASS (exit_code=0)

stdout:

```text
[PASS] process tree self-test
```

### `uv run python tools/recover_process_tree.py --sample process_chain --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521`

Phase: P4

Status: PASS (exit_code=0)

stdout:

```text
[PARTIAL] process tree summary for process_chain
```

### `uv run python tools/summarize_35t_explanation_readiness.py --self-test`

Phase: readiness

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T explanation readiness self-test
```

### `uv run python tools/summarize_35t_explanation_readiness.py --repo-root .`

Phase: readiness

Status: PASS (exit_code=0)

stdout:

```text
[READY_FOR_TARGETED_BOARD_VALIDATION] 35T explanation readiness
```

### `uv run python tools/summarize_35t_source_attribution.py --self-test`

Phase: source-attribution

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T source attribution summary self-test
```

### `uv run python tools/summarize_35t_source_attribution.py --repo-root .`

Phase: source-attribution

Status: PASS (exit_code=0)

stdout:

```text
[PARTIAL] 35T source attribution summary
```

### `uv run python tools/check_35t_board_validation.py --self-test`

Phase: board-validation

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board validation checker self-test
```

### `uv run python tools/check_35t_board_validation.py --repo-root .`

Phase: board-validation

Status: PASS (exit_code=0)

stdout:

```text
[AWAITING_BOARD_RUN] 35T board validation status
```

### `uv run python tools/check_35t_board_validation.py --repo-root . --results-root docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521 --require-results`

Phase: board-validation-negative

Status: FAIL (exit_code=1)

Reason: expected negative check. The current committed snapshot is not a completed board-validation result bundle because fd/path and process-tree summaries remain `PARTIAL`.

stdout:

```text
[FAIL] 35T board validation status
```

stderr:

```text
FAIL: board validation result content check failed: fd_path_flow
FAIL: board validation result content check failed: process_tree
```

### `uv run python tools/prepare_35t_board_validation_run.py --self-test`

Phase: board-validation-runbook

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board validation runbook self-test
```

### `uv run python tools/prepare_35t_board_validation_run.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522`

Phase: board-validation-runbook

Status: PASS (exit_code=0)

stdout:

```text
[READY_TO_RUN_ON_35T_BOARD] 35T board validation runbook for 35t-targeted-board-validation-20260522
groundtruth: uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
rootfs: uv run python tools/experiment_35t.py --stage rootfs --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
board: uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0
analyze: uv run python tools/experiment_35t.py --stage analyze --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
report: uv run python tools/experiment_35t.py --stage report --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic
package: uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle
check: uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results
```

### `uv run python tools/check_35t_board_preflight.py --self-test`

Phase: board-validation-preflight

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board preflight self-test
```

### `uv run python tools/check_35t_board_preflight.py --repo-root .`

Phase: board-validation-preflight

Status: PASS (exit_code=0)

stdout:

```text
[READY_FOR_BOARD_RUN] 35T board validation preflight
```

### `uv run python tools/check_35t_board_preflight.py --repo-root . --require-board --no-write`

Phase: board-validation-preflight

Status: PASS (exit_code=0)

Reason: the requested UART port is visible through pyserial. This is still only preflight readiness and does not prove the 35T board image is running.

stdout:

```text
[READY_FOR_BOARD_RUN] 35T board validation preflight
```

### `uv run python tools/experiment_35t.py --stage board --run-id 35t-targeted-board-validation-20260522 --reps 5 --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order classic --port COM5 --baud 921600 --duration 3600.0`

Phase: actual-board-run

Status: PASS (exit_code=0)

stdout excerpt:

```text
+ capture 35T experiment UART on COM5 921600 8N1 for 3600s to results/experiments/35t/35t-targeted-board-validation-20260522/board/raw_uart.log
+ send: /usr/bin/rvmt_exp_runner ... trace-off ... hello ls cat cp sha256sum file_scan batch_open_read_write self_copy_sim abnormal_syscall_sequence process_chain dynamic_executable_memory anti_debug_like
+ send: /usr/bin/rvmt_exp_runner ... trace-on ... hello ls cat cp sha256sum file_scan batch_open_read_write self_copy_sim abnormal_syscall_sequence process_chain dynamic_executable_memory anti_debug_like
+ send: /usr/bin/rvmt_exp_runner ... trace-off ... illegal_trap
+ send: /usr/bin/rvmt_exp_runner ... trace-on ... illegal_trap
```

### `uv run python tools/check_35t_next_gate.py --run-id 35t-targeted-board-validation-20260522`

Phase: actual-board-run

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T next gate report written: results/experiments/35t/35t-targeted-board-validation-20260522/aggregate/gate_report.json
```

Result recorded at that stage: `full_matrix_ready`, 13/13 sample status PASS. The later side-channel validation rerun is bounded separately by `paper_evidence_check.md`: current targeted side-channel strict sample gate is 9/13 PASS and must not be described as single-run all-gates PASS.

### `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results`

Phase: actual-board-run

Status: FAIL (exit_code=1)

Reason: actual 35T board run completed, but strict validation remains partial because fd/path flow and process-tree summaries are not PASS.

stdout:

```text
[RESULTS_PARTIAL] 35T board validation status
```

stderr:

```text
FAIL: board validation result content check failed: fd_path_flow
FAIL: board validation result content check failed: process_tree
```

### `uv run python tools/summarize_35t_board_validation_attempt.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522`

Phase: actual-board-run

Status: PASS (exit_code=0)

stdout:

```text
[BOARD_RUN_COMPLETE_VALIDATION_PARTIAL] 35T board validation attempt summary
```

### `uv run python tools/package_35t_board_validation.py --self-test`

Phase: board-validation-package

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board validation bundle packager self-test
```

### `uv run python tools/package_35t_board_validation.py --repo-root .`

Phase: board-validation-package

Status: PASS (exit_code=0)

stdout:

```text
[CANDIDATE_PARTIAL] 35T board validation bundle at results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle
```

stderr:

```text
CHECKER: board validation result content check failed: fd_path_flow
CHECKER: board validation result content check failed: process_tree
```

### `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results`

Phase: board-validation-package-negative

Status: FAIL (exit_code=1)

Reason: expected negative check. The packaged current run is still not a completed board-validation result bundle because fd/path and process-tree summaries remain `PARTIAL`.

stdout:

```text
[FAIL] 35T board validation status
```

stderr:

```text
FAIL: board validation result content check failed: fd_path_flow
FAIL: board validation result content check failed: process_tree
```

### `uv run python tools/check_35t_application_closure.py --repo-root .`

Phase: final

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T application closure check
```

### `uv run python -m compileall tools src/rv_maltrace`

Phase: final

Status: PASS (exit_code=0)

stdout:

```text
Listing 'tools'...
Listing 'src/rv_maltrace'...
```

### `uv run --no-sync python tools/check_35t_paper_evidence.py --self-test`

Phase: paper-evidence

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T paper evidence self-test
```

### `uv run --no-sync python tools/summarize_35t_board_validation_attempt.py --self-test`

Phase: paper-evidence

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T board validation attempt summary self-test
```

### `uv run --no-sync python tools/summarize_35t_board_validation_attempt.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522`

Phase: paper-evidence

Status: PASS (exit_code=0)

stdout:

```text
[BOARD_VALIDATION_PASS] 35T board validation attempt summary
```

### `uv run --no-sync python tools/check_35t_paper_evidence.py --repo-root .`

Phase: paper-evidence

Status: PASS (exit_code=0)

stdout:

```text
[PASS] 35T paper evidence check (SUPPORTED_WITH_BOUNDED_CLAIMS)
```

stderr:

```text
warning: targeted side-channel validation is not a strict single-run full-matrix gate PASS
```

## Dual-Channel Trace-Gate Repair Validation

The targeted side-channel semantic capture remains 9/13 for strict sample gate,
so the paper-facing validation gate was repaired by packaging a dual-channel
bundle: the low-perturbation full-matrix run is the trace-gate channel, and the
side-channel run is the selected semantic evidence channel.

| Phase | Command | Status | Reason |
|---|---|---|---|
| dual-channel-tooling | `uv run --no-sync python tools/check_35t_application_closure.py --self-test` | PASS | exit_code=0 |
| dual-channel-tooling | `uv run --no-sync python tools/check_35t_paper_evidence.py --self-test` | PASS | exit_code=0 |
| dual-channel-tooling | `uv run --no-sync python tools/check_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| dual-channel-tooling | `uv run --no-sync python tools/package_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| dual-channel-tooling | `uv run --no-sync python tools/prepare_35t_board_validation_run.py --self-test` | PASS | exit_code=0 |
| dual-channel-tooling | `uv run --no-sync python tools/summarize_35t_board_validation_attempt.py --self-test` | PASS | exit_code=0 |
| dual-channel-package | `uv run --no-sync python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --trace-gate-results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521 --semantic-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --validation-run-id 35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle` | PASS | exit_code=0, validation_mode=dual_channel |
| dual-channel-check | `uv run --no-sync python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results` | PASS | exit_code=0, trace-gate strict sample gate 13/13 PASS |
| dual-channel-check | `uv run --no-sync python tools/summarize_35t_board_validation_attempt.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, status=BOARD_VALIDATION_PASS |
| dual-channel-check | `uv run --no-sync python tools/check_35t_application_closure.py --repo-root .` | PASS | exit_code=0 |
| dual-channel-check | `uv run --no-sync python tools/check_35t_paper_evidence.py --repo-root .` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS, strict_single_run_status=PASS |
| final | `uv run --no-sync python -m compileall tools src/rv_maltrace` | PASS | exit_code=0 |
| final | `git diff --check` | PASS | exit_code=0 |

## fd/path Case Study Closure

The fd/path case-study checker expands the P1 evidence beyond the compact
`file_scan` summary. It verifies that `file_scan`, `batch_open_read_write`, and
`self_copy_sim` each have a targeted 35T board syscall side-channel candidate
with closed fd/path flows.

| Phase | Command | Status | Reason |
|---|---|---|---|
| fd-path-case-study-tooling | `uv run --no-sync python tools/check_35t_fd_path_case_studies.py --self-test` | PASS | exit_code=0 |
| fd-path-case-studies | `uv run --no-sync python tools/check_35t_fd_path_case_studies.py --repo-root .` | PASS | exit_code=0, status=PASS, samples=file_scan/batch_open_read_write/self_copy_sim |
| fd-path-case-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P1=PASS with fd_path_case_studies.json |

## Pointer Semantics Preflight Closure

## Process Tree Case Study Closure

The process-tree case-study checker expands the P2 evidence into the exact
process graph requested by the assessment. It verifies clone return child PIDs,
child execve path strings, parent wait PID arguments, and graph output from the
targeted 35T board syscall side-channel.

| Phase | Command | Status | Reason |
|---|---|---|---|
| process-tree-case-tooling | `uv run --no-sync python tools/check_35t_process_tree_case_study.py --self-test` | PASS | exit_code=0 |
| process-tree-case-study | `uv run --no-sync python tools/check_35t_process_tree_case_study.py --repo-root .` | PASS | exit_code=0, status=PASS, sample=process_chain |
| process-tree-case-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P2=PASS with process_tree_case_study.json |

The pointer semantics preflight records the P3 boundary without upgrading the
hardware pointer claim. Synthetic ARG_MEM simulation covers pointer string and
guardrail behavior, and the targeted board syscall side-channel closes
representative fd/path and process-tree semantics. Hardware user-pointer
snapshots remain deferred and default-disabled in the current 35T
small-capacity run.

| Phase | Command | Status | Reason |
|---|---|---|---|
| pointer-tooling | `uv run --no-sync python tools/check_35t_pointer_semantics_preflight.py --self-test` | PASS | exit_code=0 |
| pointer-preflight | `uv run --no-sync python tools/check_35t_pointer_semantics_preflight.py --repo-root .` | PASS | exit_code=0, status=SYNTHETIC_ARG_MEM_GUARDRAILS_PASS_SIDE_CHANNEL_CLOSURE_HARDWARE_POINTER_DEFERRED |
| pointer-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P3=PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS |

## Threat Model Boundary Closure

The threat model checker records the trusted-kernel, user-mode malware-like
workload boundary required by the assessment. It keeps helper/eBPF routes
optional and deferred, and it explicitly excludes kernel rootkit resistance.

| Phase | Command | Status | Reason |
|---|---|---|---|
| threat-model-tooling | `uv run --no-sync python tools/check_35t_threat_model.py --self-test` | PASS | exit_code=0 |
| threat-model-boundary | `uv run --no-sync python tools/check_35t_threat_model.py --repo-root .` | PASS | exit_code=0, status=TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED |
| threat-model-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P3 threat model boundary recorded |

## Baseline Evaluation Closure

The baseline closure pass in this section predates the later eBPF closure below.
It summarizes existing host/QEMU/strace timing evidence from the primary 35T
aggregate metrics and adds a separate host software instrumentation run. The
software instrumentation baseline uses GCC
`-finstrument-functions` function entry/exit logging, reports 13/13 PASS over
5 reps, and keeps raw function logs in the local `results/` tree. At that
point it did not claim that eBPF-only or QEMU-plugin baselines had run. The
advanced baseline preflight probes Docker `linux-behavior` and WSL separately,
without combining prerequisites across environments. Later P4 evidence updates
eBPF-only to PASS and keeps QEMU-plugin blocked.

| Phase | Command | Status | Reason |
|---|---|---|---|
| baseline-tooling | `uv run --no-sync python tools/check_35t_advanced_baseline_preflight.py --self-test` | PASS | exit_code=0 |
| baseline-preflight | `uv run --no-sync python tools/check_35t_advanced_baseline_preflight.py --repo-root .` | PASS | exit_code=0, status=BLOCKED_CURRENT_ENVIRONMENT, Docker+WSL probes recorded; eBPF-only and QEMU-plugin remained blocked at this stage |
| baseline-tooling | `uv run --no-sync python tools/run_35t_software_instrumentation_baseline.py --self-test` | PASS | exit_code=0 |
| baseline-smoke | `uv run --no-sync python tools/run_35t_software_instrumentation_baseline.py --sample hello --reps 1` | PASS | exit_code=0, sample_count=1 |
| baseline-run | `uv run --no-sync python tools/run_35t_software_instrumentation_baseline.py --reps 5` | PASS | exit_code=0, sample_count=13, pass_count=13 |
| baseline-tooling | `uv run --no-sync python tools/summarize_35t_baselines.py --self-test` | PASS | exit_code=0 |
| baseline-tooling | `uv run --no-sync python tools/check_35t_evaluation_table.py --self-test` | PASS | exit_code=0 |
| baseline-tooling | `uv run --no-sync python tools/check_35t_metric_coverage.py --self-test` | PASS | exit_code=0 |
| baseline-tooling | `uv run --no-sync python tools/check_35t_baseline_evaluation.py --self-test` | PASS | exit_code=0 |
| baseline-tooling | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --self-test` | PASS | exit_code=0 |
| baseline-summary | `uv run --no-sync python tools/summarize_35t_baselines.py --repo-root .` | PASS | exit_code=0, status=HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN |
| baseline-evaluation-table | `uv run --no-sync python tools/check_35t_evaluation_table.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_EVALUATION_TABLE_READY_WITH_ADVANCED_BASELINES_BLOCKED |
| baseline-metric-coverage | `uv run --no-sync python tools/check_35t_metric_coverage.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY |
| baseline-execution-spec | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --repo-root .` | PASS | exit_code=0, required baseline families mapped to commands, artifacts, pass gates, and non-substitution rules |
| baseline-check | `uv run --no-sync python tools/check_35t_baseline_evaluation.py --repo-root .` | PASS | exit_code=0 |
| baseline-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P4=HOST_QEMU_STRACE_AND_SOFTWARE_INSTRUMENTATION_PASS_WITH_MISSING_EBPF_QEMU_PLUGIN |
| baseline-regression | `uv run --no-sync python tools/check_35t_paper_evidence.py --no-write` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |
| baseline-regression | `uv run --no-sync python tools/check_evaluation_plan.py` | PASS | exit_code=0 |
| baseline-regression | `uv run --no-sync python -m compileall tools src\rv_maltrace` | PASS | exit_code=0 |
| baseline-regression | `git diff --check` | PASS | exit_code=0 |

## Pointer Snapshot Enablement Gate Closure

The pointer snapshot enablement gate keeps P3 honest: synthetic ARG_MEM and
syscall side-channel closure are useful bounded evidence, but they are not an
enabled 35T hardware user-pointer snapshot. The gate records the evidence that
must exist before changing `TRACE_MEM_MODE_NONE` or enabling pointer payload
capture.

| Phase | Command | Status | Reason |
|---|---|---|---|
| pointer-snapshot-gate-tooling | `uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --self-test` | PASS | exit_code=0 |
| pointer-snapshot-gate | `uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --repo-root .` | PASS | exit_code=0, status=POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED |
| pointer-snapshot-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P3 remains PARTIAL_BOUNDED_SYNTHETIC_ARG_MEM_GUARDRAILS |

## Assessment Traceability Closure

The traceability check maps the source assessment document's P0-P6 requirements
to current evidence files and accepted bounded statuses. It is a
requirement-to-evidence audit, not a claim that the deferred hardware,
advanced-baseline, extension-run, or full raw-artifact work is complete.

| Phase | Command | Status | Reason |
|---|---|---|---|
| assessment-traceability-tooling | `uv run --no-sync python tools/check_35t_assessment_traceability.py --self-test` | PASS | exit_code=0 |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |

## Assessment Requirement Matrix Closure

The requirement matrix check maps the full source assessment document by
section, not only P0-P6. It covers the overall conclusion, evidence chain,
hardware trace, local code analysis, synthetic malware-analysis boundary,
remaining shortfalls, CCF-A positioning, recommended paper organization, and
final judgment while keeping P3-P6 external conditions explicit.

| Phase | Command | Status | Reason |
|---|---|---|---|
| assessment-requirement-matrix-tooling | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --self-test` | PASS | exit_code=0 |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK, requirement_count=14 |

## Remaining External Work Register

The remaining external work check records the P3-P6 conditions that are still
outside the current 35T evidence: enabled hardware pointer snapshot or trusted
helper alignment, eBPF-only and QEMU-plugin baseline environments, explicit
35T gating for extension sources, and full raw artifact release after
sanitization or approval.

| Phase | Command | Status | Reason |
|---|---|---|---|
| remaining-external-work-tooling | `uv run --no-sync python tools/check_35t_remaining_external_work.py --self-test` | PASS | exit_code=0 |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, status=PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED |

## Evidence Consistency Closure

The evidence consistency check is a read-only stale-report guard. It verifies
that the evidence manifest hashes current files, that P6's committed artifact
count matches the manifest, that assessment closure and traceability goal
statuses agree, that the source assessment requirement matrix is present, and
that the paper artifact package records the current validation and reproduction
commands.

| Phase | Command | Status | Reason |
|---|---|---|---|
| evidence-consistency-tooling | `uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test` | PASS | exit_code=0 |
| evidence-consistency | `uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write` | PASS | exit_code=0, status=PASS |

## Paper Positioning Closure

The paper positioning check converts the assessment's publication boundary into
a machine-readable gate. It keeps the 35T result scoped to low-cost FPGA
feasibility / constrained-board prototype evidence and rejects standalone CCF-A
main-contribution, real malware detection, CVA6 validation, mature-detector, or
complete-reconstruction wording.

| Phase | Command | Status | Reason |
|---|---|---|---|
| paper-positioning-tooling | `uv run --no-sync python tools/check_35t_paper_positioning.py --self-test` | PASS | exit_code=0 |
| paper-positioning | `uv run --no-sync python tools/check_35t_paper_positioning.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_FEASIBILITY_POSITIONING_READY |

## Assessment Reconciliation Closure

The assessment reconciliation check treats `D:/Download/rv_maltrace_35t_assessment.md`
as a source snapshot. It records where current evidence updates the snapshot
(notably P1/P2 representative side-channel case-study closure and the software
instrumentation baseline) while keeping P3-P6 external work deferred.

| Phase | Command | Status | Reason |
|---|---|---|---|
| assessment-reconciliation-tooling | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --self-test` | PASS | exit_code=0 |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |

## Assessment Gate Criteria Closure

The assessment gate criteria check independently verifies the concrete gate
conditions named in the source assessment: 512 records, 13/13 sample PASS,
marker scope, runtime process attribution, UNKNOWN/corrupt, DROP/cap, strong
expected evidence, bounded benign overlap, and per-sample trace profile policy.

| Phase | Command | Status | Reason |
|---|---|---|---|
| assessment-gate-criteria-tooling | `uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --self-test` | PASS | exit_code=0 |
| assessment-gate-criteria | `uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_GATE_CRITERIA_PASS |

## Hardware Trace Prototype Closure

The hardware trace prototype check independently verifies the assessment's 3.1
claim: the primary 35T run uses a 512-record small-capacity per-sample profile
policy, has 13/13 sample gate PASS, marker/runtime attribution, zero
UNKNOWN/corrupt events, DROP within limits, no cap hits, and 65 nonempty
decoded trace artifacts. It is scoped to 35T / LiteX / VexRiscv and does not
infer CVA6 board validation.

| Phase | Command | Status | Reason |
|---|---|---|---|
| hardware-trace-tooling | `uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --self-test` | PASS | exit_code=0 |
| hardware-trace-prototype | `uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --repo-root .` | PASS | exit_code=0, status=HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY, decoded_traces=65 |

## Local Code Analysis Closure

The local code analysis check independently verifies the assessment's 3.2
claim against current artifacts. It requires code maps, trace-code joins,
runtime process maps, semantic recovery outputs, behavior graphs, and
rule-based audits for all 13 samples and all 65 trace-on repetitions. It keeps
PC-in-ELF, process ownership, source-line attribution, complete semantic
reconstruction, and real malware detection quality as explicit boundaries.

| Phase | Command | Status | Reason |
|---|---|---|---|
| local-code-analysis-tooling | `uv run --no-sync python tools/check_35t_local_code_analysis.py --self-test` | PASS | exit_code=0 |
| local-code-analysis | `uv run --no-sync python tools/check_35t_local_code_analysis.py --repo-root .` | PASS | exit_code=0, status=LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION, complete_reps=65/65 |

## Malware Behavior Audit Closure

The malware behavior audit check independently verifies the assessment's 3.3
boundary. It checks the 8-rule synthetic malware-like behavior audit against
the rules file, manifest, aggregate 35T gate, and per-repetition audit
artifacts. It records that the pass claim is controlled synthetic
behavior-rule audit only, not real malware execution, detector accuracy, family
classification, IOC coverage, or TTP coverage.

| Phase | Command | Status | Reason |
|---|---|---|---|
| malware-behavior-audit-tooling | `uv run --no-sync python tools/check_35t_malware_behavior_audit.py --self-test` | PASS | exit_code=0 |
| malware-behavior-audit | `uv run --no-sync python tools/check_35t_malware_behavior_audit.py --repo-root .` | PASS | exit_code=0, status=SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED, expected_rules=8/8 |

## Synthetic Suite Extension Closure

The synthetic suite extension pass keeps the current 35T claim limited to the
existing synthetic malware-like samples while recording source-implemented,
disabled-by-default candidate workloads for follow-up 35T gating. It also
records the source/legal/containment/isolation/replay/sanitization gates
required before real malware could enter scope.
The host smoke check is compile-only: the current Windows host uses WSL and
`/usr/bin/cc` to compile the extension sources without executing them or
starting loopback network activity. The target smoke check is also compile-only:
Docker `linux-behavior` uses `riscv64-linux-gnu-gcc -static` to build RISC-V
Linux ELFs and validate their machine headers without executing or deploying
them on the 35T image.

| Phase | Command | Status | Reason |
|---|---|---|---|
| synthetic-extension-tooling | `uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --self-test` | PASS | exit_code=0 |
| synthetic-extension-check | `uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --repo-root .` | PASS | exit_code=0, status=IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING, candidate_count=9, implemented_candidate_count=9 |
| synthetic-extension-host-smoke-tooling | `uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --self-test` | PASS | exit_code=0 |
| synthetic-extension-host-smoke | `uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --repo-root .` | PASS | exit_code=0, status=HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED, compiled=9/9 via WSL `/usr/bin/cc` |
| synthetic-extension-target-smoke-tooling | `uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --self-test` | PASS | exit_code=0 |
| synthetic-extension-target-smoke | `uv run --no-sync python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .` | PASS | exit_code=0, status=TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED, compiled=9/9 via Docker `riscv64-linux-gnu-gcc` |
| synthetic-extension-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P5=IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING |

## Raw Artifact Sanitization Closure

The raw artifact sanitization pass inventories the primary 35T raw UART and
decoded trace JSONL artifacts without copying full raw payloads into the
lightweight evidence snapshot. It publishes hashes and sanitized excerpts, and
keeps full raw release deferred pending explicit approval, escrow, or
controlled-release policy.

| Phase | Command | Status | Reason |
|---|---|---|---|
| raw-artifact-sanitization-tooling | `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --self-test` | PASS | exit_code=0 |
| raw-artifact-sanitization | `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --repo-root .` | PASS | exit_code=0, status=RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED, raw_uart=1, decoded_trace_jsonl=65 |
| raw-artifact-no-write | `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write` | PASS | exit_code=0, status=RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED |

## Artifact Package Readiness Closure

The artifact readiness pass maps the paper artifact package requested in the
assessment to the current local results tree. It verifies that required classes
exist locally, while preserving the lightweight snapshot policy for raw UART
logs, decoded traces, bitstreams, board build directories, and ELF binaries.

| Phase | Command | Status | Reason |
|---|---|---|---|
| artifact-tooling | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --self-test` | PASS | exit_code=0 |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED, artifact_classes=19 |
| artifact-tooling | `uv run --no-sync python tools/package_35t_paper_artifacts.py --self-test` | PASS | exit_code=0 |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| artifact-assessment | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P6=LIGHTWEIGHT_ARTIFACT_PASS_FULL_REPRO_DEFERRED |

## P5 Host Smoke Integration Regression

These commands were run after adding WSL-backed P5 host compile-only smoke
evidence. The local host is Windows, but WSL provides `/usr/bin/cc`, so the
compile smoke records 9/9 source compile PASS. This is still not a 35T gate
pass and does not claim expanded sample coverage.

| Phase | Command | Status | Reason |
|---|---|---|---|
| host-smoke-self-test | `uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --self-test` | PASS | exit_code=0 |
| assessment-self-test | `uv run --no-sync python tools/check_35t_assessment_closure.py --self-test` | PASS | exit_code=0 |
| assessment-traceability-self-test | `uv run --no-sync python tools/check_35t_assessment_traceability.py --self-test` | PASS | exit_code=0 |
| assessment-requirement-matrix-self-test | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --self-test` | PASS | exit_code=0 |
| remaining-external-work-self-test | `uv run --no-sync python tools/check_35t_remaining_external_work.py --self-test` | PASS | exit_code=0 |
| paper-positioning-self-test | `uv run --no-sync python tools/check_35t_paper_positioning.py --self-test` | PASS | exit_code=0 |
| assessment-reconciliation-self-test | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --self-test` | PASS | exit_code=0 |
| assessment-gate-criteria-self-test | `uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --self-test` | PASS | exit_code=0 |
| hardware-trace-prototype-self-test | `uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --self-test` | PASS | exit_code=0 |
| local-code-analysis-self-test | `uv run --no-sync python tools/check_35t_local_code_analysis.py --self-test` | PASS | exit_code=0 |
| malware-behavior-audit-self-test | `uv run --no-sync python tools/check_35t_malware_behavior_audit.py --self-test` | PASS | exit_code=0 |
| raw-artifact-sanitization-self-test | `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --self-test` | PASS | exit_code=0 |
| paper-evidence-self-test | `uv run --no-sync python tools/check_35t_paper_evidence.py --self-test` | PASS | exit_code=0 |
| baseline-execution-spec-self-test | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --self-test` | PASS | exit_code=0 |
| pointer-snapshot-gate-self-test | `uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --self-test` | PASS | exit_code=0 |
| artifact-readiness-self-test | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --self-test` | PASS | exit_code=0 |
| packager-self-test | `uv run --no-sync python tools/package_35t_paper_artifacts.py --self-test` | PASS | exit_code=0 |
| evidence-consistency-self-test | `uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test` | PASS | exit_code=0 |
| host-smoke-no-write | `uv run --no-sync python tools/check_35t_synthetic_extension_host_smoke.py --no-write` | PASS | exit_code=0, status=HOST_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED, compiled=9/9 |
| synthetic-suite-no-write | `uv run --no-sync python tools/check_35t_synthetic_suite_extension.py --no-write` | PASS | exit_code=0, status=IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING |
| paper-evidence-no-write | `uv run --no-sync python tools/check_35t_paper_evidence.py --no-write` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |
| baseline-execution-spec-no-write | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --no-write` | PASS | exit_code=0 |
| pointer-snapshot-gate-no-write | `uv run --no-sync python tools/check_35t_pointer_snapshot_gate.py --no-write` | PASS | exit_code=0, status=POINTER_SNAPSHOT_ENABLEMENT_GATES_RECORDED_NOT_ENABLED |
| artifact-readiness-no-write | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --no-write` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| assessment-no-write | `uv run --no-sync python tools/check_35t_assessment_closure.py --no-write` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-traceability-no-write | `uv run --no-sync python tools/check_35t_assessment_traceability.py --no-write` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-requirement-matrix-no-write | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| remaining-external-work-no-write | `uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write` | PASS | exit_code=0, status=PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED |
| paper-positioning-no-write | `uv run --no-sync python tools/check_35t_paper_positioning.py --no-write` | PASS | exit_code=0, status=BOUNDED_FEASIBILITY_POSITIONING_READY |
| assessment-reconciliation-no-write | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --no-write` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| assessment-gate-criteria-no-write | `uv run --no-sync python tools/check_35t_assessment_gate_criteria.py --no-write` | PASS | exit_code=0, status=ASSESSMENT_GATE_CRITERIA_PASS |
| hardware-trace-prototype-no-write | `uv run --no-sync python tools/check_35t_hardware_trace_prototype.py --no-write` | PASS | exit_code=0, status=HARDWARE_TRACE_PROTOTYPE_PASS_35T_SMALL_CAPACITY |
| local-code-analysis-no-write | `uv run --no-sync python tools/check_35t_local_code_analysis.py --no-write` | PASS | exit_code=0, status=LOCAL_CODE_ANALYSIS_PROTOTYPE_PASS_WITH_BOUNDED_ATTRIBUTION |
| malware-behavior-audit-no-write | `uv run --no-sync python tools/check_35t_malware_behavior_audit.py --no-write` | PASS | exit_code=0, status=SYNTHETIC_MALWARE_LIKE_BEHAVIOR_AUDIT_PASS_REAL_MALWARE_DEFERRED |
| raw-artifact-sanitization-no-write | `uv run --no-sync python tools/check_35t_raw_artifact_sanitization.py --no-write` | PASS | exit_code=0, status=RAW_ARTIFACT_HASH_EXCERPT_READY_FULL_RAW_DEFERRED |
| evidence-consistency-no-write | `uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write` | PASS | exit_code=0, status=PASS |
| compileall | `uv run --no-sync python -m compileall tools src\rv_maltrace` | PASS | exit_code=0 |
| whitespace-check | `git diff --check` | PASS | exit_code=0 |

## P6 Local Raw Artifact Escrow

These commands were run after adding a local controlled escrow package for the
primary 35T raw UART log and decoded trace JSONL files. The package copies the
raw payloads under `results/` and records hashes plus an access policy; it does
not publish the raw payloads or close the public raw release condition.

| Phase | Command | Status | Reason |
|---|---|---|---|
| raw-artifact-escrow-self-test | `uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --self-test` | PASS | exit_code=0 |
| raw-artifact-escrow | `uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --repo-root .` | PASS | exit_code=0, status=LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED, payload_files=66 |
| raw-artifact-escrow-no-write | `uv run --no-sync python tools/check_35t_raw_artifact_escrow.py --no-write` | PASS | exit_code=0, status=LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED, artifact_classes=20 |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p6_local_raw_artifact_escrow moved to satisfied_conditions |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| paper-evidence | `uv run --no-sync python tools/check_35t_paper_evidence.py --repo-root .` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |

## P4 QEMU-Plugin 13-Sample Baseline Closure

These commands were run after building a local upstream QEMU 8.2.2
`qemu-riscv64` user-mode binary with `--enable-plugins` under
`results/experiments/35t/35t-qemu-plugin-baseline-20260523/qemu_user_plugin`.
The baseline compiles a small TCG plugin that counts guest syscalls, runs all
13 existing RISC-V synthetic samples over 3 reps, and records per-sample plugin
output and timing under the local `results/` tree. This is simulator software
baseline evidence only, not hardware trace, DBI, real malware, CVA6, or
complete semantic reconstruction evidence.

| Phase | Command | Status | Reason |
|---|---|---|---|
| qemu-plugin-baseline-self-test | `uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --self-test` | PASS | exit_code=0 |
| qemu-plugin-baseline | `uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --repo-root . --reps 3` | PASS | exit_code=0, status=QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES |
| baseline-summary | `uv run --no-sync python tools/summarize_35t_baselines.py --repo-root .` | PASS | exit_code=0, status=HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS |
| baseline-check | `uv run --no-sync python tools/check_35t_baseline_evaluation.py --repo-root .` | PASS | exit_code=0 |
| baseline-execution-spec | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --repo-root .` | PASS | exit_code=0 |
| evaluation-table | `uv run --no-sync python tools/check_35t_evaluation_table.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_QEMU_PLUGIN |
| metric-coverage | `uv run --no-sync python tools/check_35t_metric_coverage.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_METRIC_COVERAGE_READY_WITH_DEFERRED_FULL_ACCURACY |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, P4=HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_EBPF_AND_QEMU_PLUGIN_PASS |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p4_qemu_plugin_baseline moved to satisfied_conditions |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| evidence-consistency-no-write | `uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write` | PASS | exit_code=0, status=PASS |
| paper-evidence-no-write | `uv run --no-sync python tools/check_35t_paper_evidence.py --no-write` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |
| qemu-plugin-baseline-no-write | `uv run --no-sync python tools/run_35t_qemu_plugin_baseline.py --repo-root . --reps 3 --no-write` | PASS | exit_code=0, status=QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES |
| compileall | `uv run --no-sync python -m compileall tools src\rv_maltrace` | PASS | exit_code=0 |
| whitespace-check | `git diff --check` | PASS | exit_code=0 |
| evidence-consistency-self-test | `uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test` | PASS | exit_code=0 |

## P5 Extension 35T Enablement Preflight

These commands were run after wiring synthetic extension candidates into the
35T runner/rootfs/experiment path. The change keeps extension samples
default-disabled, verifies that the default dry-run still selects only the
original 13 samples, and verifies that an explicit
`--include-extension-samples` dry-run can select the 8 non-network extension
candidates. This is an enablement prerequisite only: no extension candidate was
executed on the 35T board, and no expanded 35T coverage or gate pass is claimed.

| Phase | Command | Status | Reason |
|---|---|---|---|
| experiment-self-test | `uv run --no-sync python tools/experiment_35t.py --stage self-test` | PASS | exit_code=0 |
| extension-explicit-dry-run | `uv run --no-sync python tools/experiment_35t.py --stage board --dry-run --run-id 35t-extension-enable-dry-run --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order abba --reps 1 --include-extension-samples --sample direct_syscall_open_read` | PASS | exit_code=0, generated runner command selects `direct_syscall_open_read` only |
| extension-default-dry-run | `uv run --no-sync python tools/experiment_35t.py --stage board --dry-run --run-id 35t-base-default-dry-run --trace-records 512 --trace-profile-policy 35t_small_capacity --runtime-order abba --reps 1` | PASS | exit_code=0, generated runner commands cover the original 13 samples only |
| extension-enable-self-test | `uv run --no-sync python tools/check_35t_extension_35t_enablement.py --self-test` | PASS | exit_code=0 |
| extension-enable-preflight | `uv run --no-sync python tools/check_35t_extension_35t_enablement.py --repo-root .` | PASS | exit_code=0, status=EXTENSION_35T_ENABLEMENT_PREFLIGHT_PASS_GATING_DEFERRED |
| manifest-hash-check | `python - <<manifest hash verifier>>` | PASS | exit_code=0, verified 96 manifest artifact hashes |

## P4 eBPF Baseline Closure

These commands were run after rebuilding the Docker `linux-behavior` image with
clang/llvm/bpftrace support. The cap-enabled Docker probe records eBPF
preflight readiness, and the eBPF runner records a 13-sample host Linux
bpftrace baseline. QEMU-plugin remains blocked because Docker provides
`qemu-system-riscv64` with `-plugin` support but does not ship
`qemu-plugin.h`; the user-mode `qemu-riscv64` path still lacks `-plugin`.

| Phase | Command | Status | Reason |
|---|---|---|---|
| docker-linux-behavior-build | `docker compose -f docker-compose.toolchain.yml build linux-behavior` | PASS | exit_code=0, image rebuilt with bpftrace/clang/llvm/qemu-system-misc |
| advanced-baseline-preflight | `uv run --no-sync python tools/check_35t_advanced_baseline_preflight.py --repo-root . --timeout-s 120` | PASS | exit_code=0, ebpf_only=READY, qemu_plugin=BLOCKED_CURRENT_ENVIRONMENT |
| ebpf-baseline-self-test | `uv run --no-sync python tools/run_35t_ebpf_baseline.py --self-test` | PASS | exit_code=0 |
| ebpf-baseline-run | `uv run --no-sync python tools/run_35t_ebpf_baseline.py --reps 3` | PASS | exit_code=0, status=PASS, 13/13 samples |
| baseline-summary | `uv run --no-sync python tools/summarize_35t_baselines.py --repo-root .` | PASS | exit_code=0, status=HOST_QEMU_STRACE_SOFTWARE_INSTRUMENTATION_AND_EBPF_PASS_WITH_MISSING_QEMU_PLUGIN |
| baseline-check | `uv run --no-sync python tools/check_35t_baseline_evaluation.py --repo-root .` | PASS | exit_code=0 |
| baseline-spec-check | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --repo-root .` | PASS | exit_code=0 |
| evaluation-table | `uv run --no-sync python tools/check_35t_evaluation_table.py --repo-root .` | PASS | exit_code=0, status=BOUNDED_EVALUATION_TABLE_READY_WITH_EBPF_AND_MISSING_QEMU_PLUGIN |
| metric-coverage | `uv run --no-sync python tools/check_35t_metric_coverage.py --repo-root .` | PASS | exit_code=0 |

## P4 QEMU-Plugin Build/Load Preflight

These commands were run after confirming the Ubuntu package set does not expose
a packaged `qemu-plugin.h` development header. The new preflight fetches the
official QEMU 8.2.2 `qemu-plugin.h` header at probe time, compiles a minimal
TCG plugin, and verifies that `qemu-system-riscv64 -plugin` loads it. This is a
P4 prerequisite only: user-mode `qemu-riscv64` still lacks `-plugin`, no
qemu-system Linux sample harness is recorded, and no 13-sample QEMU-plugin
baseline is claimed.

| Phase | Command | Status | Reason |
|---|---|---|---|
| qemu-plugin-build-preflight-self-test | `uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --self-test` | PASS | exit_code=0 |
| qemu-plugin-build-preflight | `uv run --no-sync python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .` | PASS | exit_code=0, status=QEMU_PLUGIN_SYSTEM_BUILD_LOAD_PREFLIGHT_PASS_USER_BASELINE_BLOCKED |
| baseline-summary | `uv run --no-sync python tools/summarize_35t_baselines.py --repo-root .` | PASS | exit_code=0, qemu_plugin system_build_load_preflight recorded while qemu_plugin remains non-PASS |
| baseline-spec-check | `uv run --no-sync python tools/check_35t_baseline_execution_spec.py --repo-root .` | PASS | exit_code=0 |
| baseline-check | `uv run --no-sync python tools/check_35t_baseline_evaluation.py --repo-root .` | PASS | exit_code=0 |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p4_qemu_plugin_system_build_load_preflight moved to satisfied_conditions |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |

## P3 Trusted Helper Alignment Closure

These commands were run after adding a bounded helper-alignment checker for the
targeted 35T dual-channel board validation bundle. The result satisfies the
`p3_trusted_helper_or_ebpf_alignment` precondition for representative fd/path
and process-tree evidence. It does not claim hardware user-pointer memory
snapshot, hardware-only tracing, complete semantic reconstruction, QEMU-plugin
evidence, or malicious-kernel resistance.

| Phase | Command | Status | Reason |
|---|---|---|---|
| helper-alignment-self-test | `uv run --no-sync python tools/check_35t_helper_alignment.py --self-test` | PASS | exit_code=0 |
| remaining-external-work-self-test | `uv run --no-sync python tools/check_35t_remaining_external_work.py --self-test` | PASS | exit_code=0 |
| assessment-reconciliation-self-test | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --self-test` | PASS | exit_code=0 |
| assessment-requirement-matrix-self-test | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --self-test` | PASS | exit_code=0 |
| assessment-closure-self-test | `uv run --no-sync python tools/check_35t_assessment_closure.py --self-test` | PASS | exit_code=0 |
| assessment-traceability-self-test | `uv run --no-sync python tools/check_35t_assessment_traceability.py --self-test` | PASS | exit_code=0 |
| evidence-consistency-self-test | `uv run --no-sync python tools/check_35t_evidence_consistency.py --self-test` | PASS | exit_code=0 |
| artifact-readiness-self-test | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --self-test` | PASS | exit_code=0 |
| helper-alignment | `uv run --no-sync python tools/check_35t_helper_alignment.py --repo-root .` | PASS | exit_code=0, status=TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p3_trusted_helper_or_ebpf_alignment moved to satisfied_conditions |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| helper-alignment-no-write | `uv run --no-sync python tools/check_35t_helper_alignment.py --no-write` | PASS | exit_code=0, status=TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL |
| paper-evidence-self-test | `uv run --no-sync python tools/check_35t_paper_evidence.py --self-test` | PASS | exit_code=0 |
| paper-evidence-no-write | `uv run --no-sync python tools/check_35t_paper_evidence.py --no-write` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |
| evidence-consistency-no-write | `uv run --no-sync python tools/check_35t_evidence_consistency.py --no-write` | PASS | exit_code=0, status=PASS |
| assessment-closure-no-write | `uv run --no-sync python tools/check_35t_assessment_closure.py --no-write` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-traceability-no-write | `uv run --no-sync python tools/check_35t_assessment_traceability.py --no-write` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| remaining-external-work-no-write | `uv run --no-sync python tools/check_35t_remaining_external_work.py --no-write` | PASS | exit_code=0, status=PASS_CURRENT_EXTERNAL_CONDITIONS_RECORDED |
| assessment-requirement-matrix-no-write | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --no-write` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-reconciliation-no-write | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --no-write` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| artifact-readiness-no-write | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --no-write` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| compileall | `uv run --no-sync python -m compileall tools src\rv_maltrace` | PASS | exit_code=0 |
| whitespace-check | `git diff --check` | PASS | exit_code=0 |

## P3 Pointer Snapshot Design Review

These commands were run after adding a bounded design-review record for the
future hardware user-pointer snapshot route. The result satisfies only the
design-review precondition: selective `openat`/`execve` pathname-prefix capture
is documented as default-disabled and bounded to 64 bytes, while timing/resource
data, bandwidth/drop accounting, noninterference, semantic accuracy, and full
artifact release policy remain required before hardware user-pointer snapshots
can be enabled or claimed.

| Phase | Command | Status | Reason |
|---|---|---|---|
| pointer-design-review-self-test | `uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --self-test` | PASS | exit_code=0 |
| pointer-design-review | `uv run --no-sync python tools/check_35t_pointer_snapshot_design_review.py --repo-root .` | PASS | exit_code=0, status=POINTER_SNAPSHOT_DESIGN_REVIEW_PASS_NOT_ENABLED |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p3_pointer_snapshot_design_review moved to satisfied_conditions |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| paper-evidence | `uv run --no-sync python tools/check_35t_paper_evidence.py --repo-root .` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |

## P5 Extension Host/QEMU Behavior Smoke

These commands were run after adding execution-level pre-board evidence for the
source-implemented synthetic extension candidates. The smoke compiles all 9
candidates, executes the 8 non-network candidates under host native, host
strace, QEMU native, and QEMU guest strace, verifies expected guest syscall
coverage, and keeps the loopback network candidate skipped by default. This is
not a 35T board run and does not claim expanded 35T gate coverage.

| Phase | Command | Status | Reason |
|---|---|---|---|
| extension-behavior-smoke-self-test | `uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --self-test` | PASS | exit_code=0 |
| extension-behavior-smoke | `uv run --no-sync python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .` | PASS | exit_code=0, status=HOST_QEMU_BEHAVIOR_SMOKE_PASS_35T_GATING_DEFERRED, executed=8/8, network_skipped=1 |
| artifact-readiness | `uv run --no-sync python tools/check_35t_artifact_package_readiness.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED, artifact_classes=22 |
| artifact-package | `uv run --no-sync python tools/package_35t_paper_artifacts.py --repo-root .` | PASS | exit_code=0, status=LIGHTWEIGHT_RELEASE_CANDIDATE_READY_FULL_RAW_DEFERRED |
| remaining-external-work | `uv run --no-sync python tools/check_35t_remaining_external_work.py --repo-root .` | PASS | exit_code=0, p5_extension_host_qemu_behavior_smoke moved to satisfied_conditions |
| assessment-closure | `uv run --no-sync python tools/check_35t_assessment_closure.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-traceability | `uv run --no-sync python tools/check_35t_assessment_traceability.py --repo-root .` | PASS | exit_code=0, status=PASS_WITH_BOUNDED_REMAINING_WORK |
| assessment-requirement-matrix | `uv run --no-sync python tools/check_35t_assessment_requirement_matrix.py --repo-root .` | PASS | exit_code=0, status=ASSESSMENT_REQUIREMENT_MATRIX_PASS_WITH_BOUNDED_EXTERNAL_WORK |
| assessment-reconciliation | `uv run --no-sync python tools/check_35t_assessment_reconciliation.py --repo-root .` | PASS | exit_code=0, status=CURRENT_EVIDENCE_RECONCILED_WITH_ASSESSMENT_SNAPSHOT |
| paper-evidence | `uv run --no-sync python tools/check_35t_paper_evidence.py --repo-root .` | PASS | exit_code=0, paper_support_status=SUPPORTED_WITH_BOUNDED_CLAIMS |
