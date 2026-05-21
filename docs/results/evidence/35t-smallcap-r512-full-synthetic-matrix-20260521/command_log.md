# 35T Command Log: 35t-smallcap-r512-full-synthetic-matrix-20260521

Generated UTC: 2026-05-21T21:27:56+00:00

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
| P3 | `uv run python tools/recover_fd_path_flow.py --sample file_scan --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521` | PASS | exit_code=0 |
| P4 | `uv run python tools/recover_process_tree.py --self-test` | PASS | exit_code=0 |
| P4 | `uv run python tools/recover_process_tree.py --sample process_chain --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521` | PASS | exit_code=0 |
| readiness | `uv run python tools/summarize_35t_explanation_readiness.py --self-test` | PASS | exit_code=0 |
| readiness | `uv run python tools/summarize_35t_explanation_readiness.py --repo-root .` | PASS | exit_code=0 |
| source-attribution | `uv run python tools/summarize_35t_source_attribution.py --self-test` | PASS | exit_code=0 |
| source-attribution | `uv run python tools/summarize_35t_source_attribution.py --repo-root .` | PASS | exit_code=0, status=PARTIAL |
| board-validation | `uv run python tools/check_35t_board_validation.py --self-test` | PASS | exit_code=0 |
| board-validation | `uv run python tools/check_35t_board_validation.py --repo-root .` | PASS | exit_code=0, status=AWAITING_BOARD_RUN |
| board-validation-negative | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521 --require-results` | FAIL | exit_code=1, expected negative check: current snapshot is not a board-validation result bundle because fd/path and process tree remain PARTIAL |
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
| actual-board-run | `uv run python tools/check_35t_next_gate.py --run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, gate claim_level=full_matrix_ready, samples=13/13 PASS |
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
| actual-board-run-sidechannel | `uv run python tools/check_35t_next_gate.py --run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, samples=13/13 PASS, trace_records=512, trace_profile_policy=35t_small_capacity |
| actual-board-run-sidechannel | `uv run python tools/package_35t_board_validation.py --repo-root . --source-results-root results/experiments/35t/35t-targeted-board-validation-20260522 --out-dir results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle` | PASS | exit_code=0, status=PASS |
| actual-board-run-sidechannel | `uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results` | PASS | exit_code=0, hardware_validated=true; fd/path PASS, process-tree PASS, source-attribution PARTIAL |
| actual-board-run-sidechannel | `uv run python tools/summarize_35t_board_validation_attempt.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522` | PASS | exit_code=0, status=BOARD_VALIDATION_PASS |
| final | `uv run python tools/check_35t_application_closure.py --repo-root .` | PASS | exit_code=0 |
| final | `uv run python -m compileall tools src/rv_maltrace` | PASS | exit_code=0 |
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

### `uv run python tools/recover_fd_path_flow.py --sample file_scan --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521`

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

### `uv run python tools/recover_process_tree.py --sample process_chain --semantic-events results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/behavior_recovery/semantic_events.json --out-dir docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521`

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

### `uv run python tools/check_35t_board_validation.py --repo-root . --results-root docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521 --require-results`

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

Result: `full_matrix_ready`, 13/13 sample status PASS.

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
