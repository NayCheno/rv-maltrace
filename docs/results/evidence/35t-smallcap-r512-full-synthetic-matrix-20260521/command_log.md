# 35T Command Log: 35t-smallcap-r512-full-synthetic-matrix-20260521

Generated UTC: 2026-05-21T18:42:29+00:00

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
