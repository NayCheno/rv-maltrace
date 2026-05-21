# 35T Command Log: 35t-smallcap-r512-full-synthetic-matrix-20260521

Generated UTC: 2026-05-21T17:13:01+00:00

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
| final | `uv run python tools/check_35t_application_closure.py --repo-root .` | PASS | exit_code=0 |
| final | `uv run python -m compileall tools src/rv_maltrace` | PASS | exit_code=0 |

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
