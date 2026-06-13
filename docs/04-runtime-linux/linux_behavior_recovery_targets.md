# Linux Behavior Recovery Targets

Phase 6.4 defines the behavior recovery targets for Linux experiments. The
current Genesys2/CVA6 package now contains controlled P0 and safe-surrogate
case-study evidence for these recovery targets. The evidence is scoped to the
current repository-authored workloads and must not be read as real-malware
validation or general malware detection accuracy.

The target specification is:

```text
experiments/linux_behavior/recovery_targets.json
```

Recovery consumes:

```text
trace.jsonl
```

Recovery emits:

```text
semantic_events.json
behavior_graph.json
recovery_report.md
```

Current reviewed case-study packaging additionally emits
`case_study_summary.json` under:

```text
results/evaluation/genesys2-cva6/current/samples/<sample>/
results/evaluation/genesys2-cva6/current/case_study_manifest.json
```

## Targets

| Order | Target | Source events | Output artifact path | Status |
| ---: | --- | --- | --- | --- |
| 1 | syscall_sequence | `SYSCALL_ENTRY`, `SYSCALL_RET` | `semantic_events.syscall_sequence` | PASS_CONTROLLED_CASE_STUDY |
| 2 | control_flow_segment | `BRANCH`, `JUMP` | `semantic_events.control_flow_segments` and `behavior_graph` control edges where present | PASS_SCOPE_LIMITED_CASE_STUDY |
| 3 | trap_context_transition | `TRAP`, `CSR`, `SATP`, `PRIV` | `semantic_events.trap_context_transitions` | PASS_SCOPED_ILLEGAL_TRAP_CASE |
| 4 | privilege_boundary | `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `PRIV` | `semantic_events.privilege_boundaries` | PASS_SCOPED_SYSCALL_TRAP_BOUNDARY |
| 5 | basic_behavior_graph | `SYSCALL_ENTRY`, `SYSCALL_RET`, `BRANCH`, `JUMP`, `TRAP`, `CSR`, `SATP`, `PRIV` | `behavior_graph` | PASS_CONTROLLED_CASE_STUDY |

`tools/recover_behavior.py` is the first offline recovery prototype. It reads a
trace JSONL file and writes the three output artifacts into a selected output
directory.

The `syscall_sequence` target requires paired return semantics in addition to
the entry arguments: `return_value`, `return_pc`, and `duration` must be present
when a `SYSCALL_RET` record is available.

The recovery target remains trace semantic recovery only. It must not be used
to claim malware detection quality, dataset completeness, or hardware experiment
success without concrete Phase 5 and Phase 6 evidence artifacts.

Current validation:

```powershell
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
uv run python tools/run_check_suite.py --suite genesys2-current
```
