# Linux Behavior Recovery Targets

Phase 6.4 defines the behavior recovery targets for Linux experiments. This is
a target specification and tooling plan, not board or Linux experiment evidence.

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

## Targets

| Order | Target | Source events | Output artifact path | Status |
| ---: | --- | --- | --- | --- |
| 1 | syscall_sequence | `SYSCALL_ENTRY`, `SYSCALL_RET` | `semantic_events.syscall_sequence` | TODO(EXPERIMENT) |
| 2 | control_flow_segment | `BRANCH`, `JUMP` | `semantic_events.control_flow_segments` | TODO(EXPERIMENT) |
| 3 | trap_context_transition | `TRAP`, `CSR`, `SATP`, `PRIV` | `semantic_events.trap_context_transitions` | TODO(EXPERIMENT) |
| 4 | privilege_boundary | `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `PRIV` | `semantic_events.privilege_boundaries` | TODO(EXPERIMENT) |
| 5 | basic_behavior_graph | `SYSCALL_ENTRY`, `SYSCALL_RET`, `BRANCH`, `JUMP`, `TRAP`, `CSR`, `SATP`, `PRIV` | `behavior_graph` | TODO(EXPERIMENT) |

`tools/recover_behavior.py` is the first offline recovery prototype. It reads a
trace JSONL file and writes the three output artifacts into a selected output
directory.

The `syscall_sequence` target requires paired return semantics in addition to
the entry arguments: `return_value`, `return_pc`, and `duration` must be present
when a `SYSCALL_RET` record is available.

The recovery target remains trace semantic recovery only. It must not be used
to claim malware detection quality, dataset completeness, or hardware experiment
success without concrete Phase 5 and Phase 6 evidence artifacts.
