# Linux Behavior Experiment Principles

Phase 6.1 defines the safety and validation rules for the first Linux
behavior experiments. These rules are a plan, not board or Linux experiment
evidence.

The policy file is:

```text
experiments/linux_behavior/policy.json
```

Board and Linux experiment evidence must be captured under:

```text
results/linux_behavior/<run-id>/
```

## Safety Rules

| Rule | Requirement | Status |
| --- | --- | --- |
| Real malware | Do not run real malware in early experiments. | TODO(EXPERIMENT) |
| Sample provenance | Reject unknown-provenance binaries and payloads. | TODO(EXPERIMENT) |
| Allowed samples | Use only benign programs and malware-like synthetic programs. | TODO(EXPERIMENT) |
| Network access | Keep network behavior disabled by default; enable only for a planned small client test. | TODO(EXPERIMENT) |
| Hardware gate | Do not use Phase 6 results as evidence until the Phase 5 trace-enabled board gate has concrete artifacts. | TODO(EXPERIMENT) |

## Validation Focus

The first experiments prioritize trace semantic recovery instead of malware
detection quality. A run is useful only if it can recover:

- syscall sequence
- control-flow segment
- trap/context transition
- privilege boundary
- basic behavior graph

Each run directory must contain:

- `trace.jsonl`: exported committed behavior trace.
- `semantic_events.json`: decoded syscall/trap/context/control-flow events.
- `behavior_graph.json`: minimal graph derived from recovered behavior.
- `recovery_report.md`: operator notes and comparison against the expected behavior.

Phase 6 datasets must stay split into `benign` and `malware_like_synthetic`.
They must not include real malware, repackaged malware, unknown binaries, or
payloads intended to evade or damage the host.
