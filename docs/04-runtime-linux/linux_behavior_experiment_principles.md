# Linux Behavior Experiment Principles

Phase 6.1 defines the safety and validation rules for Linux behavior
experiments. The current Genesys2/CVA6 package now has controlled P0,
safe-surrogate, and local benign-control evidence, plus per-sample case-study
summaries. This evidence remains scoped to repository-authored controlled
workloads; it is not real-malware validation or malware detection accuracy
evidence.

The policy file is:

```text
experiments/linux_behavior/policy.json
```

Historical board and Linux experiment run directories use:

```text
results/linux_behavior/<run-id>/
```

The current reviewed evidence package is under:

```text
results/evaluation/genesys2-cva6/current/
results/evaluation/genesys2-cva6/current/case_study_manifest.json
```

## Safety Rules

| Rule | Requirement | Status |
| --- | --- | --- |
| Real malware | Do not run real malware in the current artifact. Keep real-malware work behind a separate containment/review gate. | PASS_POLICY_NONCLAIM |
| Sample provenance | Reject unknown-provenance binaries and payloads; use only repository-authored or source-controlled workloads. | PASS_REPOSITORY_AUTHORED_SAMPLES |
| Allowed samples | Use benign programs, P0 controlled programs, and malware-like safe-surrogate programs only. | PASS_BENIGN_AND_SAFE_SURROGATE_ONLY |
| Network access | Keep network behavior disabled by default; enable only for a planned small client test. | PASS_DEFAULT_DISABLED |
| Hardware gate | Use Phase 6 claims only when linked to the current controlled Genesys2/CVA6 trace package and checkers. | PASS_CURRENT_CONTROLLED_GATE |

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

Current case-study sample directories additionally contain:

- `case_study_summary.json`: reviewer-facing summary for current P0 and
  safe-surrogate samples.

Phase 6 datasets must stay split into `benign` and `malware_like_synthetic`.
They must not include real malware, repackaged malware, unknown binaries, or
payloads intended to evade or damage the host.

Current validation:

```powershell
uv run python tools/check_real_malware_containment.py --root .
uv run python tools/check_benign_control_summary.py --root .
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
uv run python tools/run_check_suite.py --suite genesys2-current
```
