# Linux Behavior Audit

Phase 6.5 defines the rule-based synthetic behavior audit that consumes
recovered semantic artifacts. The current Genesys2/CVA6 package contains
controlled safe-surrogate audit artifacts and per-sample case-study summaries.
This is still not real-malware validation or malware detection quality
evidence.

The audit rule specification is:

```text
experiments/linux_behavior/behavior_audit_rules.json
```

Audit consumes:

```text
semantic_events.json
behavior_graph.json
```

Audit emits:

```text
behavior_audit.json
behavior_audit_report.md
```

`tools/audit_behavior.py` reads the rule specification, recovered syscall,
trap, context semantics, and the behavior graph summary. It maps those artifacts
to general malware-like behavior families listed in
`experiments/linux_behavior/malware_like/manifest.json`. It does not inspect
RV-MalTrace packets, fixed PCs, trace markers, MMIO, or circuit-only state.

## Rules

| Order | Rule | Behavior family | Required evidence | Status |
| ---: | --- | --- | --- | --- |
| 1 | many_file_scan | file_discovery | `openat`, `getdents64`, `close` syscall shape | PASS_CONTROLLED_CASE_STUDY |
| 2 | batch_file_read_write | collection_staging | `openat`, `read`, `write`, `close` syscall shape | PASS_CONTROLLED_CASE_STUDY |
| 3 | self_copy_simulation | dropper_like | at least two `openat` events plus `read`, `write`, `close` | PASS_CONTROLLED_CASE_STUDY |
| 4 | abnormal_syscall_sequence | abnormal_sequence | invalid descriptor or path failure on `close`, `openat`, `read`, or `write` | PASS_CONTROLLED_CASE_STUDY |
| 5 | illegal_instruction_trap | trap_behavior | illegal-instruction trap context plus handler-visible `write` | PASS_CONTROLLED_CASE_STUDY |
| 6 | process_creation_chain | process_chain | `clone`, `execve`, `waitid` syscall shape | PASS_CONTROLLED_CASE_STUDY |
| 7 | dynamic_executable_memory | memory_permission | `mmap` followed by `mprotect` with `PROT_EXEC` set | PASS_CONTROLLED_CASE_STUDY |
| 8 | anti_analysis_indicator | anti_analysis | `ptrace` or timing-oriented syscall indicator | PASS_CONTROLLED_CASE_STUDY |

The audit result is manually reviewable triage over synthetic workloads. It must
not be used to claim malware detection quality, classifier accuracy, real
malware coverage, or hardware/Linux execution success without the corresponding
Phase 5 and Phase 6 evidence artifacts.

## Validation Command

Run this gate after editing the audit rules or tooling:

```powershell
uv run python tools/audit_behavior.py --self-test
uv run python tools/audit_behavior.py --semantic build/behavior_recovery_smoke/semantic_events.json --graph build/behavior_recovery_smoke/behavior_graph.json --manifest experiments/linux_behavior/malware_like/manifest.json --sample-id illegal_trap --out-dir build/behavior_audit_smoke
uv run python tools/check_linux_behavior_audit.py
uv run python tools/check_behavior_audit_metrics.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
```
