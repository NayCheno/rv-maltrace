# Fuzz Trace Validation

Phase 8 defines bounded fuzz/stress inputs for RV-MalTrace trace validation.
This is a deterministic trace-invariant gate, not a processor fuzzing campaign
or CVA6 bug-discovery claim.

The invariant specification is:

```text
sim/golden/fuzz_invariants.json
```

The seed generator is:

```text
tools/gen_rv_trace_fuzz.py
```

The trace checker is:

```text
tools/check_fuzz_trace.py
```

When `--out-dir` is provided, the checker writes:

```text
fuzz_trace_invariants.json
fuzz_trace_report.md
```

## Cases

| Order | Case | Stress focus | Required invariant families | Status |
| ---: | --- | --- | --- | --- |
| 1 | fuzz_cf | branch, jump, JALR, and alignment stress | known events, aligned control-flow targets, drop accounting | TODO(SIM) |
| 2 | fuzz_trap | illegal instruction and breakpoint trap shape | trap not normal retire, allowed trap causes, drop accounting | TODO(SIM) |
| 3 | fuzz_syscall | syscall entry/return argument and id shape | U-mode entry, monotonic ids, paired returns; generated seed is shape-only until a U-mode/SRET harness exists | TODO(HARNESS) |
| 4 | fuzz_context | SATP and watched-CSR context event shape | context event payloads and drop accounting | TODO(SIM) |
| 5 | fuzz_overflow | high event burst and queue overflow pressure | branch evidence, visible `DROP`, and monotonic drop count | TODO(SIM) |

The first implementation uses deterministic seed programs so failures remain
reproducible and easy to triage. Later RISCV-DV integration may feed additional
programs into the same invariant checker, but processor bug discovery is not the
two-week objective.

## Validation Command

```powershell
uv run python tools/gen_rv_trace_fuzz.py --self-test
uv run python tools/gen_rv_trace_fuzz.py --out-dir build/fuzz_trace_seeds
uv run python tools/check_fuzz_trace.py --self-test
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke --out-dir build/fuzz_trace_smoke
uv run python tools/check_fuzz_trace_plan.py
```
