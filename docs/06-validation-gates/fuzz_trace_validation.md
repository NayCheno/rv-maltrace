# Fuzz Trace Validation

Phase 8 defines bounded fuzz/stress inputs for RV-MalTrace trace validation.
This is a deterministic trace-invariant gate, not a processor fuzzing campaign
or CVA6 bug-discovery claim.

Current status:

```text
PASS_GOLDEN_TRACE_FIXTURES_WITH_SYSCALL_EVIDENCE
```

The checked golden JSONL fixtures exercise the invariant families below. The
deterministic seed assembly is still not treated as executed processor
evidence. For `fuzz_syscall`, the golden fixture is checked directly and the
syscall entry/return harness semantics are tied to existing trace-unit and RVFI
adapter syscall evidence:

```text
results/vivado_sim/summary.json
docs/07-evaluation-evidence/reports/sim_results.md
syscall_ret
rvfi_adapter
```

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
dual_commit_order
```

When `--out-dir` is provided, the checker writes:

```text
fuzz_trace_invariants.json
fuzz_trace_report.md
```

## Cases

| Order | Case | Stress focus | Required invariant families | Status |
| ---: | --- | --- | --- | --- |
| 1 | fuzz_cf | branch, jump, JALR, and alignment stress | known events, aligned control-flow targets, drop accounting | PASS_GOLDEN_TRACE_FIXTURE |
| 2 | fuzz_trap | illegal instruction and breakpoint trap shape | trap not normal retire, allowed trap causes, drop accounting | PASS_GOLDEN_TRACE_FIXTURE |
| 3 | fuzz_syscall | syscall entry/return argument and id shape | U-mode entry, monotonic ids, paired returns; existing trace-unit and RVFI adapter syscall evidence | PASS_GOLDEN_TRACE_FIXTURE_WITH_SYSCALL_EVIDENCE |
| 4 | fuzz_context | SATP and watched-CSR context event shape | context event payloads and drop accounting | PASS_GOLDEN_TRACE_FIXTURE |
| 5 | fuzz_overflow | high event burst and queue overflow pressure | branch evidence, visible `DROP`, and monotonic drop count | PASS_GOLDEN_TRACE_FIXTURE |

The checker also includes `dual_commit_order`, which requires explicit
`commit_port` ordering whenever a fixture contains multiple `RETIRE` events in
the same cycle. Existing fixtures without dual-retire cycles are not promoted
to dual-commit evidence.

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
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_cf.trace.jsonl --case fuzz_cf --out-dir build/fuzz_trace_cf
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_trap.trace.jsonl --case fuzz_trap --out-dir build/fuzz_trace_trap
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_syscall.trace.jsonl --case fuzz_syscall --out-dir build/fuzz_trace_syscall
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_context.trace.jsonl --case fuzz_context --out-dir build/fuzz_trace_context
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_overflow.trace.jsonl --case fuzz_overflow --out-dir build/fuzz_trace_overflow
uv run python tools/check_fuzz_trace_plan.py
```
