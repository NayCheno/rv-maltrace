# Lightweight Trace Analysis

Phase 9.1 defines the selective committed semantic trace analysis gate. The
current package has simulation coverage for the board-minimal profile and
scoped Genesys2/CVA6 evidence for the semantic MVP event families through
ARG_MEM pointer-prefix, drop-accounting, trace-export, and case-study gates.
This is not runtime overhead evidence, trace-enabled FPGA bandwidth evidence,
or malware detection evidence.

The profile specification is:

```text
experiments/analysis/lightweight_trace_profile.json
```

The analysis tool is:

```text
tools/analyze_trace_lightweight.py
```

## Profiles

| Order | Profile | Behavior events | Accounting events | Forbidden behavior events | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | board_minimal | `BRANCH`, `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `CSR`, `SATP`, `PRIV` | `DROP` | `RETIRE`, `JUMP`, `MARKER`, `ARG_MEM` | CHECKED(SIM) |
| 2 | semantic_mvp | `BRANCH`, `JUMP`, `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `CSR`, `SATP`, `PRIV`, `ARG_MEM` | `DROP` | `MARKER` | PASS_SCOPED_GENESYS2_CURRENT |

## Gate Scope

The gate checks compact JSONL roundtrip, event-family counts, drop accounting,
and whether a trace matches the selected event profile. It keeps full
instruction trace and full memory trace out of the default lightweight claim.
The current `semantic_mvp` status is scoped to existing Genesys2/CVA6 summaries
and checkers; it is not a claim that every raw board trace is marker-free or
that production streaming bandwidth has been measured.

It must not be used to claim runtime overhead, trace-enabled FPGA bandwidth,
trace-enabled routed resource cost, or detection quality without separate
paired-run, implementation, and experiment artifacts.

## Validation Command

```powershell
uv run python tools/analyze_trace_lightweight.py --self-test
uv run python tools/analyze_trace_lightweight.py --trace results/vivado_sim/board_minimal/trace.jsonl --profile board_minimal --out-dir build/lightweight_trace_smoke
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
uv run python tools/check_hardware_pointer_prefixes.py --root .
uv run python tools/check_trace_export_decision.py --root .
uv run python tools/check_ccfa_case_study_manifest.py --root .
uv run python tools/check_lightweight_trace_analysis.py
uv run python tools/check_lightweight_trace_analysis.py --self-test
```
