# Lightweight Trace Analysis

Phase 9.1 defines the selective committed semantic trace analysis gate. This is
an event selectivity and compact-trace-volume gate, not runtime overhead
evidence, trace-enabled FPGA bandwidth evidence, or malware detection evidence.

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
| 2 | semantic_mvp | `BRANCH`, `JUMP`, `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `CSR`, `SATP`, `PRIV`, `ARG_MEM` | `DROP` | `MARKER` | TODO(EXPERIMENT) |

## Gate Scope

The gate checks compact JSONL roundtrip, event-family counts, drop accounting,
and whether a trace matches the selected event profile. It keeps full
instruction trace and full memory trace out of the default lightweight claim.

It must not be used to claim runtime overhead, trace-enabled FPGA bandwidth,
trace-enabled routed resource cost, or detection quality without separate
paired-run, implementation, and experiment artifacts.

## Validation Command

```powershell
uv run python tools/analyze_trace_lightweight.py --self-test
uv run python tools/analyze_trace_lightweight.py --trace results/vivado_sim/board_minimal/trace.jsonl --profile board_minimal --out-dir build/lightweight_trace_smoke
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
uv run python tools/check_lightweight_trace_analysis.py
uv run python tools/check_lightweight_trace_analysis.py --self-test
```
