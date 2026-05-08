# Vivado Simulation Results

This document is the running record for MVP simulation evidence.

## Summary

| Test | Status | Retire | Branch | Jump | Ecall | Trap | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `smoke` | PASS | 2 | 0 | 0 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `branch` | PASS | 1 | 1 | 0 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `jump` | PASS | 2 | 0 | 2 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `ecall` | PASS | 0 | 0 | 0 | 1 | 1 | Confirms same-cycle ECALL/TRAP emission. |
| `trap_illegal` | PASS | 0 | 0 | 0 | 0 | 1 | Trace unit xsim and JSONL checker passed. |
| `ebreak` | PASS | 0 | 0 | 0 | 0 | 1 | Trace unit xsim and JSONL checker passed. |
| `csr` | PASS | 1 | 0 | 0 | 0 | 0 | SATP event checked by JSONL golden. |
| `context` | PASS | 2 | 0 | 0 | 0 | 0 | PRIV event checked by JSONL golden. |
| `backpressure` | PASS | 0 | 0 | 0 | 8 | 14 | Queue overflow/drop-mode unit test produced 7 DROP events. |
| `rvfi_adapter` | PASS | 4 | 1 | 1 | 1 | 2 | CVA6 RVFI adapter unit test covers dual commit ports, non-ECALL trap, compressed control flow, and an RV64 C.ADDIW non-jump case. |
| `cva6_smoke` | BLOCKED | 0 | 0 | 0 | 0 | 0 | Full CVA6 HDL compile/elab reaches xsim, but Vivado v2025.2 hits a kernel fatal at time 0 in upstream `axi_demux.sv` before the smoke program retires. |

## Artifact Layout

```text
results/vivado_sim/<test>/
  trace.jsonl
  compare.log
  xsim.log
  waveform.wdb
```

For `cva6_smoke`, `run.log` and `xsim.log` are published even on BLOCKED runs.
When Vivado fails before any committed events, `trace.jsonl` is intentionally
empty and `compare.log` starts with `[BLOCKED]`.

## Current Verification Status

- Python checker self-test: PASS via `python -m py_compile tools\compare_trace.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via `vivado -mode batch -source sim/vivado/run_all_tests.tcl`.
- CVA6 xsim smoke compile/elab: PASS. `uv run rvmt sim:cva6-smoke` compiles the
  flattened CVA6 filelist, trace sources, testharness, DPI stubs, and elaborates
  `tb_cva6_xsim_smoke_snap`.
- CVA6 xsim smoke run: BLOCKED. Vivado v2025.2 reports `FATAL_ERROR` at time 0
  in upstream `rtl/cva6/vendor/pulp-platform/axi/src/axi_demux.sv`, from the
  `ariane_testharness` AXI crossbar instance. The runner detects this simulator
  fatal explicitly instead of treating the empty trace as a checker mismatch.
- After `sim:cva6-smoke` publishes its blocked artifact, `sim:summary` reports
  the known `cva6_smoke` runtime blocker as `PASS_WITH_BLOCKED` while keeping
  true trace/checker failures and missing artifacts as failures.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; full CVA6 program trace
  comparison is waiting on the Vivado runtime blocker above.

The passing tests above are still unit-level regressions. They verify tap packet
semantics and the CVA6 RVFI committed-stream adapter before the full CVA6
program execution flow is run under xsim.
