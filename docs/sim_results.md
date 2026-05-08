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

## Artifact Layout

```text
results/vivado_sim/<test>/
  trace.jsonl
  compare.log
  xsim.log
  waveform.wdb
```

## Current Verification Status

- Python checker self-test: PASS via `python -m py_compile tools\compare_trace.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via `vivado -mode batch -source sim/vivado/run_all_tests.tcl`.
- CVA6 baseline xsim: TODO.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; full CVA6 program
  execution in xsim remains TODO.

The passing tests above are still unit-level regressions. They verify tap packet
semantics and the CVA6 RVFI committed-stream adapter before the full CVA6
program execution flow is run under xsim.
