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
| `cva6_smoke` | PASS | 5 | 0 | 2 | 0 | 0 | Direct-core CVA6 xsim smoke booted at DRAM, reached tohost, and checker matched the first committed instructions. |

## Artifact Layout

```text
results/vivado_sim/<test>/
  trace.jsonl
  compare.log
  xsim.log
  waveform.wdb
```

For `cva6_smoke`, `run.log` and `xsim.log` are also published on BLOCKED runs.
When Vivado fails before any committed events, `trace.jsonl` is intentionally
empty and `compare.log` starts with `[BLOCKED]`.

## Current Verification Status

- Python checker self-test: PASS via `python -m py_compile tools\compare_trace.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via `vivado -mode batch -source sim/vivado/run_all_tests.tcl`.
- CVA6 direct-core xsim smoke: PASS via `uv run rvmt sim:cva6-smoke`. The runner
  compiles the flattened CVA6 filelist, trace sources, direct-core testbench,
  DPI stubs, elaborates `tb_cva6_direct_xsim_smoke_snap`, runs tohost, and
  compares the JSONL trace against `sim/golden/cva6_smoke.expected.json`.
- Full CVA6 `ariane_testharness` xsim run: BLOCKED. Vivado v2025.2 reports
  `FATAL_ERROR` at time 0 in upstream
  `rtl/cva6/vendor/pulp-platform/axi/src/axi_demux.sv`, from the SoC AXI crossbar
  instance. The direct-core smoke avoids that crossbar to verify committed CVA6
  RVFI trace execution.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; the direct-core smoke
  separately verifies the same adapter/sink path against real CVA6 committed
  RVFI events.

The synthetic tests verify tap packet semantics and the CVA6 RVFI adapter. The
`cva6_smoke` row is a real CVA6 core execution smoke, but it intentionally avoids
the full SoC harness while the upstream AXI xbar runtime blocker remains open.
