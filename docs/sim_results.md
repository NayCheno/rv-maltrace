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
| `cva6_branch` | PASS | 7 | 1 | 3 | 0 | 0 | Direct-core CVA6 branch program matched taken branch target `0x80000014`. |
| `cva6_jump` | PASS | 6 | 0 | 4 | 0 | 0 | Direct-core CVA6 jump program matched JAL target `0x8000000c`. |
| `cva6_ecall` | PASS | 12 | 0 | 3 | 1 | 1 | Direct-core CVA6 ecall program matched a0/a1/a2/a7 and machine ecall trap cause. |
| `cva6_trap_illegal` | PASS | 8 | 0 | 3 | 0 | 1 | Direct-core CVA6 illegal instruction program matched trap pc/cause/tval. |
| `cva6_ebreak` | PASS | 8 | 0 | 3 | 0 | 1 | Direct-core CVA6 ebreak program matched breakpoint trap cause. |

## Artifact Layout

```text
results/vivado_sim/<test>/
  trace.jsonl
  compare.log
  xsim.log
  waveform.wdb
```

For direct-core `cva6_*` tests, `run.log` and `xsim.log` are also published on
BLOCKED runs.
When Vivado fails before any committed events, `trace.jsonl` is intentionally
empty and `compare.log` starts with `[BLOCKED]`.

## Current Verification Status

- Python checker self-test: PASS via `python -m py_compile tools\compare_trace.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via `vivado -mode batch -source sim/vivado/run_all_tests.tcl`.
- CVA6 direct-core xsim matrix: PASS via `uv run rvmt sim:cva6-smoke`. The runner
  compiles the flattened CVA6 filelist, trace sources, direct-core testbench,
  DPI stubs, elaborates `tb_cva6_direct_xsim_smoke_snap`, then runs six
  hand-encoded bare-metal DRAM images through the same snapshot and compares
  each JSONL trace against its `sim/golden/cva6_*.expected.json` file.
- Full CVA6 `ariane_testharness` xsim run: BLOCKED. Vivado v2025.2 reports
  `FATAL_ERROR` at time 0 in upstream
  `rtl/cva6/vendor/pulp-platform/axi/src/axi_demux.sv`, from the SoC AXI crossbar
  instance. The direct-core smoke avoids that crossbar to verify committed CVA6
  RVFI trace execution.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; the direct-core smoke
  separately verifies the same adapter/sink path against real CVA6 committed
  RVFI events.

The synthetic tests verify tap packet semantics, CSR/SATP/context events, and the
CVA6 RVFI adapter. The `cva6_*` rows are real CVA6 core execution tests, but they
intentionally avoid the full SoC harness while the upstream AXI xbar runtime
blocker remains open.
