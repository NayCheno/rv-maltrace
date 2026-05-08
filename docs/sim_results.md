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
| `filter` | PASS | 0 | 1 | 0 | 0 | 0 | Event enable, PC range, and privilege mask filter controls left only one expected branch. |
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
  xsim_notrace.log
  waveform.wdb
```

For direct-core `cva6_*` tests, `run.log` and `xsim.log` are also published on
BLOCKED runs. `xsim_notrace.log` records the same DRAM image running through the
direct-core snapshot with the trace adapter/sink disabled.
When Vivado fails before any committed events, `trace.jsonl` is intentionally
empty and `compare.log` starts with `[BLOCKED]`.

## Current Verification Status

- Python checker self-test: PASS via `python -m py_compile tools\compare_trace.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via `vivado -mode batch -source sim/vivado/run_all_tests.tcl`.
- CVA6 direct-core xsim matrix: PASS via `uv run rvmt sim:cva6-smoke`. The runner
  compiles the flattened CVA6 filelist, trace sources, direct-core testbench,
  DPI stubs, elaborates trace-enabled and no-trace direct-core snapshots, then
  runs six hand-encoded bare-metal DRAM images through both snapshots. The
  trace-enabled run compares each JSONL trace against its
  `sim/golden/cva6_*.expected.json` file; the no-trace run must reach the same
  tohost PASS result before the test is reported as PASS.
- Full CVA6 `ariane_testharness` xsim run: BLOCKED. Vivado v2025.2 reports
  `FATAL_ERROR` at time 0 in upstream
  `rtl/cva6/vendor/pulp-platform/axi/src/axi_demux.sv`, from the SoC AXI crossbar
  instance. The direct-core smoke avoids that crossbar to verify committed CVA6
  RVFI trace execution.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; the direct-core smoke
  separately verifies the same adapter/sink path against real CVA6 committed
  RVFI events.

The synthetic tests verify tap packet semantics, CSR/SATP/context events,
filtering, queue/drop behavior, and the CVA6 RVFI adapter. The `cva6_*` rows are
real CVA6 core execution tests with trace-on/no-trace final-result matching, but
they intentionally avoid the full SoC harness while the upstream AXI xbar
runtime blocker remains open.

Phase 2 packet compression is currently an offline prototype. On 2026-05-08,
`tools/compress_trace.py --check-roundtrip` passed for the `rvfi_adapter` JSONL
trace and `sim/golden/compression_edges.trace.jsonl`, covering cycle deltas, PC
deltas, event-specific payloads, context deltas, SATP-to-CSR context handling,
and no-PC MARKER/DROP records.

Selective memory trace is explicitly reserved but disabled by default:
`TRACE_MEM_MODE_DEFAULT == TRACE_MEM_MODE_NONE`. The synthetic trace testbench
fatal-checks this default before running the regression.

Phase 3.1 source-boundary check separates synthesizable trace RTL
(`sim/vivado/trace_rtl.f`) from simulation-only testbench/file-writer sources
(`sim/vivado/trace_sim.f`). `tools/check_trace_boundary.py` passes on the split
and scans the RTL list for simulation-only constructs; its `--self-test` path
checks negative coverage for file IO, `initial`, assertion, and delay constructs.

Phase 3.2 timing-principle check records trace as a sideband-only path:
`trace_top` and `cva6_rvfi_trace_adapter` default to a one-cycle input snapshot
before decode/packet formatting, and `tools/check_timing_principles.py` passes
with no ready/stall/backpressure ports exposed by trace RTL.

Phase 3.3 resource reporting is generated in `docs/resource_report.md` from the
existing Genesys 2 routed utilization/timing reports plus the latest
`results/vivado_sim/summary.json` drop statistics.

Phase 4.1 baseline board preflight passes via
`uv run python tools/check_board_baseline.py`. The check confirms the local
Vivado simulation summary is PASS, the existing Genesys 2 baseline bitstream,
flash image, checkpoint, GUI project, route/timing reports, board files,
active constraints, DDR/clock IP artifacts, and UART source path are present.
It also parses the baseline `check_timing` report and records the known open
constraint warnings as WARN rows. It does not replace physical board
clock/reset, UART, or bare-metal runtime observation.
