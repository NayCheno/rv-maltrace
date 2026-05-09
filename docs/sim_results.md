# Vivado Simulation Results

This document is the running record for MVP simulation evidence.

## Summary

| Test | Status | Events | Retire | Branch | Jump | Syscall Entry | Syscall Ret | Arg Mem | Trap | Priv | Drop | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `smoke` | PASS | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `branch` | PASS | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `jump` | PASS | 4 | 2 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `ecall` | PASS | 3 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 1 | 0 | Confirms same-cycle U-mode `SYSCALL_ENTRY`/`TRAP` emission from the exception path. |
| `syscall_ret` | PASS | 8 | 2 | 0 | 0 | 1 | 1 | 0 | 1 | 3 | 0 | Confirms qualified SRET-to-U return capture, return value, return PC, and syscall duration. |
| `pointer_string` | PASS | 13 | 2 | 0 | 0 | 1 | 1 | 5 | 1 | 3 | 0 | Confirms synthetic openat pathname capture as five ordered `ARG_MEM` bytes ending at NUL. |
| `pointer_guardrails` | PASS | 46 | 6 | 0 | 0 | 5 | 5 | 14 | 5 | 11 | 0 | Confirms page-boundary continuity, max-length limiting, multi-byte load clipping, watch timeout, and unrelated S-mode load rejection. |
| `trap_illegal` | PASS | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `ebreak` | PASS | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Trace unit xsim and JSONL checker passed. |
| `csr` | PASS | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | SATP event checked by JSONL golden. |
| `context` | PASS | 3 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | PRIV event checked by JSONL golden. |
| `backpressure` | PASS | 30 | 0 | 0 | 0 | 8 | 0 | 0 | 14 | 1 | 7 | Queue overflow/drop-mode unit test produced 7 DROP events. |
| `filter` | PASS | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Event enable, PC range, and privilege mask filter controls left only one expected branch. |
| `board_minimal` | PASS | 5 | 0 | 1 | 0 | 1 | 0 | 0 | 1 | 2 | 0 | Minimal board trace profile golden uses syscall/trap/context/drop-safe event names. |
| `rvfi_adapter` | PASS | 15 | 6 | 1 | 1 | 1 | 1 | 0 | 2 | 3 | 0 | CVA6 RVFI adapter unit test covers dual commit ports, U-mode syscall entry/return correlation, non-ECALL trap, compressed control flow, and an RV64 C.ADDIW non-jump case. |
| `cva6_smoke` | PASS | 7 | 5 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | Direct-core CVA6 xsim smoke booted at DRAM, reached tohost, and checker matched the first committed instructions. |
| `cva6_branch` | PASS | 10 | 7 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | Direct-core CVA6 branch program matched taken branch target `0x80000014`. |
| `cva6_jump` | PASS | 9 | 6 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | Direct-core CVA6 jump program matched JAL target `0x8000000c`. |
| `cva6_ecall` | PASS | 15 | 12 | 0 | 2 | 0 | 0 | 0 | 1 | 0 | 0 | Direct-core CVA6 machine-mode ecall program remains a TRAP, not a Linux syscall entry. |
| `cva6_trap_illegal` | PASS | 11 | 8 | 0 | 2 | 0 | 0 | 0 | 1 | 0 | 0 | Direct-core CVA6 illegal instruction program matched trap pc/cause/tval. |
| `cva6_ebreak` | PASS | 11 | 8 | 0 | 2 | 0 | 0 | 0 | 1 | 0 | 0 | Direct-core CVA6 ebreak program matched breakpoint trap cause. |

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

- Python checker and semantic recovery gates: PASS via
  `uv run python tools/recover_behavior.py --self-test` and
  `uv run python tools/check_linux_behavior_recovery.py`.
- Vivado trace unit and RVFI adapter `xvlog/xelab/xsim`: PASS via
  `uv run rvmt sim:trace-unit`. The matrix includes `syscall_ret`, which checks
  syscall entry/return pairing, return value, SRET-to-U qualification, return PC,
  and duration. It also includes `pointer_string` and `pointer_guardrails`,
  which check default-disabled `ARG_MEM` pointer snapshots, null termination,
  page-boundary continuity, max-length limiting, multi-byte load clipping,
  watch timeout, and unrelated S-mode load rejection.
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

Phase 2 packet compression is currently an offline prototype. On 2026-05-09,
`tools/compress_trace.py --check-roundtrip --stats` passed for
`sim/golden/behavior_recovery.trace.jsonl`, covering syscall entry/return,
argument-memory events, cycle deltas, PC deltas, event-specific payloads,
context deltas, SATP-to-CSR context handling, and no-PC MARKER/DROP records.

Selective memory trace is explicitly reserved but disabled by default:
`TRACE_MEM_MODE_DEFAULT == TRACE_MEM_MODE_NONE`. The synthetic trace testbench
fatal-checks this default before running the regression. `pointer_string` and
`pointer_guardrails` explicitly select a non-default mode to exercise bounded
syscall-scoped `ARG_MEM` snapshots without enabling default load/store trace.

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
