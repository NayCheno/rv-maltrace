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
| `cva6_full_soc_smoke` | PASS | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Full `ariane_testharness` breakpoint-terminated smoke compiled, elaborated, booted from DRAM, and observed the expected breakpoint trap. |
| `cva6_full_soc_uart_store_path` | PASS | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Full `ariane_testharness` observed a committed RVFI store to UART/MMIO address `0x10000000` using the two-instruction store-path gate. |
| `cva6_full_soc_tohost_normal` | PASS | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Full `ariane_testharness` normal tohost/MMIO probe compiled, elaborated, and observed a committed tohost store without `RVMT_STORE_PATH_ONLY`. |
| `cva6_full_soc_rv64gc_i_addi` | PASS | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Full-SoC retire-count microprobe for the base integer `I` extension. |
| `cva6_full_soc_rv64gc_m_mul` | PASS | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Full-SoC retire-count microprobe for the multiply/divide `M` extension. |
| `cva6_full_soc_rv64gc_c_nop` | PASS | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Compressed `C.NOP` retired once; the runner accepts the explicit PASS transcript even if xsim does not exit cleanly before the wrapper timeout. |
| `cva6_full_soc_rv64gc_f_fsgnj_s` | PASS | 4 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Full-SoC single-precision `FSGNJ.S` retired once with the simulation M-mode environment forcing FS Dirty. |
| `cva6_full_soc_rv64gc_d_fsgnj_d` | PASS | 4 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | Full-SoC double-precision `FSGNJ.D` retired once with the simulation M-mode environment forcing FS Dirty. |
| `cva6_full_soc_rv64gc_a_sc_w` | PASS | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | Full-SoC atomic `SC.W` retired once. |

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
- Full CVA6 `ariane_testharness` xsim breakpoint run: PASS via
  `uv run rvmt sim:cva6-full-soc`. On 2026-05-17, the full-SoC probe compiled
  and elaborated the full `ariane_testharness`, booted at DRAM
  `0x8000_0000`, retired a normal instruction, observed the magic breakpoint
  trap at `0x8000_0004`, and published PASS artifacts to
  `results/vivado_sim/cva6_full_soc_smoke/`.
- Full-SoC UART/MMIO store-path gate: PASS via
  `uv run rvmt sim:cva6-full-soc-store`. On 2026-05-17, the full
  `ariane_testharness` booted a two-instruction DRAM image, retired the
  address setup instruction, observed a committed RVFI store to UART/MMIO
  address `0x1000_0000` with byte strobe `0xff`, and published PASS artifacts
  to `results/vivado_sim/cva6_full_soc_uart_store_path/`. This proves the
  local full-SoC UART/MMIO store observation path, but it is not the same as a
  normal multi-instruction tohost program reaching completion.
- Normal full-SoC tohost/MMIO completion gate: PASS via
  `uv run rvmt sim:cva6-full-soc-tohost`. On 2026-05-18, the full
  `ariane_testharness` compiled and elaborated, booted
  `sim/programs/full_soc_dram_tohost/full_soc_dram_tohost.mem`, observed a
  committed RVFI store to `0x1000_0000`, and published PASS artifacts to
  `results/vivado_sim/cva6_full_soc_tohost_normal/`. This uses the normal
  completion path and does not set `RVMT_STORE_PATH_ONLY`.
- Direct CVA6 trace integration: PARTIAL. `RV_MALTRACE_TRACE=1` enables the
  guarded CVA6 testharness RVFI hook and JSONL sink; the direct-core smoke
  separately verifies the same adapter/sink path against real CVA6 committed
  RVFI events.

The synthetic tests verify tap packet semantics, CSR/SATP/context events,
filtering, queue/drop behavior, and the CVA6 RVFI adapter. The `cva6_*` rows are
real CVA6 core execution tests with trace-on/no-trace final-result matching. The
full SoC harness is now part of the reproducible local simulation evidence via a
short breakpoint-terminated smoke plus a separate UART/MMIO store-path
observation gate plus a separate normal tohost/MMIO completion gate. Both are
repository-local simulation evidence, not physical board evidence.

Full-SoC RV64GC microprobe coverage is PASS via
`uv run rvmt sim:cva6-full-soc-rv64gc`. The suite covers one committed
instruction from each RV64GC extension family: `I` (`ADDI`), `M` (`MUL`), `A`
(`SC.W`), `F` (`FSGNJ.S`), `D` (`FSGNJ.D`), and `C` (`C.NOP`). The `F` and `D`
probes use the simulation-only `RVMT_FORCE_FS_DIRTY` plusarg to model an M-mode
runtime that has enabled floating-point state. This is a minimum per-extension
full-SoC retire gate, not a claim that arbitrary RV64GC programs, riscv-tests,
Linux, or physical board execution have passed.

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

Phase 3.3 resource reporting is generated in `docs/reports/resource_report.md` from the
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
