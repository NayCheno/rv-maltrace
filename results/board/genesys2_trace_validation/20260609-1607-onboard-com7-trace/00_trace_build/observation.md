# Genesys2 CVA6 Phase 5 Observation

Status: PASS

Run ID: 20260609-1607-onboard-com7-trace
Timestamp:
2026-06-09 18:39:45 +08:00

## Commands

- `uv run rvmt bitstream:build-trace` completed, but the first routed image missed timing by 0.038 ns; see `command.log`.
- `uv run python tools/generate_resource_report.py` passed; see `resource_report.log`.
- `uv run python tools/check_board_trace_minimal.py` passed.
- `uv run python tools/check_trace_export_decision.py` passed.
- `uv run python tools/check_timing_principles.py` passed.
- A route-only recovery from `ariane_xilinx_physopt.dcp` used `recovery_route_explore.tcl`; see `recovery_explore.log`.

## Build Evidence

- `timing_summary.txt` records the initial timing miss and the recovered routed PASS.
- `trace_constraint_diff.patch` records that this trace-enabled build introduced no additional board pin or trace-export I/O constraint changes.
- `resource_report_excerpt.txt` records the generated LUT/FF/BRAM/DSP/slack delta summary.
- `policy_checks.log` records the three passing policy/checker command outputs used for this acceptance.
- `recovery_explore.log` contains `RVMT_RECOVERY_WNS=0.115` and `RVMT_RECOVERY_RESULT=PASS`.
- The final trace bitstream and MCS were regenerated under `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/`.

## Result

- Final routed trace build meets timing with worst slack 0.115 ns MET.
- Route status is 233,558/233,558 routable nets fully routed with 0 routing errors.
- `docs/07-evaluation-evidence/reports/resource_report.md` was regenerated and now records LUT +86,368 (+101.70%), FF +8,621 (+15.26%), BRAM18 equiv +6 (+5.56%), DSP +0, and slack delta -0.062 ns versus baseline.
- `tools/check_board_trace_minimal.py` confirms the first-board profile keeps full retire disabled and limits first-board behavior events to syscall, trap, context, and branch with drop accounting enabled.
- `tools/check_trace_export_decision.py` confirms the first-board export path remains the bounded BRAM ring plus JTAG-visible dump path.
- `tools/check_timing_principles.py` confirms the trace RTL keeps pipelined sideband capture and exposes no ready/stall/backpressure-style ports.

## Deviation From Original COM6/PMOD Plan

- The original acceptance document expects PMOD JC UART, but this bring-up thread explicitly switched serial bring-up to the onboard USB-UART on COM7.
- Phase 5 preserves that already-accepted onboard mapping (`tx=Y23`, `rx=Y20`) and introduces no additional UART constraint change.

## Acceptance

Phase 5 passes for the current Genesys2/CVA6 bring-up path. The trace-enabled
build is routed, timing/resource evidence is recorded under this run directory,
the first-board trace profile and BRAM/JTAG export-policy checks pass, and the
board-facing UART mapping remains the onboard COM7 path already adopted earlier
in this bring-up.
