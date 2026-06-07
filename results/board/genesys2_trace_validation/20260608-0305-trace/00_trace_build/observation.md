# Phase 5 Trace-Enabled CVA6 Build Observation

Status: PASS

Run ID: 20260608-0305-trace
Board: Digilent Genesys 2
Target: CVA6 trace-enabled FPGA build
Evidence directory: results/board/genesys2_trace_validation/20260608-0305-trace/00_trace_build

## Commands

- `uv run rvmt bitstream:build-trace`
- `uv run python tools/generate_resource_report.py`

The first `bitstream:build-trace` attempt failed during generated MIG IP directory replacement with a host-side permission-denied rename. The generated MIG output directory was scoped to the workspace and cleaned up before retry. The retry completed with `RVMT_COMMAND_EXIT=0`; the failed attempt is retained as `command_failed_mig_permission.log`.

## Build Result

- Vivado artifacts: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace`
- Bitstream: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit`
- MCS image: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.mcs`
- Timing report: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.timing.rpt`
- Utilization report: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt`

The trace-enabled implementation routed successfully, produced the bitstream and flash image, and reported worst Slack (MET) of 0.177 ns.

## Resource Summary

`uv run python tools/generate_resource_report.py` completed successfully and updated `docs/07-evaluation-evidence/reports/resource_report.md`.

- Baseline LUT: 84928
- Trace-enabled LUT: 125731
- LUT delta: +40803 (+48.04%)
- Baseline FF: 56491
- Trace-enabled FF: 59301
- FF delta: +2810 (+4.97%)
- BRAM18 equiv delta: +0
- DSP delta: +0
- Slack delta: 0.000 ns

## Constraints And Export Policy

The committed Phase 2 UART mapping remains on PMOD JC:

- `tx` AC26, LVCMOS33, DRIVE 8, SLEW SLOW
- `rx` AJ27, LVCMOS33, PULLUP TRUE

`git -C rtl/cva6 diff -- corev_apu/fpga/constraints/genesys-2.xdc` produced no hunks after the trace build, so the trace build did not drift the UART constraints.

The configured first-board trace policy matches `docs/02-trace-architecture/trace_export_decision.md`: bounded BRAM ring buffer plus ILA/JTAG dump, with full retire disabled by default and drop accounting observable. This phase proves the trace-enabled FPGA build route/timing/resource gate only; board-exported trace packet validation remains Phase 6.
