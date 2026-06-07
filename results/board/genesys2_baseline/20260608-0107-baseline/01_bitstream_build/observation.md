# Genesys2 CVA6 Phase 2 Observation

Status: PASS

Run ID: 20260608-0107-baseline
Timestamp: 2026-06-08 02:35:56 +08:00

## Change

- Updated `rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc` inside the CVA6 submodule so CVA6 UART `tx` uses PMOD JC1 / AC26 with `LVCMOS33 DRIVE 8 SLEW SLOW` and `rx` uses PMOD JC2 / AJ27 with `LVCMOS33 PULLUP TRUE`.
- `constraint_diff.patch` records the two-line UART-only constraint diff from Y23/Y20 to AC26/AJ27.

## Build Evidence

- Command: `uv run rvmt bitstream:build`, see `command.log`.
- Artifact manifest: `artifact_manifest.txt`.
- Timing summary: `timing_summary.txt`.
- Check timing summary: `check_timing_summary.txt`.
- Route status summary: `route_status_summary.txt`.
- Post-build checker: `post_build_board_baseline_check.log`.

## Result

- `ariane_xilinx.bit` generated under `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/` with size 11,443,738 bytes.
- `ariane_xilinx.mcs`, `ariane_xilinx.dcp`, GUI project, timing report, utilization report, check_timing report, route-status report, and DDR/clock IP artifacts are present.
- Routed timing is Slack (MET) 0.177 ns.
- Route status is 130,611/130,611 routable nets fully routed with 0 routing errors.
- `tools/check_board_baseline.py` passed after the rebuild; known check_timing open warning classes remain the documented WARN rows.

## Acceptance

Phase 2 passes. The baseline CVA6 image was rebuilt after the PMOD JC UART constraint change. Generated bitstream, DCP, project, reports, and Vivado caches remain ignored build artifacts and are not intended for commit.
