# Genesys2 CVA6 Phase 1 Observation

Status: PASS

Run ID: 20260608-0107-baseline
Timestamp: 2026-06-08 01:07 Asia/Shanghai

## Commands

- `uv run rvmt vivado:check`: exit 0, see `vivado_check.log`
- `uv run python tools/check_board_baseline.py`: exit 1, see `board_baseline_check.log`
- `uv run python tools/check_vivado_authorization.py`: exit 1, see `vivado_authorization_check.log`

## Result

Vivado can run and can see the configured Genesys 2 target part and board file.
After rebuilding the ignored local simulation and Vivado artifacts, all three
Phase 1 preflight commands completed successfully:

- `uv run rvmt vivado:check`: PASS
- `uv run python tools/check_board_baseline.py`: PASS, with known check_timing WARN rows only
- `uv run python tools/check_vivado_authorization.py`: PASS

Key evidence recorded by the command logs:

- `results/vivado_sim/summary.json` overall PASS, 20 expected tests PASS.
- `ariane_xilinx.bit` exists under `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/` and is 11,443,738 bytes.
- `ariane_xilinx.mcs`, `ariane_xilinx.dcp`, GUI project, utilization report, timing report, check_timing report, route-status report, and DDR/clock generated IP artifacts exist.
- Routed timing is Slack (MET) 0.177 ns.
- Route status is 130,576/130,576 routable nets fully routed with 0 routing errors.
- Vivado authorization found the Genesys 2 target part, board files, bitstream artifacts, routed timing, and route status.

## Acceptance

Phase 1 passes. The baseline artifacts used here are repository-local preflight
evidence only; the Phase 2 PMOD JC UART constraint change and rebuild remain a
separate step.
