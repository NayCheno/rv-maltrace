# Genesys2 CVA6 Phase 5 Syscall-Return Corrective Observation

Status: PASS

Run ID: 20260609-2215-phase5-syscall-ret-fix
Timestamp:
2026-06-09 23:30:00 +08:00

## Scope

This run corrects the trace-enabled Genesys2 FPGA path after Phase 6 board
evidence showed that Linux user syscalls emitted `SYSCALL_ENTRY` but never
emitted `SYSCALL_RET`.

Root cause: the FPGA RVFI export path ties `rvfi_sret_to_user` low in
`rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv`, while
`rtl/trace/cva6_rvfi_trace_adapter.sv` previously required that signal to be
high before emitting `EVT_SYSCALL_RET`. The board therefore could not produce
syscall return events even though simulation scenarios with explicit
`rvfi_sret_to_user=1` passed.

## Corrective RTL Change

- `rtl/trace/cva6_rvfi_trace_adapter.sv` adds the parameter
  `RELAX_SRET_TO_USER_CHECK`. When enabled, an S-mode `SRET` with an
  outstanding user syscall closes the syscall pair even if explicit
  `rvfi_sret_to_user` metadata is unavailable.
- `rtl/cva6/corev_apu/fpga/src/ariane_xilinx.sv` enables that relaxed mode for
  the real Genesys2 FPGA trace path.
- `sim/tb/tb_cva6_rvfi_trace_adapter.sv` now exercises the relaxed mode with
  `rvfi_sret_to_user=0` and still requires the expected `SYSCALL_RET`.
- `sim/tb/tb_cva6_direct_xsim_smoke.sv` also enables the relaxed mode so the
  direct-core smoke path matches the board-facing FPGA integration.

## Validation

- `uv run rvmt sim:trace-unit` passed.
  - `results/vivado_sim/rvfi_adapter/compare.log` still reports exactly one
    `SYSCALL_RET`.
  - The adapter test now passes with `rvfi_sret_to_user=0`, reproducing the
    board wiring gap while preserving the expected event shape.
- `uv run rvmt sim:cva6-smoke` passed.
- `uv run rvmt bitstream:build-trace` completed with routed implementation and
  met timing directly; no post-route recovery was needed.
- `uv run python tools/generate_resource_report.py` passed.
- `uv run python tools/check_board_trace_minimal.py` passed.
- `uv run python tools/check_trace_export_decision.py` passed.
- `uv run python tools/check_timing_principles.py` passed.

## Build Result

- The routed design meets all user timing constraints with:
  - `WNS=0.177ns`
  - `TNS=0.000ns`
  - `WHS=0.038ns`
  - `THS=0.000ns`
- Route status is `236233/236233` routable nets fully routed with `0` routing
  errors.
- Final trace artifacts were regenerated under
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/`.

## Resource Snapshot

- `docs/07-evaluation-evidence/reports/resource_report.md` now reports trace
  utilization of `171405` LUTs, `65194` FFs, `114` BRAM18 equiv, and `27` DSPs.
- The trace-enabled report still records `Slack=0.177ns` in
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.timing.rpt`.

## UART / Constraints

This corrective run preserves the previously adopted onboard USB-UART path on
`COM7` (`tx=Y23`, `rx=Y20`) and introduces no new XDC change. The fix is
strictly within the trace event reconstruction path.

## Acceptance

Corrective Phase 5 passes for the current bring-up path. The trace-enabled
Genesys2 build is routed, timing-clean, and now includes a board-appropriate
syscall return reconstruction rule that is validated in simulation before the
next Phase 6 board retry.
