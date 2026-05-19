# Genesys 2 Board Bring-up

Board work is intentionally after the Vivado simulation MVP.

## Baseline Bring-up Gate

| Gate | Status | Evidence |
| --- | --- | --- |
| Vivado part and board files visible | PASS | `uv run rvmt vivado:check` on 2026-05-08: `xc7k325tffg900-2` and `digilentinc.com:genesys2:part0:1.1` visible |
| Local Vivado simulation gate | PASS | `uv run python tools/check_board_baseline.py` on 2026-05-17: `results/vivado_sim/summary.json` overall PASS, 20 expected tests PASS with referenced trace/compare artifacts present |
| Baseline CVA6 bitstream generated | PASS | `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit` (11,443,738 bytes), plus `.mcs`, `.dcp`, and GUI `ariane.xpr` present |
| Baseline route/timing reports | PASS | Route status: 130,576/130,576 routable nets fully routed, 0 routing errors; timing Slack (MET) 0.177 ns |
| Baseline check_timing constraints | WARN | Parsed `ariane.check_timing.rpt`; known open warnings: `no_clock=126`, `unconstrained_internal_endpoints=33`, `no_input_delay=21`, `no_output_delay=23`, `partial_input_delay=3` |
| Genesys 2 constraints available | PASS | Active `rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc` commands constrain `cpu_resetn`, `prog_clko`, UART `tx`, and UART `rx` |
| DDR / clock / reset / UART static path | PASS | Active FPGA Tcl commands include `xlnx_mig_7_ddr3`, `xlnx_clk_gen`, `xlnx_dpti_clk`, and the APB UART source path; generated DDR/clock IP artifacts are present |
| Trace-enabled resource build | PASS | `uv run rvmt bitstream:build-trace` on 2026-05-17 generated `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/`; `docs/reports/resource_report.md` records the routed delta |
| Clock/reset sanity | TODO (BOARD) | Requires board observation notes after programming the bitstream |
| UART hello | TODO (BOARD) | Requires serial log from the physical board |
| Bare-metal program runs | TODO (BOARD) | Requires UART/tohost log from the physical board |

Local preflight:

```powershell
uv run python tools/check_board_baseline.py
uv run python tools/check_board_baseline.py --self-test
```

This preflight checks repository-local Vivado evidence only. It does not program
the Genesys 2 board or claim hardware clock/reset, UART, or bare-metal runtime
success.

## Authorization Risk Gate

Phase 4.2 is recorded in `docs/board/vivado_authorization.md`.

| Gate | Status | Evidence |
| --- | --- | --- |
| Vivado license / target-device gate | PASS (artifact evidence) | Existing Vivado v2025.2 build produced `ariane_xilinx.bit`, `.mcs`, `.dcp`, and a routed timing report for `7k325t-ffg900` |
| Genesys 2 FPGA part implementation | PASS | Routed timing Slack (MET) 0.177 ns; route status has 0 routing errors |
| Board files available | PASS | `uv run rvmt vivado:check` on 2026-05-08 and `tools/check_vivado_authorization.py` both confirm the Genesys 2 board files |

## Baseline Bring-up Sequence

Phase 4.3 is the ordered board procedure in `docs/board/baseline_bringup_runbook.md`.
Record all physical observations under `results/board/genesys2_baseline/<run-id>/`.

| Order | Step | Status | Evidence directory |
| ---: | --- | --- | --- |
| 1 | LED Blink / Clock Reset Sanity | TODO (BOARD) | `01_led_clock_reset/` |
| 2 | UART Hello | TODO (BOARD) | `02_uart_hello/` |
| 3 | Minimal RISC-V Core Boot | TODO (BOARD) | `03_minimal_core_boot/` |
| 4 | CVA6 Bare-metal Boot | TODO (BOARD) | `04_cva6_baremetal_boot/` |
| 5 | CVA6 Simple Linux Boot (Optional) | TODO (OPTIONAL) | `05_linux_boot_optional/` |

## Baseline Pass Criteria

Phase 4.4 is tracked in `docs/board/baseline_pass_criteria.md`. Current status:

| Criterion | Status | Evidence |
| --- | --- | --- |
| Bitstream generated | PASS | Phase 4.1/4.2 preflight and `ariane_xilinx.bit` artifact |
| Board clock/reset stable | TODO (BOARD) | Requires `01_led_clock_reset/observation.md` |
| UART output visible | TODO (BOARD) | Requires `02_uart_hello/observation.md` and raw UART log |
| Bare-metal program can run | TODO (BOARD) | Requires `04_cva6_baremetal_boot/observation.md` and UART/tohost/JTAG log |
| No trace modification yet | PASS | Baseline runbook forbids trace-enabled RTL/export changes |

## Trace-enabled Bring-up Plan

Phase 5.1 export choice is recorded in `docs/architecture/trace_export_decision.md`.
Phase 5.2 first-board event policy is recorded in `docs/board/board_trace_minimal.md`
and driven by `rtl/trace/trace_board_minimal_top.sv`.
Phase 5.3 validation programs are recorded in
`docs/board/board_trace_validation.md` and `board/trace_validation/manifest.json`.

1. Keep full retire disabled by default.
2. Enable syscall, trap, context, and branch events first.
3. Use drop mode before any lossless backpressure mode.
4. Export the first hardware trace through BRAM ring buffer plus ILA/JTAG dump.
5. Run hello, file open/read/write, fork/exec, and illegal-instruction validation programs.
6. Compare hardware trace event shape against Vivado simulation JSONL.
