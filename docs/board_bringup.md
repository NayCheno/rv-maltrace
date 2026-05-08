# Genesys 2 Board Bring-up

Board work is intentionally after the Vivado simulation MVP.

## Baseline Bring-up Gate

| Gate | Status | Evidence |
| --- | --- | --- |
| Vivado part and board files visible | PASS | `uv run rvmt vivado:check` on 2026-05-08: `xc7k325tffg900-2` and `digilentinc.com:genesys2:part0:1.1` visible |
| Local Vivado simulation gate | PASS | `uv run python tools/check_board_baseline.py`: `results/vivado_sim/summary.json` overall PASS, 17 expected tests PASS with referenced trace/compare artifacts present |
| Baseline CVA6 bitstream generated | PASS | `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit` (11,443,738 bytes), plus `.mcs`, `.dcp`, and GUI `ariane.xpr` present |
| Baseline route/timing reports | PASS | Route status: 130,576/130,576 routable nets fully routed, 0 routing errors; timing Slack (MET) 0.177 ns |
| Baseline check_timing constraints | WARN | Parsed `ariane.check_timing.rpt`; known open warnings: `no_clock=126`, `unconstrained_internal_endpoints=33`, `no_input_delay=21`, `no_output_delay=23`, `partial_input_delay=3` |
| Genesys 2 constraints available | PASS | Active `rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc` commands constrain `cpu_resetn`, `prog_clko`, UART `tx`, and UART `rx` |
| DDR / clock / reset / UART static path | PASS | Active FPGA Tcl commands include `xlnx_mig_7_ddr3`, `xlnx_clk_gen`, `xlnx_dpti_clk`, and the APB UART source path; generated DDR/clock IP artifacts are present |
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

## Trace-enabled Bring-up Plan

1. Keep full retire disabled by default.
2. Enable syscall, trap, context, and branch events first.
3. Use drop mode before any lossless backpressure mode.
4. Export the first hardware trace through BRAM ring buffer plus ILA/JTAG dump.
5. Compare hardware trace event shape against Vivado simulation JSONL.
