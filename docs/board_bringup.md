# Genesys 2 Board Bring-up

Board work is intentionally after the Vivado simulation MVP.

## Baseline Bring-up Gate

| Gate | Status | Evidence |
| --- | --- | --- |
| Vivado part and board files visible | TODO | `uv run rvmt vivado:check` |
| Baseline CVA6 bitstream generated | TODO | `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit` |
| Clock/reset sanity | TODO | Board observation notes |
| UART hello | TODO | UART log |
| Bare-metal program runs | TODO | UART/tohost log |

## Trace-enabled Bring-up Plan

1. Keep full retire disabled by default.
2. Enable syscall, trap, context, and branch events first.
3. Use drop mode before any lossless backpressure mode.
4. Export the first hardware trace through BRAM ring buffer plus ILA/JTAG dump.
5. Compare hardware trace event shape against Vivado simulation JSONL.
