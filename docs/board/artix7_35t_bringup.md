# Artix-7 35T Bring-up Path

This document records the low-cost Artix-7 35T path for RV-MalTrace. It is a
board-specific experiment track, not a replacement for the current CVA6 +
Genesys 2 evidence path.

## Board Assumption

The working assumption is a Digilent Arty A7-35T-class board with an
`xc7a35t` Artix-7 FPGA, external DDR memory, USB-JTAG/UART, and Vivado support
through Digilent/Xilinx board files.

If the actual board is a different Artix-7 35T module without DDR, the Linux
path below does not apply. In that case, use the board only for bare-metal trace
tap validation.

## Recommendation

Use the Artix-7 35T board for a LiteX/VexRiscv-SMP prototype first.

```text
Artix-7 35T board
  -> LiteX SoC
  -> VexRiscv SMP Linux-capable CPU
  -> minimal syscall/trap/context trace adapter
  -> bounded trace buffer / LiteX CSR export
  -> existing RV-MalTrace JSONL parser and behavior recovery tools
```

Do not target CVA6 on Artix-7 35T as the first implementation. The current CVA6
board path is sized around Genesys 2-class resources, DDR integration, and the
existing Vivado evidence flow. Forcing CVA6 into 35T would likely spend the
project budget on SoC/resource/timing reduction instead of trace semantics.

## Candidate Cores

| Core | Artix-7 35T fit | Use in this project |
| --- | --- | --- |
| VexRiscv SMP / LiteX | HIGH | Preferred Linux-capable prototype path. Use RV32 Linux to validate syscall/context trace flow and host tooling. |
| Ibex | HIGH | Good bare-metal trace tap and export-path prototype. Not enough for Linux malware behavior reconstruction. |
| VeeR EH1 / SweRVolf | MEDIUM | Good bare-metal or RTOS trace prototype. Not the primary Linux path. |
| Rocket-on-LiteX | LOW/MEDIUM | Possible as an experiment, but too tight and fragile for the first board milestone. |
| CVA6 | LOW | Keep on Genesys 2 or larger FPGA. Do not spend the 35T path on CVA6 resource closure. |
| BOOM / XiangShan | NO | Resource footprint is outside the practical 35T target. |

## First Evidence Gates

All board rows stay `TODO (BOARD)` until artifacts exist under the matching
`results/board/artix7_35t_litex/<run-id>/` directory.

| Gate | Status | Required evidence |
| --- | --- | --- |
| Board identity recorded | TODO (BOARD) | Board model, FPGA part, DDR presence, board-file source, Vivado version |
| LiteX baseline bitstream builds | TODO | Build log and generated bitstream path under `build/` |
| FPGA programming succeeds | TODO (BOARD) | Programming transcript or tool log |
| UART console works | TODO (BOARD) | Raw UART boot log |
| Linux boots on VexRiscv SMP | TODO (BOARD) | Linux boot log with CPU, memory, and init/userspace evidence |
| Minimal trace path simulates | TODO | Simulation or LiteX verilator log for trace packet shape |
| Minimal trace path runs on board | TODO (BOARD) | Captured trace dump plus parsed JSONL |
| Trace comparison passes | TODO (BOARD) | `tools/compare_trace.py` or a board-specific checker output |

## Minimal Trace Policy

Start with event-selective trace only:

- syscall entry and return when the core/software path exposes enough context
- trap/exception events
- privilege/context events when available
- drop counter / overflow event

Keep full retire, full branch, and load/store tracing disabled for the first
35T board milestone. The small FPGA should prove the low-perturbation trace
pipeline first, not full bandwidth capture.

The trace sink must remain non-intrusive. If the board-side buffer fills, drop
records and account for `EVT_DROP`; do not stall the core or Linux memory path.

## Export Path

Prefer a bounded hardware buffer exposed through LiteX CSR or a small BRAM ring
that host software can dump after a workload. UART streaming is acceptable only
for narrow smoke traces and should not become the default high-throughput
transport.

Do not reuse the Genesys 2 BRAM + ILA/JTAG decision as-is without checking 35T
resource and debug-probe constraints. The Artix-7 35T path should choose the
simplest export that preserves event semantics and drop accounting.

## Integration Notes

Keep the CVA6 and Artix-7 35T tracks separate:

- CVA6/Genesys 2 remains the RV64/SV39 application-core mainline.
- Artix-7 35T is a low-cost prototype for trace pipeline and Linux behavior
  tooling.
- Reuse the existing JSONL trace format instead of creating a second parser
  contract.
- Add any future VexRiscv adapter as a separate module; do not weaken the CVA6
  signal map to fit LiteX.
- Record all physical-board evidence under
  `results/board/artix7_35t_litex/<run-id>/`.

## Go / No-Go Criteria

Use Artix-7 35T as the next board only if the goal is fast, cheap validation of
the trace pipeline. Use Genesys 2 or a larger board if the goal is RV64 Linux
evidence, CVA6-specific signal attachment, or paper-level resource comparison.
