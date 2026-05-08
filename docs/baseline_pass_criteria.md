# Baseline Pass Criteria

Phase 4.4 pass/fail matrix for Genesys 2 baseline board work.

This document separates repository-local evidence from physical board evidence.
Only mark a physical board criterion PASS after the corresponding runbook
evidence exists under `results/board/genesys2_baseline/<run-id>/`.

| Criterion | Current Status | Required Evidence | Source |
| --- | --- | --- | --- |
| Bitstream generated | PASS | `build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ariane_xilinx.bit` exists and Phase 4.1/4.2 preflight passes | `tools/check_board_baseline.py`, `tools/check_vivado_authorization.py` |
| Board clock/reset stable | TODO (BOARD) | `01_led_clock_reset/observation.md` with PASS plus programming transcript or board observation artifact | `docs/baseline_bringup_runbook.md` |
| UART output visible | TODO (BOARD) | `02_uart_hello/observation.md` with PASS plus raw UART log | `docs/baseline_bringup_runbook.md` |
| Bare-metal program can run | TODO (BOARD) | `04_cva6_baremetal_boot/observation.md` with PASS plus UART/tohost/JTAG log showing the expected end state | `docs/baseline_bringup_runbook.md` |
| No trace modification yet | PASS | Baseline artifacts come from the existing CVA6 FPGA build and no trace-enabled board export path is enabled in the Phase 4 runbook | `docs/baseline_bringup_runbook.md` |

Baseline board bring-up is not complete until the three `TODO (BOARD)` rows
above have physical evidence. Linux boot remains optional for the MVP and does
not block Phase 4.4 unless the project explicitly chooses to make it part of the
baseline acceptance run.
