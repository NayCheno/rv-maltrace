# Artix-7 35T Resource Report

This report covers the LiteX/VexRiscv 35T prototype only. It is not CVA6 resource evidence.

| Config | Status | LUT | FF | BRAM18 equiv | DSP | WNS | Clock target | trace_records | profile |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| baseline LiteX/VexRiscv | PRESENT | 7181 | 6758 | 27 | 4 | 1.352 | 50 MHz | 0 | no-trace |
| p0 trace 256 | PRESENT | 11203 | 8010 | 27 | 4 | 1.378 | 50 MHz | 256 | p0 |
| p0 trace 512 | PRESENT | 14663 | 8175 | 27 | 4 | 1.362 | 50 MHz | 512 | p0 |
| p0 trace 1024 | BLOCKED: ERROR: [DRC UTLZ-1] Resource utilization: LUT as Distributed RAM over-utilized in Top Level Design (This design requires more LUT as Distributed RAM cells than are available in the target device. This design requires 11840 of such cell types but only 9600 compatible sites are available in the target device. Please analyze your synthesis results and constraints to ensure the design is mapped to Xilinx primitives as expected. If so, please consider targeting a larger device. Please set tcl parameter "drc.disableLUTOverUtilError" to 1 to change this error to warning.); ERROR: [DRC UTLZ-1] Resource utilization: LUT as Memory over-utilized in Top Level Design (This design requires more LUT as Memory cells than are available in the target device. This design requires 11875 of such cell types but only 9600 compatible sites are available in the target device. Please analyze your synthesis results and constraints to ensure the design is mapped to Xilinx primitives as expected. If so, please consider targeting a larger device. Please set tcl parameter "drc.disableLUTOverUtilError" to 1 to change this error to warning.); ERROR: [DRC UTLZ-1] Resource utilization: RAMD64E over-utilized in Top Level Design (This design requires more RAMD64E cells than are available in the target device. This design requires 11648 of such cell types but only 9600 compatible sites are available in the target device. Please analyze your synthesis results and constraints to ensure the design is mapped to Xilinx primitives as expected. If so, please consider targeting a larger device.); place_design failed | n/a | n/a | n/a | n/a | n/a | n/a | 1024 | p0 |
| p0 trace 2048 | BLOCKED: missing embedfire_rise_pro_utilization_place.rpt, embedfire_rise_pro_timing.rpt under D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r2048/gateware | n/a | n/a | n/a | n/a | n/a | n/a | 2048 | p0 |

## Delta From Baseline

| Config | LUT delta | FF delta | BRAM18 equiv delta | DSP delta | WNS delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| p0 trace 256 | +4022 (+56.0%) | +1252 (+18.5%) | +0 (+0.0%) | +0 (+0.0%) | 0.026 |
| p0 trace 512 | +7482 (+104.2%) | +1417 (+21.0%) | +0 (+0.0%) | +0 (+0.0%) | 0.010 |

## Sources

- `baseline LiteX/VexRiscv` utilization: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro/gateware/embedfire_rise_pro_utilization_place.rpt`
- `baseline LiteX/VexRiscv` timing: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro/gateware/embedfire_rise_pro_timing.rpt`
- `p0 trace 256` utilization: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace/gateware/embedfire_rise_pro_utilization_place.rpt`
- `p0 trace 256` timing: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace/gateware/embedfire_rise_pro_timing.rpt`
- `p0 trace 512` utilization: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r512/gateware/embedfire_rise_pro_utilization_place.rpt`
- `p0 trace 512` timing: `D:/Code/research/rv-maltrace/vendor/litex/linux-on-litex-vexriscv/build/embedfire_rise_pro_trace_r512/gateware/embedfire_rise_pro_timing.rpt`

Rows marked BLOCKED have no routed utilization/timing evidence and cannot support hardware cost claims.
