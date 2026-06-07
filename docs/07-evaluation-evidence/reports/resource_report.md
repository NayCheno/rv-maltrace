# Resource Report

Phase 3.3 resource and timing snapshot.

## Source Reports

- Utilization: `build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.utilization.rpt`
- Timing: `build/vivado/genesys2-cv64a6_imafdc_sv39/reports/ariane.timing.rpt`
- Simulation summary: `results/vivado_sim/summary.json`

The Vivado numbers below are from the existing Genesys 2 routed `ariane_xilinx` report.
Trace-specific queue/drop rows are taken from current trace RTL parameters and the latest `sim:trace-unit` summary.

## Routed Utilization

| Design | Device | State | LUT | FF | RAMB36 | RAMB18 | BRAM18 equiv | DSP |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ariane_xilinx | xc7k325tffg900-2 | Routed | 84928 | 56491 | 53 | 2 | 108 | 27 |

## Timing

| Path group | Slack (ns) | Requirement (ns) | Target Fmax (MHz) | Approx. achieved Fmax (MHz) | Data path delay (ns) | Logic levels |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| mem_refclk | 0.177 | 1.250 | 800.0 | 932.0 | 1.183 | 0 |

Critical path:

- Source: `i_ddr/u_xlnx_mig_7_ddr3_mig/u_memc_ui_top_axi/mem_intfc0/ddr_phy_top0/u_ddr_mc_phy_wrapper/u_ddr_mc_phy/ddr_phy_4lanes_1.u_ddr_phy_4lanes/phy_control_i/MEMREFCLK`
- Destination: `i_ddr/u_xlnx_mig_7_ddr3_mig/u_memc_ui_top_axi/mem_intfc0/ddr_phy_top0/u_ddr_mc_phy_wrapper/u_ddr_mc_phy/ddr_phy_4lanes_0.u_ddr_phy_4lanes/phy_control_i/PHYCTLMSTREMPTY`

## Trace Queue And Drop

| Item | Value |
| --- | ---: |
| `rtl/trace/trace_top.sv` EVENT_QUEUE_DEPTH | 8 |
| `rtl/trace/trace_top.sv` PIPELINE_INPUTS | 1 |
| `rtl/trace/cva6_rvfi_trace_adapter.sv` EVENT_QUEUE_DEPTH | 16 |
| `rtl/trace/cva6_rvfi_trace_adapter.sv` PIPELINE_INPUTS | 1 |
| Simulation overall | PASS |
| Max DROP test | backpressure |
| Max DROP records | 7 |
| Max dropped event count | 18 |

Drop rows:

| Test | Status | DROP records | Dropped event count |
| --- | --- | ---: | ---: |
| backpressure | PASS | 7 | 18 |

## Trace-Enabled FPGA Delta

- Trace utilization: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.utilization.rpt`
- Trace timing: `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/ariane.timing.rpt`

| Metric | Baseline | Trace-enabled | Delta |
| --- | ---: | ---: | ---: |
| LUT | 84928 | 125731 | +40803 (+48.04%) |
| FF | 56491 | 59301 | +2810 (+4.97%) |
| BRAM18 equiv | 108 | 108 | +0 (+0.00%) |
| DSP | 27 | 27 | +0 (+0.00%) |
| Slack (ns) | 0.177 | 0.177 | 0.000 |
| Approx. achieved Fmax (MHz) | 932.0 | 932.0 | 0.0 |
