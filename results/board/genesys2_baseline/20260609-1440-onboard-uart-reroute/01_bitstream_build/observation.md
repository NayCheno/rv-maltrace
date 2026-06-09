# Genesys2 CVA6 Phase 2 Observation

Status: PASS

Run ID: 20260609-1440-onboard-uart-reroute
Timestamp:
2026-06-09 15:44:15 +08:00

## Change

- Updated rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc inside the CVA6 submodule so CVA6 UART tx uses onboard USB-UART Y23 and rx uses onboard USB-UART Y20.
- constraint_diff.patch records the two-line UART-only constraint diff from PMOD JC AC26/AJ27 back to the onboard USB-UART pins Y23/Y20.
- This reroute replaces the earlier PMOD JC path because the working host-side serial path for continued bring-up is the board FTDI USB-UART on COM7.

## Build Evidence

- Command: uv run rvmt bitstream:build, see command.log.
- artifact_manifest.txt records bitstream, MCS, DCP, project, report, and generated IP artifact sizes and mtimes.
- timing_summary.txt records the routed timing summary; worst reported slack is 0.177 ns MET.
- check_timing_summary.txt records the check_timing bucket counts.
- route_status_summary.txt records the routed-net completion summary.
- post_build_board_baseline_check.log records a passing run of uv run python tools/check_board_baseline.py after the rebuild.

## Result

- ariane_xilinx.bit generated under build/vivado/genesys2-cv64a6_imafdc_sv39/work-fpga/ with size 11,443,738 bytes and SHA256 1B1098BA888ABC2ABDECA6CF4B7729ECBCED62C7E2342FBB85D897C71AB37D08.
- ariane_xilinx.mcs generated with SHA256 8F2A9525696C18325DB4BF67B6D8DE91BEC2E73E96439A7D87AC3A5FA51512B4.
- Routed timing is Slack (MET) 0.177 ns.
- Route status is 130,576/130,576 routable nets fully routed with 0 routing errors.
- tools/check_board_baseline.py passed after the rebuild; known check_timing warning classes remain documented WARN rows rather than build failures.
- The first forced rebuild attempt failed only at MIG generated-file rename on Windows; after cleaning generated MIG artifacts and retrying, Vivado completed synth, place, route, bitgen, and cfgmem generation without RTL/XDC errors.

## Acceptance

Phase 2 passes for the onboard COM7 reroute. The baseline CVA6 image was rebuilt after returning UART to the board USB-UART pins, and generated bitstream, MCS, DCP, project, reports, and Vivado caches remain build artifacts rather than source files.
