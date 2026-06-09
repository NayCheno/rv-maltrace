Status: PASS

# Genesys2 CVA6 Phase 3 Observation

Run ID: 20260609-1440-onboard-uart-reroute
Timestamp:
2026-06-09 15:48 +08:00

## Evidence

- program.log: Vivado opened Digilent target localhost:3121/xilinx_tcf/Digilent/200300B81858B, selected xc7k325t_0, loaded the onboard-COM7 baseline bitstream, reported startup status HIGH, completed program_hw_devices, refreshed the hardware device, and printed RVMT_PROGRAM_DONE=xc7k325t_0.
- board_observation.txt: post-program stability notes for this run.
- optional_photo_or_video.txt: records that no photo or video was captured.

## Acceptance

Phase 3 passes because Vivado successfully programmed the onboard-COM7 baseline bitstream through on-board JTAG, reported startup status HIGH, and the hardware target remained visible after refresh. This establishes a stable post-program baseline for the COM7 UART capture in Phase 4.
