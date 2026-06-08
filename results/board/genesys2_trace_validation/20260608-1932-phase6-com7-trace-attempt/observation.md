# Genesys2 CVA6 Phase 6 COM7 Trace Attempt

Status: NOT PASS.

This run used the current host serial assignment `COM7` at `115200 8N1`.
`01_host_inventory/serial_ports.log` shows `USB Serial Port (COM7)` as the
present FTDI VCP device.

Board/JTAG/trace export:

- `00_trace_bitstream_program/program_trace_dynamic_com7.log` found hardware
  target `localhost:3121/xilinx_tcf/Digilent/200300B81858B` and
  `xc7k325t_0`.
- The Phase 5 trace bitstream and LTX were programmed from
  `build/vivado/genesys2-cv64a6_imafdc_sv39-trace/work-fpga/ariane_xilinx.bit`
  and `ariane_xilinx.ltx`.
- Vivado reported startup status HIGH and detected one live ILA core,
  `hw_ila_1`.
- `02_ila_capture/capture_ila_once.log` exported
  `02_ila_capture/ila_capture.csv` from probes `rvmt_trace_fire` and
  `rvmt_trace_probe_payload[103:0]`.
- `02_ila_capture/decode_ila_capture.log` decoded the capture to
  `02_ila_capture/trace.jsonl`.

Decoded trace summary:

- `02_ila_capture/event_summary.txt` records 228 decoded events.
- Event mix: 114 `JUMP`, 114 `RETIRE`.
- No `SYSCALL_ENTRY`, `SYSCALL_RET`, `TRAP`, `PRIV`, or drop-accounting events
  were observed in this capture.

Required Phase 6 comparisons:

- `compare_hello_write.log`: fails because `RETIRE` is present and the required
  `write` syscall entry/return events are missing.
- `compare_file_open_read_write.log`: fails because `RETIRE` is present and
  `openat`, `read`, `write`, and `close` syscall events are missing.
- `compare_fork_exec.log`: fails because `RETIRE` is present and `clone`,
  `execve`, `wait4`, and `PRIV` events are missing.
- `compare_illegal_instruction.log`: fails because `RETIRE` is present and the
  illegal-instruction `TRAP` event is missing.

UART/Linux workload:

- `00_trace_bitstream_program/serial.log` captured `COM7` during/after
  programming. It contains the capture header, one NUL byte, and no Linux boot
  or workload payload.
- `linux_boot_media_probe.log` and `build_boot_media_probe.log` found no
  Genesys2/CVA6 Linux boot image, DTB, rootfs, or initramfs in the repository or
  build tree. The only CVA6 runtime payload found is the Phase 4 bare-metal UART
  pass ELF/BIN under `build/board/genesys2_cva6_phase4/`.

Result:

Phase 6 remains blocked. The JTAG-visible ILA trace export is now proven on
board with a real CSV and decoded JSONL, but the required Linux user workloads
(`hello_write`, `file_open_read_write`, `fork_exec`, and
`illegal_instruction`) were not executed and their required per-program
`program.log`, board-exported `trace.jsonl`, `compare.log`, and
`observation.md` PASS artifacts were not produced.

Phase 7 was not started because Phase 6 did not PASS.
