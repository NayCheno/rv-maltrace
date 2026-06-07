# CVA6 Genesys 2 Phased Design And Acceptance

This document is the controlling staged plan for completing the CVA6 board
goals on Digilent Genesys 2. It does not replace the detailed runbooks in this
directory; it ties the board design choices, phase order, and acceptance gates
together so that later claims are backed by physical evidence.

## Completion Target

The Genesys 2 CVA6 work is complete only when the project has evidence for:

1. A reproducible baseline CVA6 bitstream for `xc7k325tffg900-2`.
2. Physical-board programming, clock/reset, UART, and bare-metal runtime
   evidence for the baseline bitstream.
3. A trace-enabled CVA6 board build that preserves the sideband/no-backpressure
   trace rule.
4. First-board trace export through a bounded BRAM ring plus ILA/JTAG or an
   equivalent JTAG-visible dump.
5. Board trace validation for the required syscall, trap, context, branch, and
   drop-accounting event families.
6. Linux boot and Linux syscall/behavior trace evidence before making any Linux
   behavior claim.

No CVA6 board PASS, trace PASS, or Linux behavior PASS is allowed without the
run-specific artifacts listed below.

## Fixed Hardware Design

The active board is Digilent Genesys 2 with `xc7k325tffg900-2`. The board is
powered from the external 12 V supply and programmed through the on-board USB
JTAG path.

Because the on-board USB-UART path is not used for this run, UART is routed to
an external 3.3 V USB-TTL adapter through PMOD JC:

| Signal | Board connector | FPGA pin | Host side | Notes |
| --- | --- | --- | --- | --- |
| `tx` | `JC1` | `AC26` | USB-TTL `RXD` | FPGA-to-host serial output |
| `rx` | `JC2` | `AJ27` | USB-TTL `TXD` | Host-to-FPGA serial input |
| `GND` | `JC5` or `JC11` | Board ground | USB-TTL `GND` | Required common ground |
| `3V3` | `JC6` or `JC12` | Board 3.3 V | Not connected | Do not power the board from USB-TTL |

The UART electrical rule is 3.3 V TTL only. A 5 V UART, RS-232 adapter, or a
USB D+/D- connection to the USB-TTL adapter is not acceptable.

The board-local smoke test in `fpga/genesys2/uart_ttl_test/` has already proven
that this wiring can carry `115200 8N1` traffic on `COM6`. That smoke test is a
hardware wiring check only; it is not CVA6 runtime evidence.

## Constraint Policy

The upstream CVA6 Genesys 2 constraint file remains the canonical baseline
constraint source:

```text
rtl/cva6/corev_apu/fpga/constraints/genesys-2.xdc
```

For this physical run, the UART constraints must be changed from the on-board
USB-UART pins:

```text
tx -> Y23
rx -> Y20
```

to the PMOD JC external USB-TTL pins:

```tcl
set_property -dict {PACKAGE_PIN AC26 IOSTANDARD LVCMOS33 DRIVE 8 SLEW SLOW} [get_ports tx]
set_property -dict {PACKAGE_PIN AJ27 IOSTANDARD LVCMOS33 PULLUP TRUE} [get_ports rx]
```

The UART constraint diff must be recorded in the board run evidence. Trace,
clock, DDR, JTAG, Ethernet, SPI, and SD constraints must not be changed in the
baseline phase unless a failed gate proves the need.

## Phase Order

### Phase 0: Board Wiring And Host Preflight

Purpose: prove that the physical connection can support the later CVA6 run.

Required actions:

- Confirm external 12 V power is on and the board reports a stable power state.
- Confirm Vivado can see `xc7k325t_0` through on-board JTAG.
- Confirm the external USB-TTL appears as `COM6`.
- Program `fpga/genesys2/uart_ttl_test/` and capture `RVMT JC UART TEST` plus
  a host-to-board echo such as `ping`.

Acceptance artifacts:

```text
results/board/genesys2_cva6_preflight/<run-id>/
  jtag_scan.log
  uart_ttl_test_program.log
  uart_ttl_test_capture.log
  observation.md
```

Pass condition: JTAG programming succeeds, UART receives deterministic test
text at `115200 8N1`, and a host-sent token is echoed.

### Phase 1: Repository And Vivado Preflight

Purpose: prove that local build inputs are authorized and internally
consistent before changing the board image.

Required commands:

```powershell
uv run rvmt vivado:check
uv run python tools/check_board_baseline.py
uv run python tools/check_vivado_authorization.py
```

Acceptance artifacts:

```text
results/board/genesys2_baseline/<run-id>/00_preflight/
  vivado_check.log
  board_baseline_check.log
  vivado_authorization_check.log
  git_status.txt
  observation.md
```

Pass condition: all three commands complete successfully, the Genesys 2 board
file is visible, and the target part/license gate is satisfied.

### Phase 2: Baseline CVA6 Bitstream With PMOD JC UART

Purpose: build the non-trace CVA6 image that will be physically validated.

Required actions:

- Apply only the UART constraint change described above.
- Build the baseline bitstream with the repository command:

```powershell
uv run rvmt bitstream:build
```

- Collect the generated bitstream, checkpoint, route/timing, and check-timing
  reports.

Acceptance artifacts:

```text
results/board/genesys2_baseline/<run-id>/01_bitstream_build/
  command.log
  constraint_diff.patch
  artifact_manifest.txt
  timing_summary.txt
  check_timing_summary.txt
  observation.md
```

Pass condition: `ariane_xilinx.bit` is generated for
`genesys2-cv64a6_imafdc_sv39`, implementation is routed, timing is met or any
known warnings are explicitly reconciled, and the UART constraint diff is the
only intended board-interface change.

### Phase 3: Baseline Board Programming And Clock/Reset

Purpose: prove that the generated baseline image can be loaded and reaches a
stable post-program board state.

Required actions:

- Program the Phase 2 bitstream through on-board JTAG.
- Record Vivado programming transcript.
- Observe reset release and stable board-visible status, such as LEDs or other
  documented signals.

Acceptance artifacts:

```text
results/board/genesys2_baseline/<run-id>/01_led_clock_reset/
  program.log
  board_observation.txt
  optional_photo_or_video.txt
  observation.md
```

Pass condition: Vivado reports `program_hw_devices` success for `xc7k325t_0`
and the board operator records a stable post-program state.

### Phase 4: Baseline UART And CVA6 Bare-Metal Runtime

Purpose: close the baseline CVA6 physical-board gate before trace work starts.

Required actions:

- Open `COM6` at `115200 8N1` before releasing reset or before the image starts.
- Capture the first deterministic baseline UART output.
- Boot a CVA6 bare-metal program with no trace modification.
- Capture the bare-metal end marker through UART, tohost/JTAG, or another
  documented board-visible signal.

Acceptance artifacts:

```text
results/board/genesys2_baseline/<run-id>/02_uart_hello/
  serial.log
  observation.md

results/board/genesys2_baseline/<run-id>/04_cva6_baremetal_boot/
  program_manifest.txt
  program_build.log
  serial_or_tohost.log
  observation.md
```

Pass condition: baseline UART output is visible on the PMOD JC USB-TTL path and
the bare-metal program reaches its expected end state. Trace-enabled RTL must
still be absent from this baseline run.

Stop rule: do not begin Phase 5 until Phases 1 through 4 are PASS. The minimal
core boot row in `baseline_bringup_runbook.md` may be recorded as `N/A` only if
the repository has no separate minimal-core image; it must not be counted as a
bare-metal CVA6 PASS.

### Phase 5: Trace-Enabled CVA6 Build

Purpose: integrate the first-board trace configuration without perturbing CVA6
commit behavior.

Design rules:

- Use the Phase 5.2 minimal trace profile in
  `board_trace_minimal.md`.
- Keep full retire disabled by default.
- Enable syscall, trap, context, branch, and drop-accounting events.
- Use drop mode instead of lossless backpressure.
- Export through bounded BRAM ring plus ILA/JTAG or an equivalent JTAG-visible
  dump.
- Do not add ready/stall/backpressure into CVA6 commit logic.

Required actions:

```powershell
uv run rvmt bitstream:build-trace
uv run python tools/generate_resource_report.py
```

Acceptance artifacts:

```text
results/board/genesys2_trace_validation/<run-id>/00_trace_build/
  command.log
  trace_constraint_diff.patch
  resource_report_excerpt.txt
  timing_summary.txt
  observation.md
```

Pass condition: the trace-enabled build routes successfully, timing/resource
evidence is collected, the UART remains on PMOD JC, and the trace export path
matches `trace_export_decision.md`.

### Phase 6: First Board Trace Validation

Purpose: prove that board trace packets match the first-board event policy.

Required validation programs:

| Order | Program | Required event evidence |
| ---: | --- | --- |
| 1 | `hello_write` | syscall `write` (`a7=64`) |
| 2 | `file_open_read_write` | `openat`, `read`, `write`, `close` |
| 3 | `fork_exec` | `clone`, `execve`, `wait4` |
| 4 | `illegal_instruction` | trap from illegal instruction |

Each program directory must contain:

```text
program.log
trace.jsonl
compare.log
observation.md
```

Pass condition: every required program has a board-exported `trace.jsonl`, the
trace contains only allowed first-board behavior event families plus drop
accounting, and `compare.log` reconciles the board event shape with the expected
file under `board/trace_validation/expected/`.

### Phase 7: Linux CVA6 Runtime And Behavior Trace

Purpose: support Linux syscall/behavior claims after the bare-metal trace path
is proven.

Required actions:

- Prepare the SD or boot media expected by the CVA6 FPGA boot flow.
- Capture Linux boot UART output on `COM6`.
- Run a minimal user-space workload set that covers the Linux behavior claims
  the project intends to make.
- Export and decode board traces into the project JSONL format.
- Compare recovered syscall/process/file behavior against expected manifests.

Acceptance artifacts:

```text
results/board/genesys2_linux_trace/<run-id>/
  00_linux_boot/
    boot_media_manifest.txt
    serial.log
    observation.md
  01_user_workloads/
    program_logs/
    trace_jsonl/
    compare_logs/
    observation.md
  run_summary.md
```

Pass condition: Linux boots on CVA6, user workloads complete, board traces are
decoded, and the project records which behavior claims are supported and which
remain out of scope.

## Acceptance Summary Matrix

| Gate | Required for CVA6 complete? | Evidence root | Pass meaning |
| --- | --- | --- | --- |
| Board wiring/JTAG/UART preflight | Yes | `results/board/genesys2_cva6_preflight/<run-id>/` | Host can program the board and use PMOD JC UART |
| Vivado/repository preflight | Yes | `results/board/genesys2_baseline/<run-id>/00_preflight/` | Local toolchain, board files, and target authorization are valid |
| Baseline bitstream build | Yes | `results/board/genesys2_baseline/<run-id>/01_bitstream_build/` | Non-trace CVA6 image is reproducibly built with PMOD JC UART |
| Baseline programming/clock/reset | Yes | `results/board/genesys2_baseline/<run-id>/01_led_clock_reset/` | Board accepts the bitstream and reaches a stable state |
| Baseline UART hello | Yes | `results/board/genesys2_baseline/<run-id>/02_uart_hello/` | CVA6 baseline emits visible UART output |
| CVA6 bare-metal boot | Yes | `results/board/genesys2_baseline/<run-id>/04_cva6_baremetal_boot/` | CVA6 runs a bare-metal program to completion |
| Trace-enabled build | Yes | `results/board/genesys2_trace_validation/<run-id>/00_trace_build/` | Trace hardware builds without violating sideband rules |
| Board trace validation programs | Yes | `results/board/genesys2_trace_validation/<run-id>/` | Required event families are observed and decoded from board traces |
| Linux boot and behavior trace | Required for Linux claims | `results/board/genesys2_linux_trace/<run-id>/` | CVA6 Linux/user-space behavior claims have board evidence |

## Claim Rules

- `PASS` means the named evidence exists in the run directory and the
  corresponding `observation.md` records `PASS`.
- `N/A` is allowed only for explicitly optional rows or for a documented
  missing image/tool that is not part of the claimed scope.
- `TODO (BOARD)` remains until physical-board logs are captured.
- A simulation, routed bitstream, or temporary UART smoke test is not a
  substitute for CVA6 board runtime evidence.
- Host software, QEMU, eBPF, or synthetic experiment evidence must not be
  described as CVA6 board evidence.

## Recommended Run ID Format

Use stable timestamped run IDs:

```text
YYYYMMDD-HHMM-<short-purpose>
```

Example:

```text
20260608-0100-pmod-jc-baseline
```

Each run should include a top-level `run_notes.md` listing hardware connections,
Vivado version, Git commit or working-tree status, bitstream path, serial port,
baud rate, and any deviations from this document.
