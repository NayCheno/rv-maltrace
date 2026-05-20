# Artix-7 35T Bring-up Runbook

This document records the low-cost Artix-7 35T path for RV-MalTrace on the
EmbedFire Shengteng Pro A35T board. It is a board-specific experiment track, not
a replacement for the current CVA6 + Genesys 2 evidence path.

All physical-board rows remain `TODO (BOARD)` until run-specific artifacts exist
under `results/board/artix7_35t_litex/<run-id>/`.

## Source Material

Board facts in this document come from:

| Source | Use |
| --- | --- |
| `docs/board/artix7_35t_pinmap.xlsx` | Pin map for clock, DDR3, reset, keys, LEDs, USB-UART, SD, and other peripherals |
| `docs/board/artix8_35t_hw_spec.pdf` | Hardware specification currently present in this repository |

The user referred to `docs/board/artix7_35t_hw_spec.pdf`, but the current
repository file is named `docs/board/artix8_35t_hw_spec.pdf`. Treat that PDF as
the local hardware-spec source for this runbook unless a correctly named
replacement is added later. Do not rename it as part of this documentation-only
step.

## Board Identity

This path targets the EmbedFire Shengteng Pro carrier with an Artix-7 35T core
module:

| Item | Value |
| --- | --- |
| FPGA | Xilinx `XC7A35T-FGG484-2` |
| System clock | 50 MHz active oscillator, `FPGA_CLK=W19` |
| DDR3 | Two `MT41K256M16TW-107` devices, 1 GByte total, 32-bit data width |
| Flash | 128 Mbit SPI flash |
| Primary UART | On-board CH340 USB-UART |
| Primary UART pins | `UART1_RX=P17`, `UART1_TX=N17` |
| Default UART settings | 115200 baud, 8N1 for recovery; explicit 35T fast runs use 921600 baud, 8N1 |
| Reset/key pins | `RESET=N15`, `KEY1=V17`, `KEY2=W17`, `KEY3=AA18`, `KEY4=AB18` |
| User LEDs | `LED1=M21`, `LED2=L21`, `LED3=K21`, `LED4=K22` |
| JTAG | Vivado-compatible external JTAG header/download probe |

The board has DDR3, so the Linux-capable LiteX/VexRiscv path remains viable.
The first bring-up still proves clock, reset, JTAG, UART, and DDR before any
Linux or trace instrumentation work.

The board exposes expansion IO. For `XC7A35T`, the hardware specification notes
that the CN3 expansion connector is not usable because it is tied to Bank 13,
which is absent on the 35T variant. Keep the first bring-up on the documented
clock, reset, CH340 UART, LEDs, and DDR pins.

## Recommendation

Use the Artix-7 35T board for a LiteX/VexRiscv prototype first:

```text
EmbedFire Shengteng Pro A35T
  -> LiteX SoC
  -> VexRiscv or VexRiscv SMP
  -> LiteDRAM-backed DDR3
  -> minimal syscall/trap/context trace adapter
  -> bounded trace buffer / LiteX CSR export
  -> existing RV-MalTrace JSONL parser and behavior recovery tools
```

Do not target CVA6 on Artix-7 35T as the first implementation. The current CVA6
board path is sized around Genesys 2-class resources, DDR integration, and the
existing Vivado evidence flow. Forcing CVA6 into 35T would likely spend the
project budget on SoC/resource/timing reduction instead of trace semantics.

## Repository Inputs

The Artix-7 35T track expects these local dependencies to be available as
submodules or pinned external inputs:

| Path | Role |
| --- | --- |
| `rtl/vex-riscv` | Local VexRiscv source anchor for trace-adapter study and version locking |
| `vendor/litex/litex` | LiteX SoC builder and integration framework |
| `vendor/litex/litex-boards` | Board platform and target definitions to adapt or extend for this board |
| `vendor/litex/migen` | LiteX Python HDL dependency |
| `vendor/litex/litedram` | DDR controller path required for Linux-capable bring-up |
| `vendor/litex/pythondata-cpu-vexriscv_smp` | LiteX-packaged VexRiscv SMP CPU data |
| `vendor/litex/linux-on-litex-vexriscv` | Linux boot flow reference, including kernel/rootfs/OpenSBI conventions |

Do not vendor Linux kernel or Buildroot as submodules during the first bring-up
stage. Record exact versions in `docs/process/version_lock.md` or a future
Artix-7-specific lock file once the boot flow is selected.

## Primary UART Policy

Use the on-board CH340 USB-UART as the default bring-up UART. Open it before
programming or reset release so the first BIOS/boot characters are captured.

The local connected board has been enumerated as `USB-SERIAL CH340 (COM5)`.
Keep the global default at `115200 8N1` for recovery compatibility, but the
preferred 35T Linux serialboot run explicitly passes `--baud 921600` to every
LiteX/Vivado/serialboot step. If 921600 baud is unstable, retry in this fixed
order before changing transport: `460800`, then `230400`, then `115200`.

The current ram0 Linux payload set is about 19.25 MB. At 921600 baud the raw
8N1 wire-time lower bound is about 3.5 minutes; actual time is higher because
LiteX serialboot frames, ACKs, and CRC retries add overhead. The host loader
must log total bytes, progress, measured throughput, and CRC retry count for
each upload.

On the 2026-05-20 `COM5` CH340 run, the 19,261,049-byte payload took about
1,620 seconds at 921600 baud with 0 CRC retries and about 11.8 KiB/s measured
throughput. That points to SFL small-frame ACK/host-USB latency rather than a
baud-rate error. Keep serialboot as the known-good fallback, but use a 3600 s
timeout for full ram0 Linux uploads until SD or Ethernet/TFTP boot is enabled.
Interactive Linux shell commands at 921600 baud also need pacing; the CLI
defaults to a small per-character delay for `--send` and `trace-dump`.

Evidence must record:

- Windows serial device name, for example `COMx`.
- Baud rate and framing, default `115200 8N1`.
- Whether the captured direction matches the design's `uart_tx` and `uart_rx`
  naming.
- Raw UART log with timestamps when available.

An external CMOS UART may be used only as a documented backup. It must be 3.3 V
TTL-level compatible, and the run notes must record the actual FPGA/CN connector
pins before any evidence row is promoted.

## Minimal XDC Seed

Use this as the first local constraint seed for LED, UART, and clock/reset
sanity. Keep peripheral constraints out of the first pass unless the selected
LiteX target requires them.

```xdc
## 50 MHz system clock
set_property PACKAGE_PIN W19 [get_ports clk50]
set_property IOSTANDARD LVCMOS33 [get_ports clk50]
create_clock -name clk50 -period 20.000 [get_ports clk50]

## Program reset button
set_property PACKAGE_PIN N15 [get_ports reset_n]
set_property IOSTANDARD LVCMOS33 [get_ports reset_n]

## On-board CH340 USB-UART
## Confirm logical RX/TX direction in the first UART hello run.
set_property PACKAGE_PIN P17 [get_ports uart_rx]
set_property IOSTANDARD LVCMOS33 [get_ports uart_rx]
set_property PACKAGE_PIN N17 [get_ports uart_tx]
set_property IOSTANDARD LVCMOS33 [get_ports uart_tx]

## User LEDs
set_property PACKAGE_PIN M21 [get_ports {led[0]}]
set_property PACKAGE_PIN L21 [get_ports {led[1]}]
set_property PACKAGE_PIN K21 [get_ports {led[2]}]
set_property PACKAGE_PIN K22 [get_ports {led[3]}]
set_property IOSTANDARD LVCMOS33 [get_ports {led[*]}]
```

First-pass deferred interfaces:

- HDMI input/output
- Ethernet
- PCIe
- SD card
- Camera
- LCD
- SFP/GTP
- CN3 expansion IO on `XC7A35T`

## DDR3 Pin Anchor

The board has a 32-bit DDR3 interface. The first LiteX target must use a DDR3
configuration consistent with the hardware spec and pin map.

Key DDR3 anchors:

| Signal group | Pins |
| --- | --- |
| Address | `DDR3_A0=AA4` through `DDR3_A14=V3` |
| Bank address | `DDR3_BA0=AA1`, `DDR3_BA1=Y3`, `DDR3_BA2=AA3` |
| Control | `DDR3_CSN=T1`, `DDR3_RASN=W6`, `DDR3_CASN=U5`, `DDR3_WEN=Y4`, `DDR3_ODT=T5`, `DDR3_CKE=AB5`, `DDR3_RESET=R3` |
| Clock | `DDR3_CLK0_P=V4`, `DDR3_CLK0_N=W4` |
| Data | `DDR3_D0=C2` through `DDR3_D31=P2` |
| Strobes | `DDR3_DQS0_P=E1`, `DDR3_DQS0_N=D1`, `DDR3_DQS1_P=K2`, `DDR3_DQS1_N=J2`, `DDR3_DQS2_P=M1`, `DDR3_DQS2_N=L1`, `DDR3_DQS3_P=P5`, `DDR3_DQS3_N=P4` |
| Masks | `DDR3_DM0=D2`, `DDR3_DM1=G2`, `DDR3_DM2=M2`, `DDR3_DM3=M5` |

The full DDR3 constraint set should be generated by the selected LiteX/LiteDRAM
platform target, not manually copied from this table into unrelated designs.

## Candidate Cores

| Core | Artix-7 35T fit | Use in this project |
| --- | --- | --- |
| VexRiscv SMP / LiteX | HIGH | Preferred Linux-capable prototype path. Use RV32 Linux to validate syscall/context trace flow and host tooling. |
| VexRiscv single-core / LiteX | HIGH | Fallback if SMP does not meet area, timing, or stability gates. |
| Ibex | HIGH | Good bare-metal trace tap and export-path prototype. Not enough for Linux malware behavior reconstruction. |
| VeeR EH1 / SweRVolf | MEDIUM | Good bare-metal or RTOS trace prototype. Not the primary Linux path. |
| Rocket-on-LiteX | LOW/MEDIUM | Possible as an experiment, but too tight and fragile for the first board milestone. |
| CVA6 | LOW | Keep on Genesys 2 or larger FPGA. Do not spend the 35T path on CVA6 resource closure. |
| BOOM / XiangShan | NO | Resource footprint is outside the practical 35T target. |

## Evidence Layout

Use one run directory per physical-board attempt:

```text
results/board/artix7_35t_litex/<run-id>/
  00_board_identity/
  01_vivado_jtag/
  02_led_clock_reset/
  03_uart_hello/
  04_litex_ddr/
  05_baremetal/
  06_linux_boot/
  07_trace_minimal/
  08_trace_jsonl_compare/
  run_notes.md
```

Each step directory should contain command transcripts, raw UART/JTAG logs when
applicable, relevant Vivado/resource/timing summaries, and an `observation.md`
with `PASS`, `FAIL`, or `N/A` plus the reason. `N/A` is allowed only for
explicitly optional steps or for a documented unavailable image.

## Current 35T Command Sequence

Use this sequence for the connected CH340 on `COM5`:

```text
uv run rvmt board:artix7:jtag-scan --port COM5
uv run rvmt board:artix7:led-build --port COM5
uv run rvmt board:artix7:led-load --port COM5
uv run rvmt board:artix7:litex-build --port COM5 --baud 921600
uv run rvmt board:artix7:litex-load --port COM5 --baud 921600
uv run rvmt board:artix7:serial-capture --port COM5 --baud 921600 --board-step 04_litex_ddr
uv run rvmt board:artix7:baremetal-build --port COM5 --baud 921600
uv run rvmt board:artix7:baremetal-run --port COM5 --baud 921600
uv run rvmt board:artix7:linux-images-prep --port COM5 --baud 921600
uv run rvmt board:artix7:linux-build --port COM5 --baud 921600
uv run rvmt board:artix7:linux-load --port COM5 --baud 921600
uv run rvmt board:artix7:linux-boot-capture --port COM5 --baud 921600 --duration 3600
uv run rvmt board:artix7:trace-build --port COM5 --baud 921600
uv run rvmt board:artix7:trace-load --port COM5 --baud 921600
uv run rvmt board:artix7:linux-boot-capture --port COM5 --baud 921600 --duration 3600
uv run rvmt board:artix7:trace-dump --port COM5 --baud 921600 --duration 60 --trace-records 128
uv run rvmt board:artix7:trace-jsonl-compare --port COM5 --baud 921600
```

All LiteX build/load wrappers must pass `--uart-baudrate` matching `--baud`.
The trace dump command reads the `rvmt_trace` CSR base from the generated
`csr.csv`, clears the ring, runs `/usr/bin/rvmt_linux_user_pass`, and sends
`/usr/bin/rvmt_trace_dump <csr-base> <records>` through the paced Linux serial
console. The second `linux-boot-capture` is required after `trace-load` because
programming the trace bitstream resets the SoC and the ram0 Linux payload must
be uploaded again.

## Bring-up Sequence

### 0. Board Identity

Goal: record the board and local tool context before programming.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/00_board_identity/
```

Procedure:

1. Record board model, FPGA marking, DDR part/capacity, and serial/JTAG adapter
   identifiers.
2. Record Vivado version and host OS.
3. Record source material versions and note the local PDF filename mismatch.
4. Confirm the primary UART path is the board CH340.

Pass evidence:

- `observation.md` with board identity and tool versions.
- Optional board photos or adapter notes.

### 1. Vivado / JTAG Visibility

Goal: prove Vivado can see the Artix-7 35T target through the connected
download probe.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/01_vivado_jtag/
```

Procedure:

1. Power the board from a stable supply.
2. Start Vivado `hw_server`.
3. Open the hardware target.
4. Confirm the detected device is compatible with `xc7a35t`.
5. Save the Vivado hardware-target transcript.

Pass evidence:

- Hardware manager or batch transcript showing the target scan.
- `observation.md` identifying the detected FPGA and JTAG probe.

### 2. LED / Clock / Reset Sanity

Goal: verify the 50 MHz clock, reset input, programming path, and basic outputs
before loading a SoC.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/02_led_clock_reset/
```

Procedure:

1. Build or use a minimal LED blink design constrained to `clk50`, `reset_n`,
   and `led[3:0]`.
2. Program the bitstream through Vivado.
3. Observe LED activity and reset behavior.
4. Save programming logs and any timing/utilization summary.

Pass evidence:

- Vivado programming transcript with successful `program_hw_devices`.
- `observation.md` describing stable LED and reset behavior.

### 3. UART Hello

Goal: prove the CH340 serial path and resolve logical TX/RX direction.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/03_uart_hello/
```

Procedure:

1. Open the board CH340 serial port at `115200 8N1`.
2. Program a minimal UART hello design or LiteX BIOS-only bitstream.
3. Capture the first deterministic UART output.
4. If no output appears, swap logical UART direction in the design constraints
   only after recording the failed attempt.

Pass evidence:

- Raw UART log.
- Programming transcript.
- `observation.md` recording serial device, baud rate, and confirmed TX/RX
  direction.

### 4. LiteX DDR Baseline

Goal: build a no-trace LiteX SoC and prove DDR before Linux.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/04_litex_ddr/
```

Initial configuration:

- CPU: VexRiscv or VexRiscv SMP, starting from the smallest Linux-capable
  configuration that fits.
- Clock input: 50 MHz `FPGA_CLK=W19`.
- Memory: LiteDRAM-backed external DDR3.
- Peripherals: UART, timer, interrupt controller, CSR bridge, LEDs.
- Deferred peripherals: Ethernet, SDCard, DMA, HDMI, PCIe, and high-bandwidth
  trace export.

Procedure:

1. Add or adapt a LiteX platform/target for this board using the documented pin
   map.
2. Build the no-trace SoC.
3. Generate the Vivado bitstream.
4. Program the board.
5. Run the LiteX BIOS DDR memory test.

Pass evidence:

- Build command transcript.
- Vivado utilization, route, timing, and bitstream path.
- Raw UART BIOS log showing DDR memory test result.

### 5. Minimal Bare-metal Program

Goal: run a small non-Linux program before booting Linux or enabling trace.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/05_baremetal/
```

Procedure:

1. Build a tiny bare-metal program for the selected LiteX CPU configuration.
2. Load it through the LiteX BIOS or selected host loader.
3. Capture a deterministic UART completion marker.

Pass evidence:

- Program source or image identifier.
- Build/load transcript.
- Raw UART log showing the completion marker.

### 6. Linux Boot

Goal: reach userspace before adding trace instrumentation.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/06_linux_boot/
```

Procedure:

1. Use `vendor/litex/linux-on-litex-vexriscv` as the reference flow.
2. Prefer downloaded/pinned kernel, OpenSBI, and rootfs artifacts over adding
   kernel or Buildroot submodules.
3. Record Linux kernel, OpenSBI, rootfs, LiteX, VexRiscv, and Vivado versions.
4. If SMP does not fit or is unstable, fall back to a single-core Linux-capable
   VexRiscv configuration and record the decision.
5. Boot to userspace and run a tiny user program.

Pass evidence:

- Raw UART boot log with CPU, memory, and init/userspace evidence.
- Artifact/version manifest.
- User program log.

### 7. Minimal Trace Tap

Goal: connect the Artix-7 35T path to the existing RV-MalTrace event contract
without attempting full trace bandwidth.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/07_trace_minimal/
```

First events:

- syscall entry
- syscall return with bounded duration when a tracked user syscall returns
- trap/exception
- privilege/context events when available
- drop/overflow accounting

Deferred events:

- full retire stream
- full branch stream
- load/store address/data stream
- user-pointer memory snapshot

Procedure:

1. Add the VexRiscv/LiteX trace adapter as a separate module or integration
   shim.
2. Reuse `rtl/trace/trace_pkg.sv` and the existing JSONL schema.
3. Keep CVA6 signal semantics intact; do not weaken
   `docs/architecture/signal_map.md` to fit LiteX.
4. Keep the trace sink non-intrusive. If the buffer fills, drop records and
   account for `EVT_DROP`; do not stall the CPU or Linux memory path.

Pass evidence:

- Simulation or board log showing packet shape compatibility with
  `docs/architecture/trace_format.md`.
- Drop-accounting evidence for overflow behavior.

The Artix-7 raw dump uses 16 little schema words per record before JSONL
conversion:

| Word | Meaning |
| --- | --- |
| 0 | Header: event id, current privilege, old privilege, new privilege |
| 1 | Capture cycle |
| 2 | PC |
| 3 | Instruction |
| 4 | Trap cause or return/context target |
| 5 | Trap tval or syscall duration |
| 6 | Syscall sequence id |
| 7 | Drop counter snapshot |
| 8..15 | Shadowed `a0` through `a7` |

### 8. Trace Dump / JSONL Compare

Goal: dump a small board trace into the existing parser/checker pipeline.

Evidence directory:

```text
results/board/artix7_35t_litex/<run-id>/08_trace_jsonl_compare/
```

Preferred export order:

1. LiteX CSR-readable bounded trace ring.
2. BRAM ring buffer with host-side dump.
3. UART dump for very small smoke traces only.

Deferred exports:

- Ethernet streaming
- AXI DMA
- continuous high-bandwidth trace

Initial workloads:

- hello/syscall smoke
- open/read/write/close
- illegal-instruction trap
- fork/exec if Linux boot is stable enough
- anti-debug-like syscall sequence

Pass evidence:

- Raw hardware trace dump.
- Converted JSONL trace.
- `tools/parse_trace.py` output.
- `tools/compare_trace.py` or board-specific checker output.
- Behavior recovery summary when applicable.

## First Evidence Gates

| Gate | Status | Required evidence |
| --- | --- | --- |
| Board identity recorded | TODO (BOARD) | Board model, FPGA part, DDR3 facts, CH340 serial path, Vivado version |
| Vivado/JTAG target visible | TODO (BOARD) | Hardware-target transcript identifying the Artix-7 35T device |
| LED/clock/reset sanity passes | TODO (BOARD) | Programming transcript plus observation notes |
| CH340 UART console works | TODO (BOARD) | Raw UART log at `115200 8N1` and confirmed TX/RX direction |
| LiteX baseline bitstream builds | TODO | Build log, utilization, timing, and generated bitstream path under `build/` |
| LiteX DDR memory test passes | TODO (BOARD) | UART BIOS log with DDR memory test result |
| Minimal bare-metal program runs | TODO (BOARD) | Build/load transcript and UART completion marker |
| Linux boots on VexRiscv | TODO (BOARD) | Linux boot log with CPU, memory, init/userspace evidence |
| Minimal trace path simulates | TODO | Simulation or LiteX verilator log for trace packet shape |
| Minimal trace path runs on board | TODO (BOARD) | Captured trace dump plus parsed JSONL |
| Trace comparison passes | TODO (BOARD) | `tools/compare_trace.py` or board-specific checker output |

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
