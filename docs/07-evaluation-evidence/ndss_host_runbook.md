# NDSS Host Runbook

Status: `HOST_SMOKE_EXECUTED_EXTERNAL_CLOSURE_OPEN`

Vivado, Genesys2/JTAG/UART, and LaTeX are host-side steps. Python, RISC-V
Linux tooling, QEMU, strace, eBPF, experiment packaging, and analysis should run
through Docker unless a checker explicitly documents a host-only dependency.

## Executed Host Evidence

- `uv run rvmt vivado:check` passed on the host.
- Vivado 2025.2 rebuilt the trace-marker Genesys2/CVA6 image with routed timing
  WNS `0.177 ns`.
- The trace-marker bitstream was programmed to Genesys2 target
  `Digilent/200300B81858B`, device `xc7k325t_0`, through
  `tools/program_genesys2_bitstream.tcl`. The Vivado refresh reported one ILA
  core and `RVMT_PROGRAM_DONE`.
- `uv run rvmt ndss:jtag-ram-boot-probe` ran a read-only Vivado Hardware
  Manager inventory against the same target. It observed the JTAG target,
  `xc7k325t_0`, and `hw_ila_1`, but no `hw_axis`, `hw_axi`, or `hw_mem`
  memory-control object. The canonical summary is
  `results/evaluation/genesys2-cva6/current/jtag_ram_boot_probe_summary.json`
  with status `BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL`; no FPGA programming,
  reset, memory write, RAM boot, kernel update, SD-card modification, or board
  boot is claimed. A non-SD kernel update path requires a future bitstream that
  exposes a real memory-control/hart-control path and then passes
  `uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root . --require-ram-control`.
- UART boot/login on COM7 reached Buildroot Linux
  `Linux buildroot 6.19.6 #1 Tue Jun 9 06:02:04 UTC 2026 riscv64`.
- A non-destructive host disk discovery on 2026-06-24 found only the system NVMe
  disk and two 1 TB USB disks; no small removable Genesys2 SD-card target was
  safely identifiable, so `build/linux/genesys2-cva6/sdcard.img` was not written
  to physical media.
- `uv run rvmt ndss:sdcard-write-preflight --image build/linux/genesys2-cva6/sdcard.img`
  repeated that discovery as a current artifact-backed checker. It wrote
  `results/evaluation/genesys2-cva6/current/sdcard_write_preflight_summary.json`
  with status `BLOCKED_NO_SAFE_SDCARD_TARGET`: disk 0 is the boot/system NVMe,
  and disks 1/2 are USB devices larger than the 128 GiB SD-card safety limit.
  The summary records the SD image SHA256
  `be3bf82f7c0fea386e3d1748e8c5bf72c5849ffc1344b9820f60772d39c87c79`.
  No physical SD-card write, board boot, live kernel config export, or
  cycle-source claim is made by this preflight.
- Strict-SRET `hello_write/rep_02` was rerun on the current trace-marker
  bitstream after transferring the exact board ELF to `/tmp/rvmt_p0/hello_write`.
  `results/evaluation/genesys2-cva6/current/strict_sret_board_smoke_summary.json`
  is now `PASS`: it binds the current bitstream/LTX hashes, JTAG programming
  summary, board ELF transfer hash, UART `rc=0`, ILA capture log, BRAM records,
  strict syscall-id entry/return pair, trap and privilege-transition events,
  sequence continuity, wrap=0, and drop=0. It remains a one-sample smoke and
  does not replace the full P0 repetition cohort or claim SD-card-image boot,
  cycle-source availability, runtime overhead, production streaming/DMA
  throughput, or real-malware validation.
- `uv run rvmt ndss:host-latex` passed on the host and wrote
  `build/latex/ndss2026/latex_build_summary.json`. Current PDF SHA256:
  `d1492f316814325fcbe804b4160c6eb0f6fbbf5b8d05ff2e21e7228c88b3c33c`.
- `uv run python tools/build_genesys2_cycle_counter_smoke.py` built a
  freestanding Linux/RISC-V `rdcycle` smoke ELF in Docker. Current ELF SHA256:
  `d0f8b7266628e7cd93da070d843a685e5177016d32481503019d42d46ab211bf`.
- `qemu-riscv64 build/board/genesys2_cycle_counter_smoke/cycle_counter_smoke.riscv64`
  produced five positive `RVMT_CYCLE_SMOKE` rows in Docker/QEMU. This is a
  program/parser smoke only, not board overhead evidence.
- `uv run python tools/run_genesys2_cycle_counter_smoke.py --skip-build --port COM7 --baud 115200 --reps 5 --iters 10000 --minimum-repetitions 5`
  completed the live Genesys2 UART transfer and verified the board-side ELF
  SHA256, then blocked during execution because user-mode `rdcycle` raised an
  illegal-instruction trap. The run wrote
  `results/evaluation/genesys2-cva6/current/cycle_counter_smoke_summary.json`
  with status `BLOCKED_BOARD_RDCYCLE_UNAVAILABLE`; no board rdcycle PASS or
  runtime-overhead claim is made from that attempt.
- `uv run python tools/run_genesys2_cycle_source_probe.py --skip-build --port COM7 --baud 115200 --reps 5 --iters 10000 --minimum-repetitions 5`
  completed the live Genesys2 UART transfer and verified the board-side ELF
  SHA256, then blocked during execution because `perf_event_open` returned
  `-38` for `PERF_COUNT_HW_CPU_CYCLES`. The run wrote
  `results/evaluation/genesys2-cva6/current/cycle_source_probe_summary.json`
  with status `BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE`; no kernel-perf
  cycle-source PASS or runtime-overhead claim is made from that attempt.
- `uv run python tools/run_genesys2_counter_access_matrix.py --skip-build --port COM7 --baud 115200 --reps 5 --iters 10000 --minimum-repetitions 5`
  ran on the live SD-card Buildroot Linux image. The transferred static ELF
  SHA256 was `979ab06cac0a0ed1693da3682deaea5bae2488f9d6c36cdc6daba0340f0a22e4`.
  The board reported user `rdcycle` and `rdinstret` as illegal instructions,
  but user `rdtime` and Linux `clock_gettime` were available. The run wrote
  `results/evaluation/genesys2-cva6/current/counter_access_matrix_summary.json`
  with status `BLOCKED_BOARD_CYCLE_COUNTER_UNAVAILABLE_NONCYCLE_TIME_AVAILABLE`;
  no cycle-level overhead or production slowdown claim is made from the
  non-cycle timing sources.
- `uv run rvmt ndss:cycle-diagnostics --port COM7 --baud 115200` captured an
  expanded live SD-card Linux preflight. It confirmed Linux 6.19.6, root shell,
  `zicntr`/`zihpm` in `/proc/cpuinfo`, no `/proc/sys/kernel/perf_event_paranoid`,
  no `/sys/bus/event_source/devices`, no observed SBI PMU, no PMU/perf
  device-tree node, no readable kernel config, no `/lib/modules/6.19.6`, and
  retained prior user `rdcycle` illegal-instruction traps. The checker accepts
  this as a truthful `BLOCKED_BOARD_KERNEL_PMU_AND_USER_CYCLE_UNAVAILABLE`
  diagnostic, not a cycle-source PASS.
- `uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200` captured
  a live SD-card Linux identity manifest over COM7. The current manifest records
  Buildroot Linux 6.19.6, root shell, 7 rootfs identity hash rows, 3 DTB
  identity hash rows, missing `/boot`, missing readable kernel config, and raw
  UART log metadata.
  This is a live booted-image identity artifact only; it is not a
  Buildroot/OpenSBI/kernel/SD-card rebuild source path and does not claim a
  board cycle source.
- `uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200`
  attempted to export the readable live kernel config from the same board image.
  It wrote `live_kernel_config_export_summary.json` with status
  `BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE`; `/proc/config.gz`,
  `/boot/config-6.19.6`, and `/lib/modules/6.19.6/build/.config` were all
  missing. The raw UART log metadata is recorded in the current summary.
- `uv run rvmt ndss:linux-counter-preflight` records the repository-local
  counter-path rebuild state in
  `results/evaluation/genesys2-cva6/current/linux_counter_path_preflight.json`.
  The current status is `BLOCKED_SD_CARD_LINUX_SOURCE_MISSING`: the repo now
  contains a source-lock entrypoint, Genesys2/CVA6 Buildroot defconfig, Linux
  counter/perf config, OpenSBI source manifest, Docker-built OpenSBI/Linux
  payload, local GPT SD-card image manifest, live SD-card identity manifest, and
  source-level PMU DTS template. The remaining missing anchor is the live
  kernel-config export from a rebuilt board image. These source/build inputs do
  not prove that a physical SD card was written, that Genesys2 booted the new
  image, or that the live board exposes PMU/SBI PMU.
- `uv run rvmt ndss:linux-rebuild-prep --fetch --configure` runs the
  Docker-side Buildroot/OpenSBI rebuild preparer. It writes
  `linux_rebuild_manifest.json`; preparation does not claim a boot payload.
  Add `--execute` only for the long full build, and only a hash-bound
  `fw_payload.bin` can become `PASS_LINUX_PAYLOAD_BUILT`.
- `uv run rvmt ndss:boot-sdcard-image --payload <fw_payload.bin>` creates the
  local GPT SD-card image layout expected by the CVA6 bootrom after a real
  OpenSBI/Linux boot payload exists. The first GPT partition is the payload
  loaded to `0x80000000`; optional rootfs content is placed after it. Run
  `uv run python tools/check_genesys2_boot_sdcard_image.py --root .` after image
  generation. This step is not a Buildroot/OpenSBI compile, physical SD-card
  write, live boot, kernel config export, or cycle-source proof by itself.
- `uv run rvmt ndss:sdcard-write-preflight --image build/linux/genesys2-cva6/sdcard.img`
  runs a read-only host `Get-Disk` inventory and verifies that any target disk is
  explicit, non-boot, non-system, online, writable, large enough for the image,
  and below the configured SD-card size limit. Run
  `uv run python tools/check_genesys2_sdcard_write_preflight.py --root .` for
  the truthful BLOCKED/PASS summary, and use
  `uv run python tools/check_genesys2_sdcard_write_preflight.py --root . --require-pass`
  only before manually writing media. A PASS from this preflight still is not a
  physical write or board boot claim.

Current P0 trace-marker hashes:

- bitstream SHA256: `3b30e5ceda81f44a8c9e9b062557035adf66b6746b91559389437cf47cffd7fd`
- MCS SHA256: `918e0152e585f38ad54b8fceb47c99a4790e17c351923ecfdd09acb1f16efe44`
- LTX SHA256: `16360c1f20031509b61dafb4847ba638b85d1a758a1c10b96d2faacdb4ce7ee3`
- routed DCP SHA256: `5ad61ae2ab85414952585e026f8422258b83c72e1db172cd43e5018215f2fbf2`
- timing report SHA256: `7c764720ada1c8be3a27fc86eabafb23df78d608991690d4347a42ac553bd0c5`
- utilization report SHA256:
  `1b240125293f8f09c20412d78d74087321761015cb6ef3a72484c20dced8c43b`
- build manifest SHA256:
  `22a6ec09c87a1fd912cd3b61bf67d5ecaa8ab3807a2dcc9a02477474b8ea599c`
- programming summary SHA256:
  `fe1a50281b944486b4c39b9e03cd870e92cd81915061b35a0151ea6273511d03`
- programming log SHA256:
  `ad9395078cacd6aae737b0cf5254385628ffff31fd0f9e68925f8661bdb04bb4`

The programming summary proves only host Vivado/JTAG programming of this
trace-marker image. It does not prove a physical SD-card write, boot from the
new generated SD-card image, a board cycle source, overhead, production
streaming/DMA throughput, or malware validation.

## Docker Reproduction

```powershell
uv run rvmt ndss:docker-quick
uv run rvmt ndss:docker-local
uv run rvmt ndss:docker-full
```

Dry-run validation:

```powershell
uv run rvmt ndss:docker-quick --dry-run
uv run rvmt ndss:docker-local --dry-run
uv run rvmt ndss:docker-full --dry-run
```

## Host Vivado And Genesys2 Rerun

Use this path when rerunning board evidence or collecting the still-open
external blockers. Do not mark a new row `PASS` until the generated artifacts
exist and their checker passes.

```powershell
uv run rvmt vivado:check
uv run rvmt bitstream:build-trace-marker
uv run python tools/run_genesys2_p0_bram_repetitions.py --root . --run-root results/board/genesys2_trace_validation/<run-id> --sample hello_write --start-repetition 1 --repetitions 10 --minimum-repetitions 10 --force --port COM7 --timeout-seconds 120 --arm-timeout 60 --process-wait-timeout 240 --pre-read 0.5 --post-read 10
uv run python tools/package_genesys2_p0_bram_trace.py --run-root results/board/genesys2_trace_validation/<run-id> --minimum-repetitions 10
uv run python tools/check_genesys2_p0_bram_trace.py --root .
uv run rvmt repro:local
```

External closure intake remains open for:

- production non-BRAM streaming/DMA throughput;
- board-native cycle-counter smoke and cycle-level overhead, after enabling or
  otherwise exposing a valid board-side cycle source for the benchmark. Current
  failed probes cover both user-mode `rdcycle` and kernel `perf_event_open`
  hardware cycles. The SD-card Linux image does expose user `rdtime`, but that
  is not a cycle counter and must not be reported as cycle-level overhead.

Accepted external summaries for board-native source lines, scoped full
hardware pointer strings, and board benign controls are handled by
`external_closure_intake.json`. They remain scope-limited by their own
summaries and must not be generalized beyond those accepted artifacts.

## Host JTAG RAM-Boot Probe

This probe is read-only. It is intended for remote feasibility triage when the
SD card is not physically available.

```powershell
uv run rvmt ndss:jtag-ram-boot-probe
uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .
uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root . --require-ram-control
```

The default checker accepts a truthful `BLOCKED_*` result when the probe proves
that no RAM-write control object is visible. The `--require-ram-control` form
is the gate to use only after a new bitstream exposes a JTAG-to-AXI,
`hw_mem`, or equivalent memory-control path. Do not attempt or document a
RAM-load/kernel-update PASS until a separate non-read-only experiment records
the exact memory writes, reset/hart-control sequence, UART boot evidence, and
matching checker PASS.

## Host Cycle-Counter Smoke

This is a host/board check, not a Docker reproduction gate. The checker accepts
truthful `BLOCKED_*` summaries by default and requires a real board PASS only
when `--require-pass` is set.

```powershell
uv run python tools/build_genesys2_cycle_counter_smoke.py
uv run rvmt ndss:cycle-smoke --port COM7 --baud 115200 --reps 5
uv run python tools/check_genesys2_cycle_counter_smoke.py --root .
uv run python tools/check_genesys2_cycle_counter_smoke.py --root . --require-pass
uv run python tools/build_genesys2_cycle_source_probe.py
uv run rvmt ndss:cycle-source-probe --port COM7 --baud 115200 --reps 5
uv run python tools/check_genesys2_cycle_source_probe.py --root .
uv run python tools/check_genesys2_cycle_source_probe.py --root . --require-pass
uv run rvmt ndss:cycle-diagnostics --port COM7 --baud 115200
uv run python tools/check_genesys2_cycle_diagnostics.py --root .
uv run python tools/build_genesys2_counter_access_matrix.py
uv run rvmt ndss:counter-access-matrix --port COM7 --baud 115200 --reps 5
uv run python tools/check_genesys2_counter_access_matrix.py --root .
uv run python tools/check_genesys2_counter_access_matrix.py --root . --require-pass
uv run rvmt ndss:sdcard-linux-manifest --port COM7 --baud 115200
uv run python tools/check_genesys2_sdcard_linux_manifest.py --root .
uv run rvmt ndss:live-kernel-config-export --port COM7 --baud 115200
uv run python tools/check_genesys2_live_kernel_config_export.py --root .
uv run python tools/check_genesys2_live_kernel_config_export.py --root . --require-pass
uv run rvmt ndss:linux-source-lock
uv run rvmt ndss:linux-rebuild-prep --fetch --configure
uv run rvmt ndss:linux-rebuild-prep --execute --jobs 8
uv run python tools/check_genesys2_linux_rebuild_manifest.py --root .
uv run python tools/check_genesys2_linux_rebuild_manifest.py --root . --require-pass
uv run rvmt ndss:boot-sdcard-image --payload build/linux/genesys2-cva6/images/fw_payload.bin --rootfs build/linux/genesys2-cva6/images/rootfs.ext2
uv run python tools/check_genesys2_boot_sdcard_image.py --root .
uv run rvmt ndss:sdcard-write-preflight --image build/linux/genesys2-cva6/sdcard.img
uv run python tools/check_genesys2_sdcard_write_preflight.py --root .
uv run python tools/check_genesys2_sdcard_write_preflight.py --root . --require-pass
uv run rvmt ndss:linux-counter-preflight
uv run python tools/check_genesys2_linux_counter_path_preflight.py --root .
uv run python tools/check_genesys2_linux_counter_path_preflight.py --root . --require-pass
```

The latest 2026-06-24 live Genesys2 rerun transferred the ELFs successfully, but
the cycle-smoke program trapped on user-mode `rdcycle` and exited through the
shell as `RVMT_CYCLE_SMOKE_RC=132`. A follow-up kernel-perf probe also
transferred successfully, but `perf_event_open` returned `-38`. The
counter-access matrix then confirmed that the same SD-card Linux image exposes
user `rdtime` and `clock_gettime` while keeping `rdcycle` and `rdinstret`
unavailable. The diagnostic preflight further shows no PMU/perf DT node, no
readable kernel config, no module tree, no perf event-source directory, and no
observed SBI PMU.
The repository-local Linux counter-path preflight additionally shows that the
source-locked SD-card Linux/OpenSBI/Buildroot payload and local SD-card image
can now be built, but the new image still must be physically written, booted on
Genesys2, and checked for live kernel config, PMU/SBI PMU, and cycle-source
availability before rerunning the board cycle-source probes with require-pass.
Do not promote
`BLOCKED_BOARD_RDCYCLE_UNAVAILABLE` or
`BLOCKED_BOARD_KERNEL_PERF_CYCLES_UNAVAILABLE` to PASS, and do not re-label
`rdtime` as cycle-level overhead evidence.

## Host Vivado Preflight

```powershell
uv run rvmt ndss:host-vivado-check
uv run python tools/check_ndss_host_vivado_check.py --root .
uv run rvmt ndss:host-vivado-runbook
```

This preflight only checks the configured Vivado executable, the Genesys2
`xc7k325tffg900-2` part, and the Digilent Genesys2 board part. It writes
`results/evaluation/genesys2-cva6/current/host_vivado_check_summary.json` and
`results/evaluation/genesys2-cva6/current/host_vivado_check.log`. It does not
run synthesis, implementation, bitstream generation, board programming, or
board runtime capture.

## Host LaTeX

```powershell
uv run rvmt ndss:host-latex
uv run rvmt ndss:host-latex-runbook
```

The current `paper.tex` is a skeleton, not a complete anonymous NDSS submission.
Do not use it to claim final paper readiness until figures, related work,
ethics, artifact appendix, and raw-data-generated tables are complete.
