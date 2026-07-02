# NDSS Artifact Instructions

Canonical evidence root: `results/evaluation/genesys2-cva6/current/`.

## Quick Reproduction

```powershell
uv run rvmt repro:quick
```

This runs the reproducibility manifest checker, artifact package checker, raw
artifact release checker, semantic provenance checker, directed trace
correctness checker, local code-analysis fixture checker, safe software
tracer-visibility baseline checker, cycle diagnostic checker, read-only JTAG
RAM-boot probe checker, and recursive artifact path/hash checker. A `PASS` from
this command means the current local evidence
package is internally consistent; it does not mean host Vivado or Genesys2
experiments were rerun.

The current package is a lightweight manifest package. It hashes summaries,
checkers, paper-facing reports, and NDSS instructions, and it references raw
board roots selected by `latest_manifest.json`. It does not copy all raw board
artifacts into the Git package. A reviewer evaluating from a clean checkout must
either receive the raw artifact ZIP named below or rerun the host board
collection runbook before treating raw-board reproduction as closed.

For a clean checkout that receives the raw ZIP, extract it into the repository
root before running quick/local so the manifest-listed `results/board/...`
paths exist:

```powershell
Expand-Archive build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip -DestinationPath . -Force
uv run rvmt repro:quick
uv run rvmt repro:local
```

## Raw Artifact ZIP

The local raw-board release candidate is:

```text
build/ndss_artifacts/rv-maltrace-genesys2-cva6-current-raw-artifacts.zip
```

SHA256:

```text
d88dc671ca2ab90d72a6b5d6340a6726d98572a41988b9f1ca499e4fff6eac04
```

`results/evaluation/genesys2-cva6/current/raw_artifact_release_manifest.json`
records `file_count: 1998` and `size_bytes: 285238085` and is checked by:

```powershell
uv run python tools/check_genesys2_raw_artifact_release.py --root .
```

This is a local release candidate. It is not an external immutable release
asset until published outside the working tree. The ZIP intentionally excludes
`results/evaluation/genesys2-cva6/current/`; that canonical evidence root is
supplied by the repository snapshot, while the ZIP supplies manifest-referenced
raw board and build artifacts outside the current root.

## Local Reproduction

```powershell
uv run rvmt repro:local
```

This extends quick reproduction with current CCF-A quality, case-study, and bitstream artifact checks. It remains local-only.

## Local Clean-Export Reproduction

```powershell
uv run rvmt repro:clean-export
uv run python tools/check_genesys2_clean_repro_bundle.py --root .
```

This creates `build/clean_repro/genesys2-cva6-current-<timestamp>/`, copies the
current publishable worktree, extracts the raw artifact ZIP, carries over the
local bitstream inventory artifacts, CVA6 source-hash inputs, and Genesys2/CVA6
Linux image rebuild artifacts, and runs quick plus local reproduction inside
that isolated directory. Its manifest is local evidence for the current
uncommitted worktree only; a true reviewer fresh clone still requires
commit/tag/release publication of the Git tree and raw ZIP.

## Docker Reproduction

```powershell
uv run rvmt ndss:docker-quick
uv run rvmt ndss:docker-local
uv run rvmt ndss:docker-full
```

The Docker entry uses `docker-compose.toolchain.yml` service `linux-behavior`
and runs the same `uv run rvmt ...` CLI inside the container. It sets
`UV_PROJECT_ENVIRONMENT=/tmp/rvmt-uv-env` and
`UV_CACHE_DIR=/tmp/rvmt-uv-cache` so the Linux container does not reuse the
host `.venv` mounted from Windows. `ndss:docker-full` adds Python compile
checks plus the current, artifact, Genesys2 self-test, and CCF-A gate self-test
suites.

## Artifact Integrity Policy

- Every `PASS` row that points at a concrete artifact path must reference an existing file or directory.
- Every `sha256` paired with an artifact path must match the file bytes.
- Wildcard paths are not accepted as evidence for `PASS` rows.
- Host/control, QEMU, and strace data are validation oracles only. They must not be marked as hardware reconstruction output.
- External host/board/Vivado evidence that has not been produced remains `BLOCKED_*` or `TODO_*`, not `PASS`.
- `artifact_package_manifest.json` has `raw_board_artifacts_copied=false` by design; the raw archive is a separate ZIP release asset, not Git contents.
- `tracer_visibility_baseline_summary.json` is a safe Docker software baseline
  only. It may support a strace/qemu visibility-oracle comparison row, but it
  is not Genesys2 board evidence, hardware invisibility evidence, malware
  execution, or detection-accuracy evidence.
- `linux_counter_path_preflight.json` must remain `BLOCKED_*` until a
  Genesys2/CVA6-specific Buildroot/OpenSBI/Linux/SD-card rebuild path, kernel
  counter config, PMU device-tree path, and live kernel-config export are
  present and checked. The Buildroot, OpenSBI, and build-entrypoint anchors
  require content-level semantic checks, not just existing paths.
  Artix-7/LiteX/VexRiscv assets are not substitutes.
- The repo-owned 64-bit CVA6/Genesys2 bootrom DTS template
  `rtl/cva6/corev_apu/fpga/src/bootrom/cv64a6.dts.in` contains a
  `compatible = "riscv,pmu"` PMU node and satisfies the source-level PMU
  device-tree anchor. This is not live PMU evidence until a rebuilt DTB,
  rebuilt SD-card payload, OpenSBI/kernel support, and live board diagnostics
  prove PMU/SBI PMU visibility.
- `board/genesys2-cva6/linux/` contains the current source-level rebuild
  contract: Buildroot defconfig, Linux counter/perf config, OpenSBI `v1.7`
  source manifest, and a README that documents the claim boundary. Validate it
  with `uv run rvmt ndss:linux-source-lock`. These files do not claim a built
  SD-card image, a live kernel config export, or board PMU/cycle availability.
- `tools/prepare_genesys2_cva6_linux_rebuild.py` and `uv run rvmt
  ndss:linux-rebuild-prep --fetch --configure` run in Docker and write
  `linux_rebuild_manifest.json`. `PASS_LINUX_REBUILD_PREPARED` means the
  generated CVA6 DTS and generated Buildroot defconfig are hash-bound and the
  container has the required build tools. It is not a payload-build claim.
  `PASS_LINUX_PAYLOAD_BUILT` requires a real `fw_payload.bin` under
  `output_artifacts`, and still does not claim physical SD-card write, live
  board boot, live kernel-config export, or board PMU/cycle availability.
- The current Docker rebuild uses Buildroot 2026.02, Linux 6.19.6, OpenSBI
  `1.7` as the Buildroot version value for source tag `v1.7`, and disables the
  user-space Buildroot `linux-tools/perf` package after it blocked payload
  generation. Kernel perf/counter support remains in `linux.config` and must be
  proven by the board `perf_event_open` probes, not by the presence of a `perf`
  binary.
- `tools/create_genesys2_boot_sdcard_image.py` and `uv run rvmt
  ndss:boot-sdcard-image --payload <fw_payload.bin>` provide the local GPT
  image layout step for the CVA6 bootrom contract. The first GPT partition is
  the boot payload copied to `0x80000000`; optional rootfs content is placed in
  a later partition. `tools/check_genesys2_boot_sdcard_image.py` verifies the
  image SHA256, GPT signatures, partition bytes, source payload/rootfs hashes,
  and zero padding. This tool does not compile Buildroot/OpenSBI, write the
  physical SD card, boot Genesys2, export a live kernel config, or prove board
  PMU/cycle availability.
- `sdcard_linux_manifest.json` is live Genesys2/CVA6 booted-image identity
  evidence only. Its Buildroot/Linux version, DTB identity, root filesystem
  hashes, missing `/boot`, missing live kernel config, absent visible SD/MMC
  block device, and observed SBI extensions are parsed from the UART log. Those
  fields must not be used as a Buildroot source/defconfig, OpenSBI source,
  kernel config, PMU/SBI PMU, or board cycle-source claim.
- `live_kernel_config_export_summary.json` is the live board attempt to export
  a readable kernel config. The current status is
  `BLOCKED_LIVE_KERNEL_CONFIG_UNAVAILABLE`, with hashed COM7 UART evidence that
  `/proc/config.gz`, `/boot/config-6.19.6`, and
  `/lib/modules/6.19.6/build/.config` are absent. Do not create or cite
  `live_kernel_config.txt` unless a real future board export writes it and
  `tools/check_genesys2_live_kernel_config_export.py --require-pass` succeeds.

## Host-Only Work

Use `docs/07-evaluation-evidence/ndss_host_runbook.md` for Vivado, Genesys2/JTAG/UART, and LaTeX commands. Do not change a blocked status to `PASS` until the generated artifacts exist and pass their checker.
