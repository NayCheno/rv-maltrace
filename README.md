# RV-MalTrace

RV-MalTrace is a CVA6/RISC-V hardware-assisted behavior tracing project. The
current mainline is centered on the Digilent Genesys2 + CVA6 evidence package
under `results/evaluation/genesys2-cva6/current/`: committed-event trace RTL,
Vivado simulation, physical-board BRAM/ILA marker-window captures, local
ELF/process attribution, semantic provenance, and artifact checkers.

The current paper-level direction is a hardware-rooted RISC-V behavior trace and
semantic reconstruction system. The repository does not claim real-malware
validation, malware detection accuracy, production streaming/DMA throughput, or
full hardware-derived pointer strings unless the corresponding artifact-backed
gate passes.

## Repository Layout

```text
docs/         Categorized plans, architecture notes, runbooks, reports, and gates
rtl/trace/    Synthesizable trace RTL and CVA6 RVFI trace adapter
sim/          Vivado xsim filelists, testbenches, programs, and goldens
tools/        Python helpers for builds, trace parsing, comparison, and checks
board/        First-board trace validation manifests and expected outputs
fpga/         Local FPGA bring-up notes and stable output conventions
src/          rvmt command-line task runner
```

Generated Vivado, simulation, and board evidence normally stays under `build/`
or `results/`. The canonical current summaries and selected small evidence
files are promoted explicitly through `.gitignore` exceptions and checked by the
artifact package. Large raw board roots remain referenced by manifest and are
covered by a separate raw artifact ZIP release candidate when present.

## Quick Start

Use `uv` as the single entry point:

```powershell
uv run rvmt config:show
uv run rvmt tasks:list
uv run rvmt repro:quick
uv run rvmt repro:local
uv run rvmt ndss:docker-full
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:cva6-full-soc-tohost
uv run rvmt sim:cva6-full-soc-rv64gc
uv run rvmt sim:summary
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture
uv run rvmt exp:35t --stage all --run-id dryrun --dry-run
```

For documentation and experiment gates, run the narrow checker that matches the
touched area. Common checks include:

```powershell
uv run python tools/check_trace_boundary.py
uv run python tools/check_timing_principles.py
uv run python tools/check_board_baseline.py
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_programs.py
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/check_semantic_enrichment_strategy.py
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_behavior_demo.py
uv run python tools/check_35t_experiment_bundle.py --self-test
```

For the current Genesys2/CVA6 evidence package, the main local gates are:

```powershell
uv run rvmt repro:quick
uv run rvmt repro:local
uv run rvmt repro:full
uv run rvmt repro:clean-export
uv run rvmt ndss:docker-full
```

`repro:quick` checks the reproducibility manifest, lightweight artifact package,
raw artifact release manifest/ZIP, semantic provenance, and recursive artifact
path/hash integrity. `repro:local` adds current-quality, case-study, and
bitstream artifact inventory checks. `repro:clean-export` copies the current
worktree into an isolated local export, extracts the raw artifact ZIP there,
and reruns quick/local without claiming a committed release clone.
Host-only Vivado, Genesys2/JTAG/UART, and LaTeX steps are documented in
`docs/07-evaluation-evidence/ndss_host_runbook.md`.
The board-side timing-source probes are exposed as
`uv run rvmt ndss:cycle-smoke`, `uv run rvmt ndss:cycle-source-probe`, and
`uv run rvmt ndss:counter-access-matrix`. `uv run rvmt
ndss:sdcard-linux-manifest` captures the live booted SD-card Linux identity over
UART, and `uv run rvmt ndss:linux-counter-preflight` records whether the
repository has the Genesys2/CVA6 Buildroot/OpenSBI/Linux/SD-card source anchors
needed to repair that path. The counter-path preflight requires semantic
Genesys2/CVA6 Buildroot/OpenSBI/build-entrypoint evidence, not placeholder
paths. These commands record BLOCKED summaries unless the live SD-card Linux
image actually exposes the requested cycle source and the source-locked rebuild
path is present.
`uv run rvmt ndss:tracer-visibility-baseline` runs the safe Docker software
baseline for anti-analysis comparison tables. It records native/no-tracer,
native/strace, qemu-user, and qemu-user-strace observations and keeps qemu and
strace as oracle-only software baselines, not hardware evidence.

## Behavior Demo

The behavior demo evidence bundle is documented in `docs/04-runtime-linux/behavior_demo.md`.
It writes artifacts under `results/demo/<run-id>/<sample-id>/` and can also
use a custom output root for smoke runs:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture
uv run rvmt demo:groundtruth --sample anti_debug_like
uv run python tools/check_behavior_demo.py
```

The demo is synthetic behavior audit evidence, not malware detection quality evidence,
Linux-on-board evidence, or physical hardware validation.

The normal full-SoC tohost probe is available as `uv run rvmt sim:cva6-full-soc-tohost`.
It is repository-local Vivado simulation evidence and remains distinct from
physical Genesys2 board evidence. Board claims are made only through the current
Genesys2/CVA6 summaries and their checker suite.

## Core Artifacts

- `docs/10-process/version_lock.md` records the current CVA6, Vivado, bare-metal
  toolchain, board target, and decoder anchors. Linux kernel, Buildroot, and
  SD-card image anchors remain TODO/BLOCKED until
  `results/evaluation/genesys2-cva6/current/linux_counter_path_preflight.json`
  no longer reports `BLOCKED_SD_CARD_LINUX_SOURCE_MISSING`.
- `docs/02-trace-architecture/signal_map.md` maps committed CVA6/RVFI signals into the trace adapter.
- `docs/02-trace-architecture/trace_format.md` defines the JSONL event schema, packet fields,
  comparison rules, filters, compression prototype, and disabled memory modes.
- `docs/07-evaluation-evidence/reports/sim_results.md` summarizes current Vivado simulation evidence.
- `docs/03-platform-architecture/genesys2/board_bringup.md`, `docs/03-platform-architecture/genesys2/board_trace_minimal.md`, and
  `docs/03-platform-architecture/genesys2/board_trace_validation.md` separate repository-local build evidence
  from physical-board evidence.
- `docs/07-evaluation-evidence/evaluation_plan.md` defines the CCF-A-oriented research questions,
  baselines, datasets, metrics, and required artifact gates.
- `docs/README.md` indexes the categorized documentation tree.
- `docs/03-platform-architecture/artix7-35t/artix7_35t_bringup.md` records the low-cost Artix-7 35T
  LiteX/VexRiscv prototype path.
- `docs/07-evaluation-evidence/ndss_artifact_instructions.md` and
  `docs/09-planning/ndss_execution_status.md` record the current NDSS artifact
  instructions, validation commands, completed host runs, and open blockers.

## Evidence Policy

Do not mark board or Linux rows as PASS unless the documented artifact exists
under the matching `results/board/.../<run-id>/` or `results/linux/.../<run-id>/`
path and any recorded SHA-256 matches. Simulation evidence, bitstream evidence,
physical-board observations, and paper-level evaluation results are separate
gates. QEMU, strace, and host-control logs are validation oracles only; they must
not be described as hardware-recovered semantics.

Trace logic is sideband-only. A full trace sink must never backpressure CVA6;
when bandwidth is exceeded, the design must drop trace records and emit/count
`EVT_DROP`.

## FPGA Notes

The stable Vivado output convention is:

```text
build/vivado/<board>-<target>/
  project/
  work-fpga/
  reports/
```

The top-level `fpga/` directory is for repository-owned bring-up notes, board
profiles, constraints overlays, ILA plans, and host-side scripts. Generated
bitstreams, checkpoints, and reports remain ignored build artifacts unless a
specific reproducibility package intentionally promotes a small summary file.
