# RV-MalTrace

RV-MalTrace is a CVA6/RISC-V hardware-assisted behavior tracing project. The
current repository focus is a reproducible committed-event trace MVP: collect
sideband trace events from committed execution, compare simulation output with
golden JSONL traces, and keep board and Linux claims behind explicit evidence
gates.

The paper-level direction is described in `docs/09-planning/next-plan.md`: RV-MalScope, a
low-perturbation RISC-V syscall/control-flow/trap/context tracer with planned
semantic reconstruction, board validation, and evasion-resistance evaluation.

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

Generated Vivado, simulation, and board evidence should stay under `build/` or
`results/`. Those directories are intentionally ignored; promote only stable
summaries, runbooks, scripts, or expected artifacts into version control.

## Quick Start

Use `uv` as the single entry point:

```powershell
uv run rvmt config:show
uv run rvmt tasks:list
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
It is repository-local Vivado simulation evidence; the current result is
BLOCKED on timeout, so it does not upgrade board, Linux, or malware detection
claims.

## Core Artifacts

- `docs/10-process/version_lock.md` records the current CVA6, Vivado, bare-metal
  toolchain, board target, and decoder anchors. Linux kernel, Buildroot, and
  `riscv64-linux-gnu-gcc` anchors remain TODO until the Linux bring-up gate.
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

## Evidence Policy

Do not mark board or Linux rows as PASS unless the documented artifact exists
under the matching `results/board/.../<run-id>/` or `results/linux/.../<run-id>/`
path. Simulation evidence, bitstream evidence, physical-board observations, and
paper-level evaluation results are separate gates.

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
