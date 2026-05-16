# uv Workflow

Use `uv` as the single entry for local build tasks:

```powershell
uv run rvmt config:show
uv run rvmt docker:build
uv run rvmt toolchain:build
uv run rvmt bootrom:build
uv run rvmt vivado:check
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:cva6-run --asm path\to\program.S --name custom_program
uv run rvmt sim:summary
uv run rvmt baremetal:build
uv run rvmt bitstream:build
uv run rvmt vivado:project
uv run python tools/check_board_baseline.py
uv run python tools/check_vivado_authorization.py
uv run python tools/check_bringup_runbook.py
uv run python tools/check_baseline_pass_criteria.py
uv run python tools/check_trace_export_decision.py
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_programs.py
uv run python tools/check_linux_behavior_principles.py
uv run python tools/check_linux_benign_dataset.py
uv run python tools/check_linux_malware_like_dataset.py
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/audit_behavior.py --self-test
uv run python tools/check_linux_behavior_audit.py
uv run python tools/gen_rv_trace_fuzz.py --self-test
uv run python tools/check_fuzz_trace.py --self-test
uv run python tools/check_fuzz_trace_plan.py
uv run python tools/check_noninterference_gate.py
uv run python tools/check_semantic_enrichment_rationale.py
uv run python tools/check_semantic_enrichment_routes.py
uv run python tools/check_semantic_enrichment_strategy.py
uv run python tools/check_evaluation_plan.py
```

Slash groups are expanded, so this runs the long build sequence:

```powershell
uv run rvmt docker/toolchain/bootrom/bitstream
```

The Windows executable itself is `rvmt`. Task names can contain colons because they are arguments, not Windows executable filenames.

## Configuration

Edit `[tool.rv-maltrace]` in `pyproject.toml`:

```toml
[tool.rv-maltrace]
vivado = "C:/Xilinx/Vivado/2024.2/bin/vivado.bat"
vivado_board_repo_paths = ["vendor/vivado-boards/new/board_files"]
vivado_subst_drive = "R:"
make = "make.exe"
make_path_prepend = ["D:/env/tools/MinGW/msys/1.0/bin"]
build_dir = "build"
vivado_populate_project = true
board = "genesys2"
# Optional override. By default this is derived from board.
# xilinx_part = "xc7k325tffg900-2"
# xilinx_board = "digilentinc.com:genesys2:part0:1.1"
target = "cv64a6_imafdc_sv39"
xlen = 64
toolchain_config = "gcc-13.1.0-baremetal"
baremetal_tool_prefix = "riscv-none-elf-"
num_jobs = 8
```

`make` is resolved only from `make_path_prepend`. Keep this pointed at the MSYS toolchain bin directory; `rvmt` intentionally does not fall back to any other global `PATH` entry for `make`.

For `bitstream:build`, `rvmt` also prepends the configured Vivado `bin` directory to the child process `PATH`. CVA6's nested Xilinx IP Makefiles call `vivado` directly, so this keeps those calls on the same Vivado installation configured above.

Digilent board files are provided by the `vendor/vivado-boards` submodule. `rvmt` injects `vivado_board_repo_paths` into Vivado with `board.repoPaths`, including nested CVA6 Xilinx IP generation calls.

On Windows, `vivado_subst_drive` maps the repository to a short drive path before running Vivado. This avoids Vivado's 260-character path limit during Xilinx IP synthesis.

`bitstream:build` writes the stable FPGA deliverables under:

```text
build/vivado/<board>-<target>/
  project/        # Vivado GUI project: ariane.xpr
  work-fpga/      # bitstream, flash image, netlists, checkpoints, generated IP xci copies
  reports/        # timing and utilization reports
```

Set `vivado_artifact_dir` if you want to override that exact directory instead of deriving it from `build_dir`, `board`, and `target`.
Set `vivado_project_dir` if you want the GUI `.xpr` somewhere else.

The upstream CVA6 batch flow still creates temporary Vivado state in `rtl/cva6/corev_apu/fpga/`, because the CVA6 scripts create the synthesis project from that directory. `rvmt` generates the stable GUI project under `build/` and removes the transient source-tree `.xpr` after the import step.

If Vivado is already in `PATH`, keep:

```toml
vivado = "vivado"
```

## Tasks

```text
docker:build      Build the Ubuntu 24.04 Docker image.
toolchain:build   Build the CVA6 RISC-V GCC/newlib toolchain in Docker.
bootrom:build     Generate CVA6 FPGA bootrom_64.sv using the Docker toolchain.
vivado:check      Check whether Vivado has the configured FPGA part and board files.
vivado:project    Generate build/vivado/<board>-<target>/project/ariane.xpr for GUI browsing.
bitstream:build   Run CVA6 make fpga with Windows Vivado.
bitstream:collect Copy existing CVA6 FPGA outputs into build/vivado/<board>-<target>.
sim:trace-unit    Run the trace_top unit regression in Vivado xsim and compare JSONL output.
sim:cva6-smoke    Compile/elaborate the direct CVA6 xsim testbench and run the trace/no-trace matrix.
sim:cva6-run      Run one custom assembly, ELF, raw binary, or readmemh image through the direct CVA6 xsim testbench.
sim:summary       Summarize results/vivado_sim into a table and summary.json.
baremetal:build   Build all sim/programs bare-metal ELF/dump/bin artifacts when the RISC-V toolchain is available.
config:show       Print resolved configuration.
tasks:list        Print task names.
completion:*      Print shell completion scripts.
```

Aliases:

```text
tool -> toolchain:build
bootrom -> bootrom:build
bitstream/fpga -> bitstream:build
vivado:xpr -> vivado:project
sim/sim:unit/sim:trace -> sim:trace-unit
sim:cva6/sim:cva6-xsim -> sim:cva6-smoke
sim:run/sim:cva6-custom -> sim:cva6-run
summary -> sim:summary
baremetal/programs -> baremetal:build
```

The source-tree `ariane.xpr` is generated by CVA6's batch flow. Upstream uses `read_verilog` and `read_vhdl` for synthesis, so that transient project can be empty even after a successful bitstream build. `bitstream:build` creates the `build/` GUI project automatically when `vivado_populate_project = true`. You can also run `uv run rvmt vivado:project` manually to regenerate the Vivado Sources and Constraints views before opening:

```text
build/vivado/<board>-<target>/project/ariane.xpr
```

## Completion

PowerShell, temporary for the current shell:

```powershell
uv run --quiet rvmt completion:powershell | Out-String | Invoke-Expression
```

PowerShell, persistent:

```powershell
New-Item -ItemType Directory -Force .\scripts\completions | Out-Null
uv run --quiet rvmt completion:powershell | Set-Content .\scripts\completions\rvmt.ps1
Add-Content $PROFILE "`n. `"$PWD\scripts\completions\rvmt.ps1`""
```

Then restart PowerShell. Completion works for both forms:

```powershell
uv run rvmt <TAB>
rvmt <TAB>
```

Bash:

```bash
uv run --quiet rvmt completion:bash >> ~/.bashrc
source ~/.bashrc
```

Zsh:

```zsh
uv run --quiet rvmt completion:zsh >> ~/.zshrc
source ~/.zshrc
```

List task names:

```powershell
uv run rvmt tasks:list
```

`sim:cva6-smoke` uses the configured Vivado installation and writes its working
tree under `build/cva6_xsim_smoke`. It instantiates the CVA6 core directly with a
simple AXI memory, boots six minimal DRAM images (`cva6_smoke`, `cva6_branch`,
`cva6_jump`, `cva6_ecall`, `cva6_trap_illegal`, and `cva6_ebreak`) through both
trace-enabled and no-trace snapshots, and publishes
`results/vivado_sim/cva6_*/{trace.jsonl,compare.log,run.log,xsim.log,xsim_notrace.log}`.
The full `ariane_testharness` SoC path still hits a Vivado v2025.2 simulator
kernel fatal in upstream CVA6 AXI demux logic, so the direct-core matrix is the
current local full-core execution gate.

`sim:cva6-run` uses the same direct-core trace/no-trace snapshots for one custom
program. Choose exactly one input:

```powershell
uv run rvmt sim:cva6-run --asm .\scratch\demo.S --name demo
uv run rvmt sim:cva6-run --asm .\scratch\demo.S --name demo --tool-mode docker
uv run rvmt sim:cva6-run --elf .\build\demo.elf --name demo
uv run rvmt sim:cva6-run --bin .\build\demo.bin --name demo
uv run rvmt sim:cva6-run --mem .\build\demo.mem --name demo --expected .\sim\golden\demo.expected.json
```

For `--asm`, the runner links `sim/programs/common/crt0.S`,
`trap_vector.S`, `finish.S`, and `linker.ld` by default, so the assembly source
can just define `main` and return `a0=1` for PASS:

```asm
.section .text
.globl main
main:
  li a0, 1
  ret
```

Use `--no-runtime` only for a complete image that defines its own `_start`,
trap handling, and tohost write. ELF and raw binary inputs are loaded at the
direct-core DRAM base `0x80000000`; raw binaries must already be laid out for
that address. Results are published under
`results/vivado_sim/<name>/{trace.jsonl,compare.log,run.log,xsim.log,xsim_notrace.log}`.

When `riscv-none-elf-*` is not on the host `PATH`, `sim:cva6-run` falls back to
the existing `docker-compose.toolchain.yml` service for `--asm` and `--elf`
tool steps. Use `--tool-mode docker` to force the container, or
`--tool-mode local` to require host tools.

## Trace Source Boundary

Trace simulation compiles synthesizable trace RTL and simulation-only sources
from separate filelists:

```text
sim/vivado/trace_rtl.f
sim/vivado/trace_sim.f
```

Run the boundary check before synthesis-oriented work:

```powershell
uv run python tools/check_trace_boundary.py
uv run python tools/check_trace_boundary.py --self-test
```

## Trace Timing Principles

Phase 3.2 keeps trace logic sideband-only. `trace_top` and
`cva6_rvfi_trace_adapter` default to a one-cycle input snapshot before complex
decode and packet formatting, and the trace RTL must not expose ready/stall
interfaces that could backpressure the core.

```powershell
uv run python tools/check_timing_principles.py
uv run python tools/check_timing_principles.py --self-test
```

## Resource Report

Phase 3.3 resource reporting is generated from the existing Genesys 2 Vivado
reports plus the latest trace simulation summary:

```powershell
uv run python tools/generate_resource_report.py
uv run python tools/generate_resource_report.py --self-test
```

The generated report is `docs/resource_report.md`.

## Board Baseline Preflight

Phase 4.1 checks the local Genesys 2 baseline evidence before physical board
bring-up. The preflight verifies the Vivado simulation summary, baseline
bitstream/flash/checkpoint/project artifacts, route/timing reports, Genesys 2
board files, active reset/clock/UART constraints, and active DDR/clock/UART
source paths:

```powershell
uv run python tools/check_board_baseline.py
uv run python tools/check_board_baseline.py --self-test
```

This is a repository-local artifact gate. Physical clock/reset, UART, and
bare-metal runtime observations are still recorded in `docs/board_bringup.md`.
The current baseline also parses `ariane.check_timing.rpt` and reports known
open constraint warnings as WARN rows instead of treating report presence as a
clean timing-constraint pass.

## Vivado Authorization Evidence

Phase 4.2 records the Vivado license/part/board-file risk before physical board
work. The checker verifies the configured Genesys 2 target, board files,
existing bitstream/MCS/DCP artifacts, routed timing report, and route status:

```powershell
uv run rvmt vivado:check
uv run python tools/check_vivado_authorization.py
uv run python tools/check_vivado_authorization.py --self-test
```

The license support conclusion is artifact-based: the local Vivado environment
has already generated a routed Genesys 2 bitstream. Rerun these checks before a
fresh rebuild because a future license checkout can still fail independently of
the stored artifacts.

## Board Bring-up Runbook

Phase 4.3 is documented in `docs/baseline_bringup_runbook.md`. The runbook
records the required order: LED/clock/reset sanity, UART hello, minimal RISC-V
core boot, CVA6 bare-metal boot, and optional Linux boot. It is a procedure and
does not claim physical board success until logs are captured under
`results/board/genesys2_baseline/<run-id>/`.

```powershell
uv run python tools/check_bringup_runbook.py
uv run python tools/check_bringup_runbook.py --self-test
```

## Baseline Pass Criteria

Phase 4.4 is tracked in `docs/baseline_pass_criteria.md`. The checker keeps
repository-local PASS rows separate from physical board PASS rows. Without a
concrete `results/board/genesys2_baseline/<run-id>` evidence directory, the
clock/reset, UART, and bare-metal criteria must remain `TODO (BOARD)`.

```powershell
uv run python tools/check_baseline_pass_criteria.py
uv run python tools/check_baseline_pass_criteria.py --self-test
```

After a board run, pass the run directory to compare the document status against
the captured observations:

```powershell
uv run python tools/check_baseline_pass_criteria.py --evidence-root results/board/genesys2_baseline/<run-id>
```

## Trace Export Decision

Phase 5.1 is tracked in `docs/trace_export_decision.md`. The first board export
path is BRAM ring buffer plus ILA/JTAG dump; UART streaming and AXI
DMA/Ethernet streaming are deferred.

```powershell
uv run python tools/check_trace_export_decision.py
uv run python tools/check_trace_export_decision.py --self-test
```

## Board Trace Minimal Policy

Phase 5.2 is tracked in `docs/board_trace_minimal.md`. The first board trace
wrapper is `rtl/trace/trace_board_minimal_top.sv`: full retire, jump, and marker
events stay off; syscall, trap, context, branch, and drop accounting stay on.
The `board_minimal` trace-unit regression exercises the profile wiring.

```powershell
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_minimal.py --self-test
```

## Board Trace Validation Programs

Phase 5.3 is tracked in `docs/board_trace_validation.md` and
`board/trace_validation/manifest.json`. The first board validation set is:
hello/write, file open/read/write/close, fork/exec/wait, and illegal instruction
trap.

```powershell
uv run python tools/check_board_trace_programs.py
uv run python tools/check_board_trace_programs.py --self-test
```

## Linux Behavior Experiment Principles

Phase 6.1 is tracked in `docs/linux_behavior_experiment_principles.md` and
`experiments/linux_behavior/policy.json`. Early experiments must use benign and
malware-like synthetic programs only; real malware and unknown-provenance
binaries stay forbidden.

```powershell
uv run python tools/check_linux_behavior_principles.py
uv run python tools/check_linux_behavior_principles.py --self-test
```

## Linux Benign Dataset

Phase 6.2 is tracked in `docs/linux_benign_dataset.md` and
`experiments/linux_behavior/benign/manifest.json`. The benign set covers hello,
`ls`, `cat`, `cp`, `sha256sum`, and an optional small network client that stays
disabled by default unless a planned target network setup is available.

```powershell
uv run python tools/check_linux_benign_dataset.py
uv run python tools/check_linux_benign_dataset.py --self-test
```

## Linux Malware-like Synthetic Dataset

Phase 6.3 is tracked in `docs/linux_malware_like_dataset.md` and
`experiments/linux_behavior/malware_like/manifest.json`. The synthetic set
covers file scanning, batch open/read/write, self-copy simulation, abnormal
syscall sequences, illegal-instruction trap behavior, process creation chains,
dynamic executable memory transitions, and anti-debug-like timing indicators.
It does not include real malware.

```powershell
uv run python tools/check_linux_malware_like_dataset.py
uv run python tools/check_linux_malware_like_dataset.py --self-test
```

## Linux Behavior Recovery Targets

Phase 6.4 is tracked in `docs/linux_behavior_recovery_targets.md` and
`experiments/linux_behavior/recovery_targets.json`. The offline recovery
prototype is `tools/recover_behavior.py`; it derives `semantic_events.json`,
`behavior_graph.json`, and `recovery_report.md` from `trace.jsonl`.

```powershell
uv run python tools/recover_behavior.py --self-test
uv run python tools/recover_behavior.py --trace sim/golden/behavior_recovery.trace.jsonl --out-dir build/behavior_recovery_smoke
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/check_linux_behavior_recovery.py --self-test
```

## Linux Behavior Audit

Phase 6.5 is tracked in `docs/linux_behavior_audit.md` and
`experiments/linux_behavior/behavior_audit_rules.json`. The offline audit
prototype is `tools/audit_behavior.py`; it derives `behavior_audit.json` and
`behavior_audit_report.md` from recovered semantic artifacts for synthetic
case-study review only.

```powershell
uv run python tools/audit_behavior.py --self-test
uv run python tools/audit_behavior.py --semantic build/behavior_recovery_smoke/semantic_events.json --graph build/behavior_recovery_smoke/behavior_graph.json --manifest experiments/linux_behavior/malware_like/manifest.json --sample-id illegal_trap --out-dir build/behavior_audit_smoke
uv run python tools/check_linux_behavior_audit.py
uv run python tools/check_linux_behavior_audit.py --self-test
```

## Bounded Fuzz Trace Validation

Phase 8 trace-validator fuzzing is tracked in `docs/fuzz_trace_validation.md`
and `sim/golden/fuzz_invariants.json`. The first implementation uses
deterministic seed programs from `tools/gen_rv_trace_fuzz.py` and checks trace
invariants with `tools/check_fuzz_trace.py`.

```powershell
uv run python tools/gen_rv_trace_fuzz.py --self-test
uv run python tools/gen_rv_trace_fuzz.py --out-dir build/fuzz_trace_seeds
uv run python tools/check_fuzz_trace.py --self-test
uv run python tools/check_fuzz_trace.py --trace sim/golden/fuzz_trace_smoke.trace.jsonl --case fuzz_trace_smoke
uv run python tools/check_fuzz_trace_plan.py
uv run python tools/check_fuzz_trace_plan.py --self-test
```

## Noninterference And Resource Gate

Phase 3.4 is tracked in `docs/noninterference_resource_gate.md` and
`experiments/hardware/noninterference_gate.json`. The gate keeps current
evidence limited to sideband trace capture, drop accounting, direct-core
trace/no-trace parity, and baseline resource reporting until trace-enabled
implementation reports exist.

```powershell
uv run python tools/check_noninterference_gate.py
uv run python tools/check_noninterference_gate.py --self-test
```

## Semantic Enrichment Rationale

Phase 7.1 is tracked in `docs/semantic_enrichment_rationale.md` and
`experiments/linux_behavior/semantic_enrichment_rationale.json`. eBPF, kernel
helpers, and memory snapshots are deferred optional semantic enrichment; the
core contribution remains RTL-level committed behavior trace.

```powershell
uv run python tools/check_semantic_enrichment_rationale.py
uv run python tools/check_semantic_enrichment_rationale.py --self-test
```

## Semantic Enrichment Routes

Phase 7.2 is tracked in `docs/semantic_enrichment_routes.md` and
`experiments/linux_behavior/semantic_enrichment_routes.json`. The three routes
are selective memory snapshot, kernel helper metadata, and eBPF metadata
alignment; all remain deferred until the FPGA trace path works.

```powershell
uv run python tools/check_semantic_enrichment_routes.py
uv run python tools/check_semantic_enrichment_routes.py --self-test
```

## Semantic Enrichment Strategy

Phase 7.3 is tracked in `docs/semantic_enrichment_strategy.md` and
`experiments/linux_behavior/semantic_enrichment_strategy.json`. The recommended
order is: MVP without eBPF/kernel-helper/memory-snapshot dependency; after FPGA
trace works, evaluate selective memory snapshot; after Linux experiments,
optionally add eBPF metadata alignment.

```powershell
uv run python tools/check_semantic_enrichment_strategy.py
uv run python tools/check_semantic_enrichment_strategy.py --self-test
```

## Evaluation Plan

Paper-level evaluation planning is tracked in `docs/evaluation_plan.md`. It
keeps the RQ, baseline, dataset, metric, and artifact gates in TODO status until
simulation, board, Linux, or study evidence exists.

```powershell
uv run python tools/check_evaluation_plan.py
uv run python tools/check_evaluation_plan.py --self-test
```

## Trace Compression Prototype

Phase 2 keeps compression as an offline simulation artifact until the packet
format is stable. Compress and round-trip a trace with:

```powershell
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.jsonl --out results/vivado_sim/rvfi_adapter/trace.compact.jsonl --stats
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.compact.jsonl --decompress --out results/vivado_sim/rvfi_adapter/trace.roundtrip.jsonl
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.jsonl --check-roundtrip --stats
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
```
