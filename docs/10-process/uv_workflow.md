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
uv run rvmt sim:cva6-full-soc
uv run rvmt sim:cva6-full-soc-store
uv run rvmt sim:cva6-full-soc-tohost
uv run rvmt sim:cva6-full-soc-rv64gc
uv run rvmt sim:cva6-run --asm path\to\program.S --name custom_program
uv run rvmt sim:summary
uv run rvmt baremetal:build
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture
uv run rvmt demo:groundtruth --sample anti_debug_like
uv run rvmt bitstream:build
uv run rvmt bitstream:build-trace-marker
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
uv run python tools/check_genesys2_safe_surrogate.py
uv run python tools/capture_genesys2_runtime_process_map.py --self-test
uv run python tools/recover_behavior.py --self-test
uv run python tools/annotate_trace_disasm.py --self-test
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/audit_behavior.py --self-test
uv run python tools/check_linux_behavior_audit.py
uv run python tools/render_behavior_demo.py --self-test
uv run python tools/check_behavior_demo.py
uv run python tools/gen_rv_trace_fuzz.py --self-test
uv run python tools/check_fuzz_trace.py --self-test
uv run python tools/check_fuzz_trace_plan.py
uv run python tools/check_noninterference_gate.py
uv run python tools/analyze_trace_lightweight.py --self-test
uv run python tools/check_lightweight_trace_analysis.py
uv run python tools/check_semantic_enrichment_rationale.py
uv run python tools/check_semantic_enrichment_routes.py
uv run python tools/check_semantic_enrichment_strategy.py
uv run python tools/check_isa_behavior_portability.py
uv run python tools/check_evaluation_plan.py
uv run python tools/summarize_35t_baselines.py --self-test
uv run python tools/check_35t_baseline_evaluation.py --self-test
uv run python tools/check_35t_qemu_plugin_build_preflight.py --self-test
uv run python tools/check_35t_fd_path_case_studies.py --self-test
uv run python tools/check_35t_process_tree_case_study.py --self-test
uv run python tools/check_35t_pointer_semantics_preflight.py --self-test
uv run python tools/check_35t_pointer_snapshot_gate.py --self-test
uv run python tools/check_35t_pointer_snapshot_design_review.py --self-test
uv run python tools/check_35t_threat_model.py --self-test
uv run python tools/check_35t_helper_alignment.py --self-test
uv run python tools/check_35t_evaluation_table.py --self-test
uv run python tools/check_35t_metric_coverage.py --self-test
uv run python tools/check_35t_baseline_execution_spec.py --self-test
uv run python tools/check_35t_synthetic_suite_extension.py --self-test
uv run python tools/check_35t_synthetic_extension_host_smoke.py --self-test
uv run python tools/check_35t_synthetic_extension_target_smoke.py --self-test
uv run python tools/check_35t_synthetic_extension_behavior_smoke.py --self-test
uv run python tools/check_35t_extension_35t_enablement.py --self-test
uv run python tools/check_35t_raw_artifact_sanitization.py --self-test
uv run python tools/check_35t_raw_artifact_escrow.py --self-test
uv run python tools/check_35t_assessment_closure.py --self-test
uv run python tools/check_35t_assessment_traceability.py --self-test
uv run python tools/check_35t_assessment_requirement_matrix.py --self-test
uv run python tools/check_35t_remaining_external_work.py --self-test
uv run python tools/check_35t_paper_positioning.py --self-test
uv run python tools/check_35t_assessment_reconciliation.py --self-test
uv run python tools/check_35t_assessment_gate_criteria.py --self-test
uv run python tools/check_35t_hardware_trace_prototype.py --self-test
uv run python tools/check_35t_local_code_analysis.py --self-test
uv run python tools/check_35t_malware_behavior_audit.py --self-test
uv run python tools/check_35t_evidence_consistency.py --self-test
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
bitstream:build-trace Run a trace-enabled FPGA build into build/vivado/<board>-<target>-trace.
bitstream:build-trace-marker Run a trace-enabled FPGA build with marker-scope events into build/vivado/<board>-<target>-trace-marker.
bitstream:collect Copy existing CVA6 FPGA outputs into build/vivado/<board>-<target>.
sim:trace-unit    Run the trace_top unit regression in Vivado xsim and compare JSONL output.
sim:cva6-smoke    Compile/elaborate the direct CVA6 xsim testbench and run the trace/no-trace matrix.
sim:cva6-full-soc Compile/elaborate the ariane_testharness full SoC breakpoint smoke probe.
sim:cva6-full-soc-store Compile/elaborate the ariane_testharness full SoC UART/MMIO store-path probe.
sim:cva6-full-soc-tohost Compile/elaborate the ariane_testharness full SoC normal tohost/MMIO probe.
sim:cva6-full-soc-rv64gc Compile/elaborate one ariane_testharness snapshot and run RV64GC extension microprobes.
sim:cva6-run      Run one custom assembly, ELF, raw binary, or readmemh image through the direct CVA6 xsim testbench.
sim:summary       Summarize results/vivado_sim into a table and summary.json.
baremetal:build   Build all sim/programs bare-metal ELF/dump/bin artifacts when the RISC-V toolchain is available.
demo:behavior     Build a synthetic behavior demo evidence bundle from a fixture or user trace.
demo:groundtruth  Build and run a Linux synthetic sample under host strace and qemu-riscv64 strace in Docker.
config:show       Print resolved configuration.
tasks:list        Print task names.
completion:*      Print shell completion scripts.
```

Aliases:

```text
tool -> toolchain:build
bootrom -> bootrom:build
bitstream/fpga -> bitstream:build
bitstream:trace/fpga:trace -> bitstream:build-trace
bitstream:trace-marker/fpga:trace-marker -> bitstream:build-trace-marker
vivado:xpr -> vivado:project
sim/sim:unit/sim:trace -> sim:trace-unit
sim:cva6/sim:cva6-xsim -> sim:cva6-smoke
sim:full-soc/sim:fullsoc/sim:cva6-full-soc-smoke -> sim:cva6-full-soc
sim:cva6-full-soc-uart-store -> sim:cva6-full-soc-store
sim:full-soc-tohost -> sim:cva6-full-soc-tohost
sim:full-soc-rv64gc -> sim:cva6-full-soc-rv64gc
sim:run/sim:cva6-custom -> sim:cva6-run
summary -> sim:summary
baremetal/programs -> baremetal:build
demo -> demo:behavior
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
The full `ariane_testharness` SoC path is available as:

```powershell
uv run rvmt sim:cva6-full-soc
```

The full-SoC probe compiles and elaborates `ariane_testharness`, boots a
full-SoC-specific DRAM image at `0x8000_0000`, and terminates on a magic
breakpoint trap. It publishes
`results/vivado_sim/cva6_full_soc_smoke/{trace.jsonl,compare.log,run.log,xsim.log}`.
On 2026-05-17 this path passed locally on Vivado v2025.2; the direct-core matrix
remains the broader committed-trace execution gate because it still runs the
trace/no-trace program matrix and tohost-store checks.

The full-SoC UART/MMIO store-path probe is:

```powershell
uv run rvmt sim:cva6-full-soc-store
```

It boots a two-instruction DRAM image that sets the UART/MMIO base and commits a
store to `0x1000_0000`; the testbench uses `RVMT_STORE_PATH_ONLY` to pass when
that committed store is observed through RVFI. It publishes
`results/vivado_sim/cva6_full_soc_uart_store_path/{trace.jsonl,compare.log,run.log,xsim.log}`.
This is a store-path observation gate, not proof that a normal multi-instruction
full-SoC pseudo-tohost program can run to completion.

The normal full-SoC tohost/MMIO probe is:

```powershell
uv run rvmt sim:cva6-full-soc-tohost
```

It boots `sim/programs/full_soc_dram_tohost/full_soc_dram_tohost.mem` through
the full `ariane_testharness` and passes only when the testbench observes a
committed RVFI store to the tohost/MMIO address. It publishes
`results/vivado_sim/cva6_full_soc_tohost_normal/{trace.jsonl,compare.log,run.log,xsim.log}`.
This is stronger than the breakpoint smoke and does not use the
`RVMT_STORE_PATH_ONLY` shortcut, but it remains repository-local simulation
evidence rather than board or Linux validation. As of 2026-05-18 this gate
passes by observing a committed store to `0x1000_0000`.

The full-SoC RV64GC microprobe suite is:

```powershell
uv run rvmt sim:cva6-full-soc-rv64gc
```

It reuses one full `ariane_testharness` elaboration and runs short
per-extension probes under retire-count completion. Current evidence is
minimum full-SoC RV64GC coverage: `I`, `M`, `A`, `F`, `D`, and `C` probes all
PASS. The `F` and `D` probes use the simulation-only `RVMT_FORCE_FS_DIRTY`
plusarg to model an M-mode runtime with floating-point state enabled. This
command is a coverage frontier, not a claim that arbitrary RV64GC programs,
riscv-tests, Linux, or board execution pass in full SoC.

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
For `--asm` and `--elf` inputs, the runner also publishes `program.dump` and
`trace.disasm.jsonl`.

When `riscv-none-elf-*` is not on the host `PATH`, `sim:cva6-run` falls back to
the existing `docker-compose.toolchain.yml` service for `--asm` and `--elf`
tool steps. Use `--tool-mode docker` to force the container, or
`--tool-mode local` to require host tools.

Trace disassembly is a derived annotation step. Keep `trace.jsonl` as the raw
capture, then generate `trace.disasm.jsonl` when an ELF or objdump dump is
available. This is automatic for `sim:cva6-run --asm` and `sim:cva6-run --elf`;
the manual command is useful for existing traces:

```powershell
uv run python tools/annotate_trace_disasm.py --trace results/vivado_sim/demo/trace.jsonl --elf build/demo.elf --out results/vivado_sim/demo/trace.disasm.jsonl
uv run python tools/annotate_trace_disasm.py --trace results/vivado_sim/demo/trace.jsonl --objdump build/demo.dump --out results/vivado_sim/demo/trace.disasm.jsonl --strict
uv run python tools/annotate_trace_disasm.py --self-test
```

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
reports, the optional trace-enabled Vivado reports, and the latest trace
simulation summary:

```powershell
uv run rvmt bitstream:build-trace
uv run python tools/generate_resource_report.py
uv run python tools/generate_resource_report.py --self-test
```

The generated report is `docs/07-evaluation-evidence/reports/resource_report.md`. When
`build/vivado/genesys2-cv64a6_imafdc_sv39-trace/reports/{ariane.utilization.rpt,ariane.timing.rpt}`
exists, the report includes the routed baseline-vs-trace FPGA delta.

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
bare-metal runtime observations are still recorded in `docs/03-platform-architecture/genesys2/board_bringup.md`.
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

Phase 4.3 is documented in `docs/03-platform-architecture/genesys2/baseline_bringup_runbook.md`. The runbook
records the required order: LED/clock/reset sanity, UART hello, minimal RISC-V
core boot, CVA6 bare-metal boot, and optional Linux boot. It is a procedure and
does not claim physical board success until logs are captured under
`results/board/genesys2_baseline/<run-id>/`.

```powershell
uv run python tools/check_bringup_runbook.py
uv run python tools/check_bringup_runbook.py --self-test
```

## Baseline Pass Criteria

Phase 4.4 is tracked in `docs/03-platform-architecture/genesys2/baseline_pass_criteria.md`. The checker keeps
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

Phase 5.1 is tracked in `docs/02-trace-architecture/trace_export_decision.md`. The first board export
path is BRAM ring buffer plus ILA/JTAG dump; UART streaming and AXI
DMA/Ethernet streaming are deferred.

```powershell
uv run python tools/check_trace_export_decision.py
uv run python tools/check_trace_export_decision.py --self-test
```

## Board Trace Minimal Policy

Phase 5.2 is tracked in `docs/03-platform-architecture/genesys2/board_trace_minimal.md`. The first board trace
wrapper is `rtl/trace/trace_board_minimal_top.sv`: full retire, jump, and marker
events stay off; syscall, trap, context, branch, and drop accounting stay on.
The `board_minimal` trace-unit regression exercises the profile wiring.

```powershell
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_minimal.py --self-test
```

## Board Trace Validation Programs

Phase 5.3 is tracked in `docs/03-platform-architecture/genesys2/board_trace_validation.md` and
`board/trace_validation/manifest.json`. The first board validation set is:
hello/write, file open/read/write/close, fork/exec/wait, and illegal instruction
trap.

```powershell
uv run python tools/check_board_trace_programs.py
uv run python tools/check_board_trace_programs.py --self-test
```

The 2026-06-09 Genesys2/CVA6 trace validation run proves that the current ILA
can capture syscall entries and syscall returns, but it has not yet captured a
target syscall entry and its matching return in one window. For the next paired
syscall capture attempt, rebuild the trace bitstream with a larger ILA window
or storage qualification enabled; the `xlnx_ila` generator accepts these
environment variables:

```powershell
$env:RVMT_ILA_DATA_DEPTH = "4096"
$env:RVMT_ILA_STORAGE_QUAL = "1"
$env:RVMT_ILA_ADV_TRIGGER = "TRUE"
uv run rvmt bitstream:build-trace
```

Record the generated `RVMT_ILA_*` lines from the Vivado/IP build log and pass
the matching values into `tools/package_genesys2_trace_evidence.py` with
`--ila-data-depth`, `--ila-storage-qualification`, and
`--ila-advanced-trigger`. Do not claim paired syscall evidence until a decoded
single capture contains both the target `SYSCALL_ENTRY` and `SYSCALL_RET`.

## Linux Behavior Experiment Principles

Phase 6.1 is tracked in `docs/04-runtime-linux/linux_behavior_experiment_principles.md` and
`experiments/linux_behavior/policy.json`. Early experiments must use benign and
malware-like synthetic programs only; real malware and unknown-provenance
binaries stay forbidden.

```powershell
uv run python tools/check_linux_behavior_principles.py
uv run python tools/check_linux_behavior_principles.py --self-test
```

## Linux Benign Dataset

Phase 6.2 is tracked in `docs/04-runtime-linux/linux_benign_dataset.md` and
`experiments/linux_behavior/benign/manifest.json`. The benign set covers hello,
`ls`, `cat`, `cp`, `sha256sum`, and an optional small network client that stays
disabled by default unless a planned target network setup is available.

```powershell
uv run python tools/check_linux_benign_dataset.py
uv run python tools/check_linux_benign_dataset.py --self-test
```

## Linux Malware-like Synthetic Dataset

Phase 6.3 is tracked in `docs/04-runtime-linux/linux_malware_like_dataset.md` and
`experiments/linux_behavior/malware_like/manifest.json`. The synthetic set
covers file scanning, batch open/read/write, self-copy simulation, abnormal
syscall sequences, illegal-instruction trap behavior, process creation chains,
dynamic executable memory transitions, and anti-debug-like timing indicators.
It does not include real malware.

```powershell
uv run python tools/check_linux_malware_like_dataset.py
uv run python tools/check_linux_malware_like_dataset.py --self-test
```

## Genesys2 Safe Surrogate Evidence

Genesys2/CVA6 safe surrogate evidence is gated under
`results/board/genesys2_cva6_safe_surrogate/<run-id>/`. The checker verifies
that every listed sample remains synthetic/surrogate only, carries the required
hardware trace, local code analysis, behavior mapping, and integrated validation
artifacts, and keeps real malware and 35T out of current Genesys2/CVA6 claims.

```powershell
uv run python tools/check_genesys2_safe_surrogate.py
uv run python tools/check_genesys2_safe_surrogate.py --self-test
```

Build the marker-scope trace bitstream before claiming marker-scoped board
evidence, then program the Genesys2 via on-board JTAG and the local
`hw_server`:

```powershell
uv run rvmt bitstream:build-trace-marker
D:\Application\vivado\2025.2\Vivado\bin\vivado.bat -mode batch -source tools\program_genesys2_bitstream.tcl -tclargs build\vivado\genesys2-cv64a6_imafdc_sv39-trace-marker\work-fpga\ariane_xilinx.bit build\vivado\genesys2-cv64a6_imafdc_sv39-trace-marker\work-fpga\ariane_xilinx.ltx localhost:3121
```

To capture `/proc/<pid>/maps` ownership evidence for a Genesys2/CVA6 board run,
emit a shell command and send it over the board UART with
`tools/serial_direct_command_capture.py`, then parse the UART log:

```powershell
uv run python tools/capture_genesys2_runtime_process_map.py --emit-command-b64 --sample-id illegal_trap --runtime-path /tmp/rvmt_p2/illegal_trap --warmup
uv run python tools/capture_genesys2_runtime_process_map.py --parse-log results/board/genesys2_cva6_safe_surrogate/<run-id>/<sample>/runtime_process_map_capture.log --out results/board/genesys2_cva6_safe_surrogate/<run-id>/<sample>/runtime_process_map.json
```

The resulting `rvmt.runtime_process_map.v1` artifact is necessary but not
sufficient for strong process attribution. Strong attribution still requires a
valid hardware marker scope in the decoded trace.

## Linux Behavior Recovery Targets

Phase 6.4 is tracked in `docs/04-runtime-linux/linux_behavior_recovery_targets.md` and
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

Phase 6.5 is tracked in `docs/04-runtime-linux/linux_behavior_audit.md` and
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

## Behavior Demo Evidence Bundle

The behavior demo is tracked in `docs/04-runtime-linux/behavior_demo.md`. It stitches a checked
RV-MalTrace fixture trace or a user-provided trace through recovery, rule-based
audit, and static rendering. The default output root is:

```text
results/demo/<run-id>/<sample-id>/
```

Use the fixture backend for a board-free, deterministic smoke:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture --run-id smoke --out-dir build/demo_behavior_smoke
```

Use the trace backend after a real simulation, Linux, or board trace exists:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend trace --trace results/vivado_sim/<case>/trace.jsonl
```

Ground truth uses the separate `linux-behavior` Docker service. It builds the
repository-authored Linux C sample and captures host `strace` plus
`qemu-riscv64 -strace` transcripts:

```powershell
uv run rvmt demo:groundtruth --sample anti_debug_like
uv run rvmt demo:groundtruth --sample file_scan --run-id smoke --out-dir build/demo_behavior_smoke
```

Validate the demo support without requiring Docker:

```powershell
uv run python tools/render_behavior_demo.py --self-test
uv run python tools/check_behavior_demo.py
uv run python tools/check_behavior_demo.py --self-test
```

The demo output is not malware detection quality evidence, Linux-on-board
evidence, or physical hardware validation.

## 35T Experiment Matrix

The Artix-7 35T LiteX/VexRiscv paper route uses a unified runner for the
non-network benign set plus the eight malware-like synthetic samples. It writes
artifacts under:

```text
results/experiments/35t/<run-id>/
```

Dry-run the full matrix without accessing the board:

```powershell
uv run rvmt exp:35t --stage all --run-id dryrun --dry-run
```

Run the default 35T route on the connected CH340 console after the trace image
and experiment rootfs are ready:

```powershell
uv run rvmt exp:35t --stage all --run-id <run-id> --port COM5 --baud 921600 --reps 5
```

Stages may be run separately with `--stage groundtruth`, `rootfs`, `board`,
`analyze`, or `report`. The board rootfs includes `/usr/bin/rvmt_exp_runner` and
`/usr/bin/rvmt_benign_workload`; the runner emits `RVMT_EXP_*` markers, captures
trace-on and trace-off repetitions, and keeps real malware plus network samples
out of this matrix.

Validate a finished bundle with:

```powershell
uv run python tools/experiment_35t.py --stage self-test
uv run python tools/check_35t_experiment_bundle.py --run-id <run-id> --reps 5
uv run python tools/check_35t_experiment_bundle.py --self-test
```

## Bounded Fuzz Trace Validation

Phase 8 trace-validator fuzzing is tracked in `docs/06-validation-gates/fuzz_trace_validation.md`
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

Phase 3.4 is tracked in `docs/06-validation-gates/noninterference_resource_gate.md` and
`experiments/hardware/noninterference_gate.json`. The gate keeps current
evidence limited to sideband trace capture, drop accounting, direct-core
trace/no-trace parity, routed trace-enabled resource delta, and board-free
noninterference evidence.

```powershell
uv run python tools/generate_noninterference_report.py --self-test
uv run python tools/generate_noninterference_report.py --out-dir build/noninterference_gate
uv run python tools/check_noninterference_gate.py
uv run python tools/check_noninterference_gate.py --self-test
```

## Lightweight Trace Analysis

Phase 9.1 is tracked in `docs/05-semantic-analysis/lightweight_trace_analysis.md` and
`experiments/analysis/lightweight_trace_profile.json`. The analysis tool reads
trace JSONL, checks event-selective profiles, and reports compact trace volume
without claiming runtime overhead or detection quality.

```powershell
uv run python tools/analyze_trace_lightweight.py --self-test
uv run python tools/analyze_trace_lightweight.py --trace results/vivado_sim/board_minimal/trace.jsonl --profile board_minimal --out-dir build/lightweight_trace_smoke
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
uv run python tools/check_lightweight_trace_analysis.py
uv run python tools/check_lightweight_trace_analysis.py --self-test
```

## ISA Behavior Portability

Phase 10.1 is tracked in `docs/05-semantic-analysis/isa_behavior_portability.md` and
`experiments/analysis/isa_behavior_portability.json`. The rubric keeps the
x86-to-RISC-V comparison at the behavior semantics layer instead of raw opcode
translation.

```powershell
uv run python tools/check_isa_behavior_portability.py
uv run python tools/check_isa_behavior_portability.py --self-test
```

## Semantic Enrichment Rationale

Phase 7.1 is tracked in `docs/05-semantic-analysis/semantic_enrichment_rationale.md` and
`experiments/linux_behavior/semantic_enrichment_rationale.json`. eBPF, kernel
helpers, and memory snapshots are deferred optional semantic enrichment; the
core contribution remains RTL-level committed behavior trace.

```powershell
uv run python tools/check_semantic_enrichment_rationale.py
uv run python tools/check_semantic_enrichment_rationale.py --self-test
```

## Semantic Enrichment Routes

Phase 7.2 is tracked in `docs/05-semantic-analysis/semantic_enrichment_routes.md` and
`experiments/linux_behavior/semantic_enrichment_routes.json`. The three routes
are selective memory snapshot, kernel helper metadata, and eBPF metadata
alignment; all remain deferred until the FPGA trace path works.

```powershell
uv run python tools/check_semantic_enrichment_routes.py
uv run python tools/check_semantic_enrichment_routes.py --self-test
```

## Semantic Enrichment Strategy

Phase 7.3 is tracked in `docs/05-semantic-analysis/semantic_enrichment_strategy.md` and
`experiments/linux_behavior/semantic_enrichment_strategy.json`. The recommended
order is: MVP without eBPF/kernel-helper/memory-snapshot dependency; after FPGA
trace works, evaluate selective memory snapshot; after Linux experiments,
optionally add eBPF metadata alignment.

```powershell
uv run python tools/check_semantic_enrichment_strategy.py
uv run python tools/check_semantic_enrichment_strategy.py --self-test
```

## Evaluation Plan

Paper-level evaluation planning is tracked in `docs/07-evaluation-evidence/evaluation_plan.md`. It
keeps the RQ, baseline, dataset, metric, and artifact gates in TODO status until
simulation, board, Linux, or study evidence exists.

```powershell
uv run python tools/check_evaluation_plan.py
uv run python tools/check_evaluation_plan.py --self-test
```

## 35T Assessment Closure

The assessment closure checker maps the 35T assessment goals to bounded current
evidence. It treats fd/path and process-tree representative closure as PASS,
uses the bounded baseline summary/check when available, reads trusted helper
alignment, pointer snapshot design review, and the synthetic suite extension
gate when present, and keeps hardware pointer snapshots, implemented expanded
sample coverage, and full public paper artifact release as bounded remaining
work unless corresponding evidence exists.

```powershell
uv run python tools/check_35t_assessment_closure.py --self-test
uv run python tools/check_35t_fd_path_case_studies.py --repo-root .
uv run python tools/check_35t_process_tree_case_study.py --repo-root .
uv run python tools/check_35t_helper_alignment.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_design_review.py --repo-root .
uv run python tools/check_35t_assessment_closure.py --repo-root .
uv run python tools/check_35t_assessment_traceability.py --repo-root .
uv run python tools/check_35t_assessment_requirement_matrix.py --repo-root .
uv run python tools/check_35t_remaining_external_work.py --repo-root .
uv run python tools/check_35t_paper_positioning.py --repo-root .
uv run python tools/check_35t_assessment_reconciliation.py --repo-root .
uv run python tools/check_35t_assessment_gate_criteria.py --repo-root .
uv run python tools/check_35t_evidence_consistency.py --no-write
```

The traceability checker reads the assessment source document and maps P0-P6 to
current evidence files, accepted statuses, and remaining bounded conditions. It
is a requirement-to-evidence audit and does not upgrade deferred hardware,
baseline, extension, or full artifact work to completed status.

The requirement matrix checker reads the same source assessment section by
section. It verifies the overall conclusion, evidence chain, 3.1 hardware trace,
3.2 local code analysis, 3.3 synthetic malware-analysis boundary, P1-P6 follow-up
items, CCF-A positioning, and final judgment against current evidence while
keeping P3-P6 external conditions explicit.

The remaining external work checker records the P3-P6 conditions that still
need hardware enablement, capable baseline environments, 35T extension gating,
or raw artifact sanitization/approval before their bounded statuses can be
upgraded. It separately records satisfied preconditions such as representative
trusted-helper alignment, host/target extension compile smoke, and host eBPF
baseline evidence.

The paper positioning checker records the assessment's publication boundary:
35T evidence is a low-cost FPGA feasibility / constrained-board prototype
result, not a standalone CCF-A main contribution, real malware detection claim,
CVA6 validation, mature detector, or complete semantic reconstruction claim.

The assessment reconciliation checker treats the source assessment as a
snapshot and records how current evidence updates earlier PARTIAL/BLOCKED
statements, without silently completing deferred P3-P6 external work.

The assessment gate criteria checker independently verifies the concrete gate
conditions named by the assessment: 512 records, 13/13 sample PASS, marker
scope, runtime process attribution, UNKNOWN/corrupt, DROP/cap, strong expected
rules, bounded benign overlap, and per-sample trace profile policy.

The hardware trace prototype checker independently verifies the assessment's
3.1 claim. It ties the 512-record 35T gate, small-capacity per-sample profile
policy, decoded trace artifacts, marker/runtime attribution, UNKNOWN/corrupt,
DROP, and cap-hit evidence together without inferring CVA6 validation.

The local code analysis checker independently verifies the assessment's 3.2
claim. It requires all 13 samples and all 65 trace-on repetitions to have board
ELF code maps, trace-code joins, runtime process maps, semantic recovery
outputs, behavior graphs, and rule-based audit files. It keeps PC-in-ELF,
process ownership, source-line attribution, and real malware detection as
explicit boundaries rather than upgraded claims.

The malware behavior audit checker independently verifies the assessment's 3.3
claim. It checks the 8-rule synthetic malware-like suite against the rules
file, manifest, aggregate 35T gate, and per-repetition audit artifacts while
keeping real malware execution, detector accuracy, family classification, IOC
coverage, and TTP coverage out of scope.

The evidence consistency checker is read-only. It verifies that
`evidence_manifest.json`, `assessment_closure.json`,
`assessment_traceability.json`, `assessment_requirement_matrix.json`,
`artifact_package_readiness.json`, and `paper_artifact_package_manifest.json`
agree on status, artifact counts, manifest hashes, source-section coverage,
hardware-trace evidence, local-code-analysis evidence, malware-behavior-audit
evidence, helper-alignment evidence, and package validation commands.

## 35T Pointer Semantics Preflight

The pointer semantics preflight records the P3 boundary for the 35T evidence:
synthetic ARG_MEM simulation covers pointer strings and guardrails, and the
targeted board syscall side-channel closes representative fd/path and
process-tree semantics, but hardware user-pointer snapshots remain deferred and
default-disabled in the current 35T small-capacity run.

```powershell
uv run python tools/check_35t_pointer_semantics_preflight.py --self-test
uv run python tools/check_35t_pointer_semantics_preflight.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_gate.py --self-test
uv run python tools/check_35t_pointer_snapshot_gate.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_design_review.py --self-test
uv run python tools/check_35t_pointer_snapshot_design_review.py --repo-root .
uv run python tools/check_35t_helper_alignment.py --self-test
uv run python tools/check_35t_helper_alignment.py --repo-root .
```

The pointer snapshot gate records the requirements that must be met before
hardware user-pointer capture can be enabled: design review, default-disabled
safety guardrails, timing/resource data, bandwidth/drop accounting,
noninterference, semantic accuracy, artifact release policy, and the trusted
kernel/user-mode threat boundary.

The pointer snapshot design-review checker records the bounded current design
state for that route: selective `openat`/`execve` pathname-prefix capture,
64-byte limits, default-disabled policy, no default memory-trace payload mode,
and no hardware snapshot or measurement pass claim.

## 35T Threat Model Boundary

The threat model checker records the P3 trusted-kernel boundary requested by
the assessment. It verifies that helper/eBPF semantic companions stay bounded
to trusted-kernel companion evidence, that the current attacker model is a
user-mode malware-like workload under a trusted Linux kernel, and that kernel
rootkit resistance is explicitly out of scope.

```powershell
uv run python tools/check_35t_threat_model.py --self-test
uv run python tools/check_35t_threat_model.py --repo-root .
uv run python tools/check_35t_helper_alignment.py --self-test
uv run python tools/check_35t_helper_alignment.py --repo-root .
```

The helper alignment checker records the representative P3 side-channel route
that is now satisfied: fd/path and process-tree helper evidence is aligned with
the targeted 35T dual-channel board validation bundle. It does not claim a
hardware user-pointer memory snapshot, hardware-only tracing, complete semantic
reconstruction, QEMU-plugin evidence, or malicious-kernel resistance.

## 35T fd/path Case Studies

The fd/path case-study checker records the P1 scope called out by the assessment:
`file_scan`, `batch_open_read_write`, and `self_copy_sim`. It replays the
targeted board-validation syscall side-channel for each sample, recovers closed
fd/path flows, and keeps unresolved fields explicit so the compact
`fd_path_flow_summary.json` is not over-read as full-suite coverage.

```powershell
uv run python tools/check_35t_fd_path_case_studies.py --self-test
uv run python tools/check_35t_fd_path_case_studies.py --repo-root .
```

## 35T Process Tree Case Study

The process-tree case-study checker records the P2 scope called out by the
assessment for `process_chain`. It replays the targeted board-validation
syscall side-channel, verifies positive clone child PIDs, child execve path
strings, parent wait PID arguments, and emits the parent-child graph lines.
The parent PID remains explicitly unresolved unless PID/SATP/ASID or equivalent
ownership evidence exists.

```powershell
uv run python tools/check_35t_process_tree_case_study.py --self-test
uv run python tools/check_35t_process_tree_case_study.py --repo-root .
```

## 35T Bounded Evaluation Table

The bounded evaluation table combines the currently available P4 evidence:
host/QEMU/strace timing baselines, software instrumentation, host eBPF/bpftrace
baseline evidence, board trace-on/off ratios, DROP/cap accounting, resource/Fmax
summaries, and the synthetic `anti_debug_like` behavior check. It keeps
QEMU-plugin non-PASS unless separate per-sample plugin evidence exists.

```powershell
uv run python tools/check_35t_evaluation_table.py --self-test
uv run python tools/check_35t_evaluation_table.py --repo-root .
```

## 35T Metric Coverage

The metric coverage checker enumerates the P4 metric list from the assessment
and ties each item to current evidence. It marks alignment precision/recall,
return pairing, and argument reconstruction as measured proxies; fd/path and
process graph accuracy as case-study measured; resource, timing, DROP, trace
bytes, and synthetic anti-debug evidence as measured or bounded. It keeps
full-suite semantic accuracy and advanced baseline perturbation deferred where
the current repository lacks stronger evidence.

```powershell
uv run python tools/check_35t_metric_coverage.py --self-test
uv run python tools/check_35t_metric_coverage.py --repo-root .
```

## 35T Baseline Execution Spec

The baseline execution spec maps the assessment's P4 baseline families to
current evidence rows, reproduction commands, required artifacts, pass gates,
and non-substitution rules. It keeps eBPF-only, QEMU-plugin, pointer snapshot,
and helper/companion rows from being treated as complete until their separate
environment and run evidence exists.

```powershell
uv run python tools/check_35t_baseline_execution_spec.py --self-test
uv run python tools/check_35t_baseline_execution_spec.py --repo-root .
```

## 35T Synthetic Suite Extension

The synthetic suite extension checker verifies that the current malware-like
suite remains synthetic-only, non-destructive, and network-free while recording
source-implemented disabled-by-default extension candidates and the gates
required before real malware could enter scope. Passing this checker means P5
has source-ready extension candidates; it does not claim expanded sample
coverage until the new samples are explicitly enabled, built, and run through
the same 35T gates. The host smoke checker adds a compile-only preflight: on
Linux, or on Windows with WSL compiler access, it compiles all extension
sources. Hosts without Linux/WSL compiler access record an explicit environment
blocker. The target smoke checker cross-compiles static RISC-V Linux ELFs. The
behavior smoke checker then executes the 8 non-network candidates under host
native, host strace, QEMU native, and QEMU guest strace, while keeping the
loopback network candidate skipped by default. These checks do not count as 35T
gating. The extension enablement preflight verifies the next step in that
chain: extension candidates are present in the 35T runner and rootfs build
path, stay disabled by default, and can be selected only through explicit
`experiment_35t.py --include-extension-samples` dry-run commands. It still does
not execute the board or count as expanded 35T coverage.

```powershell
uv run python tools/check_35t_synthetic_suite_extension.py --self-test
uv run python tools/check_35t_synthetic_suite_extension.py --repo-root .
uv run python tools/check_35t_synthetic_extension_host_smoke.py --self-test
uv run python tools/check_35t_synthetic_extension_host_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_target_smoke.py --self-test
uv run python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_behavior_smoke.py --self-test
uv run python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .
uv run python tools/check_35t_extension_35t_enablement.py --self-test
uv run python tools/check_35t_extension_35t_enablement.py --repo-root .
```

## 35T Baseline Evaluation

The baseline summary reads the 35T aggregate metrics and records which baseline
families have evidence. Host native, host strace, QEMU native, and QEMU strace
are treated as present only when all 13 samples have timing fields. The
software-instrumentation baseline is treated as present only when the separate
`35t-software-instrumentation-baseline-20260523` summary reports 13/13 PASS.
The eBPF-only baseline is treated as present only when
`ebpf_baseline_summary.json` reports 13/13 PASS from the
`35t-ebpf-baseline-20260523` bpftrace run. The QEMU-plugin baseline is treated
as present only when `qemu_plugin_baseline_summary.json` reports
`QEMU_PLUGIN_BASELINE_PASS_13_SAMPLES` for 13/13 samples from the
`35t-qemu-plugin-baseline-20260523` user-mode TCG-plugin run. The advanced
baseline preflight remains a packaged-environment capability boundary and does
not combine prerequisites across Docker `linux-behavior` and WSL environments.
The QEMU-plugin build preflight is a narrower P4 prerequisite check: it fetches
the official QEMU 8.2.2 plugin header at probe time, builds a minimal TCG
plugin, and verifies `qemu-system-riscv64 -plugin` loads it. The 13-sample
baseline itself is supplied by `run_35t_qemu_plugin_baseline.py`, which uses a
local upstream QEMU 8.2.2 `qemu-riscv64` build configured with
`--enable-plugins`. This simulator syscall-count evidence is not hardware trace,
DBI, or real malware evidence.

```powershell
uv run python tools/check_35t_advanced_baseline_preflight.py --self-test
uv run python tools/check_35t_advanced_baseline_preflight.py --repo-root .
uv run python tools/check_35t_qemu_plugin_build_preflight.py --self-test
uv run python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .
uv run python tools/run_35t_qemu_plugin_baseline.py --self-test
uv run python tools/run_35t_qemu_plugin_baseline.py --repo-root . --reps 3
uv run python tools/run_35t_software_instrumentation_baseline.py --self-test
uv run python tools/run_35t_software_instrumentation_baseline.py --reps 5
uv run python tools/run_35t_ebpf_baseline.py --self-test
uv run python tools/run_35t_ebpf_baseline.py --reps 3
uv run python tools/summarize_35t_baselines.py --self-test
uv run python tools/summarize_35t_baselines.py --repo-root .
uv run python tools/check_35t_evaluation_table.py --self-test
uv run python tools/check_35t_evaluation_table.py --repo-root .
uv run python tools/check_35t_baseline_execution_spec.py --self-test
uv run python tools/check_35t_baseline_execution_spec.py --repo-root .
uv run python tools/check_35t_metric_coverage.py --self-test
uv run python tools/check_35t_metric_coverage.py --repo-root .
uv run python tools/check_35t_threat_model.py --self-test
uv run python tools/check_35t_threat_model.py --repo-root .
uv run python tools/check_35t_baseline_evaluation.py --self-test
uv run python tools/check_35t_baseline_evaluation.py --repo-root .
```

## 35T Hardware Trace Prototype

The hardware trace prototype checker turns the assessment's section 3.1 claim
into a machine-readable gate. It verifies the 512-record primary 35T run,
small-capacity per-sample profile policy, trace-control masks, 13/13 sample
gate PASS, marker/runtime attribution, UNKNOWN/corrupt zero, DROP/cap limits,
and 65 nonempty decoded trace artifacts. It is scoped to the 35T
LiteX/VexRiscv run and does not imply CVA6 validation.

```powershell
uv run python tools/check_35t_hardware_trace_prototype.py --self-test
uv run python tools/check_35t_hardware_trace_prototype.py --repo-root .
```

## 35T Local Code Analysis

The local code analysis checker turns the assessment's section 3.2 claim into a
machine-readable gate. It checks code-map generation, trace-code join,
runtime-process-map attribution, behavior recovery, behavior graph, and
rule-based audit outputs across the full 13-sample, 65-repetition trace-on
matrix. Passing status is prototype-level attribution only; it does not imply
complete process ownership, source-line attribution, complete semantic
reconstruction, or real malware detection quality.

```powershell
uv run python tools/check_35t_local_code_analysis.py --self-test
uv run python tools/check_35t_local_code_analysis.py --repo-root .
```

## 35T Malware Behavior Audit

The malware behavior audit checker turns the assessment's section 3.3 claim
into a machine-readable gate. It requires the 8 current synthetic
malware-like samples to remain synthetic-only, non-destructive, and
network-free; verifies that every expected rule is matched in the aggregate
35T gate; and checks that behavior audit artifacts record the non-claim that
this is synthetic triage, not real malware detection quality evidence.

```powershell
uv run python tools/check_35t_malware_behavior_audit.py --self-test
uv run python tools/check_35t_malware_behavior_audit.py --repo-root .
```

## 35T Artifact Package Readiness

The artifact package readiness checker verifies the paper artifact inventory
without copying large raw outputs into the lightweight snapshot. It accounts for
run config, raw UART logs, decoded traces, runtime process maps, code maps,
trace-code joins, semantic events, behavior graphs, audits, alignment, metrics,
resource/timing reports, ELF hashes, bitstream metadata, scripts/commands,
source-implemented synthetic extension candidates, negative cases, and
reproduction notes. The raw artifact path also has a local controlled escrow
package for full raw UART and decoded trace payloads; it is not a public raw
release.

```powershell
uv run python tools/check_35t_artifact_package_readiness.py --self-test
uv run python tools/check_35t_fd_path_case_studies.py --repo-root .
uv run python tools/check_35t_process_tree_case_study.py --repo-root .
uv run python tools/check_35t_threat_model.py --repo-root .
uv run python tools/check_35t_helper_alignment.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_gate.py --repo-root .
uv run python tools/check_35t_pointer_snapshot_design_review.py --repo-root .
uv run python tools/check_35t_metric_coverage.py --repo-root .
uv run python tools/check_35t_baseline_execution_spec.py --repo-root .
uv run python tools/check_35t_qemu_plugin_build_preflight.py --repo-root .
uv run python tools/check_35t_synthetic_suite_extension.py --repo-root .
uv run python tools/check_35t_synthetic_extension_host_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_target_smoke.py --repo-root .
uv run python tools/check_35t_synthetic_extension_behavior_smoke.py --repo-root .
uv run python tools/check_35t_extension_35t_enablement.py --repo-root .
uv run python tools/check_35t_raw_artifact_sanitization.py --repo-root .
uv run python tools/check_35t_raw_artifact_escrow.py --repo-root .
uv run python tools/check_35t_artifact_package_readiness.py --repo-root .
uv run python tools/package_35t_paper_artifacts.py --self-test
uv run python tools/package_35t_paper_artifacts.py --repo-root .
uv run python tools/check_35t_assessment_traceability.py --repo-root .
uv run python tools/check_35t_assessment_requirement_matrix.py --repo-root .
uv run python tools/check_35t_remaining_external_work.py --repo-root .
uv run python tools/check_35t_paper_positioning.py --repo-root .
uv run python tools/check_35t_assessment_reconciliation.py --repo-root .
uv run python tools/check_35t_assessment_gate_criteria.py --repo-root .
uv run python tools/check_35t_hardware_trace_prototype.py --repo-root .
uv run python tools/check_35t_local_code_analysis.py --repo-root .
uv run python tools/check_35t_malware_behavior_audit.py --repo-root .
uv run python tools/check_35t_evidence_consistency.py --no-write
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
