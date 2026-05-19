# RV-MalTrace Project Map

## Core Entry Points

- `pyproject.toml`: project metadata, `rvmt` CLI config, Vivado/board/toolchain settings.
- `src/rv_maltrace/cli.py`: task runner for Docker, toolchain, bootrom, Vivado, bitstream, sim, summary, and bare-metal builds.
- `Makefile`: thin wrappers around `uv run rvmt`.
- `docs/process/uv_workflow.md`: canonical command list.

## RTL and Simulation

- `rtl/trace/trace_pkg.sv`: event IDs, packet structures, filter/memory-mode constants.
- `rtl/trace/trace_top.sv`: top-level trace tap composition.
- `rtl/trace/*_tap.sv`: retire, branch, syscall, trap, context, and arg shadow tap logic.
- `rtl/trace/cva6_rvfi_trace_adapter.sv`: CVA6 RVFI committed stream to trace tap interface.
- `sim/tb/`: SystemVerilog testbenches, trace sink, scoreboard, memory model.
- `sim/vivado/`: xsim filelists and Tcl run scripts.
- `sim/golden/`: expected JSON/JSONL artifacts.
- `sim/programs/`: bare-metal programs and common runtime files.

## Python Tools

- `tools/build_baremetal.py`: builds bare-metal programs when toolchain is available.
- `tools/parse_trace.py`: parses trace output.
- `tools/compare_trace.py`: compares traces with expected files.
- `tools/compress_trace.py`: compact trace prototype and round-trip checking.
- `tools/recover_behavior.py`: behavior recovery logic and self-test.
- `tools/summarize_results.py`: result summaries.
- `tools/check_*.py`: structured documentation and experiment gates.

## Documentation

- `docs/planning/plan.md`: MVP phase plan.
- `docs/planning/next-plan.md`: paper-level next-stage plan.
- `docs/architecture/trace_format.md`: event semantics, packet fields, JSONL schema, comparison rules, filters, compression, memory mode.
- `docs/architecture/signal_map.md`: CVA6 signal attachment map and integration notes.
- `docs/architecture/timing_principles.md`: trace timing/critical-path guidance.
- `docs/architecture/trace_export_decision.md`: export-path decisions.
- `docs/process/version_lock.md`: reproducibility anchors.
- `docs/process/risk_log.md`: known risks and mitigations.
- `docs/reports/resource_report.md`: FPGA/resource reporting.

## Board and Linux Work

- `docs/board/board_bringup.md`
- `docs/board/baseline_bringup_runbook.md`
- `docs/board/baseline_pass_criteria.md`
- `docs/board/board_trace_minimal.md`
- `docs/board/board_trace_validation.md`
- `board/trace_validation/programs/`
- `board/trace_validation/expected/`
- `experiments/linux_behavior/`
- `docs/linux_*`
- `docs/research/semantic/semantic_enrichment_*`

## Common Validation Commands

```powershell
uv run rvmt config:show
uv run rvmt tasks:list
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:summary
uv run rvmt baremetal:build
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_trace_boundary.py
uv run python tools/check_timing_principles.py
uv run python tools/check_board_baseline.py
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_programs.py
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/check_semantic_enrichment_strategy.py
```

Pick the narrowest command that covers the touched surface. Do not claim Vivado, bitstream, or board validation unless those commands/procedures actually ran.
