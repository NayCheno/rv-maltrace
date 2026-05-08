---
name: rv-maltrace
description: Repository-specific workflow for RV-MalTrace, a CVA6/RISC-V hardware-assisted malware behavior tracing project. Use when Codex works in this repository on RTL trace taps, Vivado/xsim simulation, CVA6 integration, board bring-up, trace JSONL/golden files, behavior recovery experiments, project documentation, validation gates, or research-plan changes.
---

# RV-MalTrace

Use this skill to keep RV-MalTrace work aligned with mature open-source hardware practice: stage-gated bring-up, reproducible evidence, golden trace comparison, small reviewable changes, and explicit separation between simulation claims and physical-board claims.

## First Steps

1. Confirm the repo root by finding `pyproject.toml` with `name = "rv-maltrace"`.
2. Read the most relevant local docs before editing:
   - `docs/uv_workflow.md` for commands and configuration.
   - `docs/trace_format.md` before changing trace packets, JSONL, parser, compressor, or goldens.
   - `docs/signal_map.md` before touching CVA6 adapter or RTL tap attachment points.
   - `docs/plan.md` and `docs/next-plan.md` before changing project direction.
   - Board docs under `docs/board_*.md` before claiming board progress.
3. Inspect current diffs with `git status --short` and preserve user changes.
4. Prefer the repository entry points over ad hoc commands:
   - `uv run rvmt tasks:list`
   - `uv run rvmt config:show`
   - `uv run rvmt sim:trace-unit`
   - `uv run rvmt sim:cva6-smoke`
   - `uv run rvmt sim:summary`
   - `uv run python tools/<check_name>.py`

## Workflow

### RTL or CVA6 Trace Changes

Keep trace logic sideband-only. Do not add core backpressure for trace collection. When queues overflow, drop trace records and emit/account for `EVT_DROP`.

Before editing, read:

- `references/project-map.md`
- `docs/trace_format.md`
- `docs/signal_map.md`
- the touched files under `rtl/trace/`

Validation expectations:

- Run `uv run rvmt sim:trace-unit` for trace RTL changes.
- Run `uv run rvmt sim:cva6-smoke` for CVA6 adapter or CVA6 integration changes when Vivado is available.
- Run `uv run rvmt sim:summary` after simulation results exist.
- Update matching golden files only when the semantic expectation intentionally changes; explain why.

### Parser, Decoder, Golden, or Experiment Changes

Treat JSONL as the stable behavioral interface between RTL/sim and Python tools. Keep comparison rules explicit and avoid silently relaxing checks.

Before editing, read:

- `docs/trace_format.md`
- `tools/compare_trace.py`
- `tools/parse_trace.py`
- relevant files under `sim/golden/`, `board/trace_validation/expected/`, or `experiments/linux_behavior/`

Validation expectations:

- Run the narrow tool self-test if present, for example `uv run python tools/recover_behavior.py --self-test`.
- Run the matching `tools/check_*.py` gate for docs or experiment metadata.
- Preserve deterministic output ordering for JSON/JSONL artifacts.

### Documentation or Research Plan Changes

Use docs as executable intent, not prose-only planning. Tie claims to gates, artifacts, or explicit assumptions.

Before editing, read:

- `references/open-source-patterns.md`
- the target doc
- adjacent check script under `tools/check_*.py` if one exists

Validation expectations:

- Run the corresponding `uv run python tools/check_*.py` gate when available.
- Do not mark board evidence PASS unless artifacts exist under the documented `results/board/.../<run-id>/` path.
- Distinguish `TODO`, `PASS`, `BLOCKED`, and `BOARD` statuses.

### Board Bring-Up Changes

Separate repository-local build evidence from physical board evidence.

Before editing, read:

- `docs/baseline_bringup_runbook.md`
- `docs/baseline_pass_criteria.md`
- `docs/board_bringup.md`
- `docs/board_trace_minimal.md`
- `docs/board_trace_validation.md`

Validation expectations:

- Run `uv run python tools/check_board_baseline.py` for baseline board docs/config.
- Run `uv run python tools/check_board_trace_minimal.py` and `uv run python tools/check_board_trace_programs.py` for trace-enabled board plans.
- Keep first-board trace profiles narrow: syscall/trap/context/drop first; full retire and full branch traces only after bandwidth is justified.

## Design Rules

- Prefer staged gates over large end-to-end promises: baseline sim, trace-unit sim, CVA6 smoke, bitstream, board evidence, Linux workload, semantic enrichment.
- Keep event semantics committed-only. ECALL/trap paths must not depend solely on normal retire conditions.
- Account for compressed instructions when computing sequential PC.
- Prefer resolved target/next PC from CVA6 when available; use inferred next committed PC only as a documented fallback.
- Treat `a0-a7` shadow validity as an assumption unless reset-to-trace coverage or RF snapshot evidence exists.
- Do not claim malware-analysis value from syscall numbers alone; semantic reconstruction needs return values, context, fd/path recovery, pointer enrichment, or a stated fallback.
- Keep Windows/Vivado path constraints in mind. Use `uv run rvmt` because it applies project configuration such as Vivado path, board files, and `subst` handling.

## Mature OSS Patterns

Load `references/open-source-patterns.md` when making process, verification, or documentation decisions. It distills practices from OpenTitan DV/checklists, OpenHW/CVA6 and CORE-V verification flows, and riscv-dv-style golden/reference-model thinking.

Load `references/project-map.md` when deciding which files, docs, and commands are relevant to a task.
