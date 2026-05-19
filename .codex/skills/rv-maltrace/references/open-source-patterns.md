# Mature Open-Source Hardware Patterns for RV-MalTrace

Use these patterns as guardrails when changing RV-MalTrace. They are distilled from mature open-source hardware and RISC-V verification ecosystems such as OpenTitan DV/checklists, OpenHW/CVA6, CORE-V verification, and riscv-dv-style regression flows.

## Patterns to Preserve

### Stage gates over vague progress

Represent progress as explicit gates with evidence, not narrative claims. A gate should name:

- required artifact
- command or manual procedure
- pass/fail status
- owner of physical evidence when board hardware is involved

Apply this to docs such as `baseline_pass_criteria.md`, `board_trace_validation.md`, semantic enrichment plans, and Linux behavior experiments.

### Smoke first, broad regression second

Keep a cheap smoke path available before expensive Vivado, board, or Linux flows. Prefer this progression:

1. static/doc check script
2. parser/tool self-test
3. trace-unit xsim
4. CVA6 smoke xsim
5. bitstream/build collection
6. physical board evidence
7. Linux behavior workload

### Golden/reference comparison

Every trace semantic change should have a golden or expected artifact:

- `sim/golden/*.expected.json`
- `sim/golden/*.trace.jsonl`
- `board/trace_validation/expected/*.expected.json`
- `experiments/linux_behavior/*.json`

When expected files change, state whether the change is formatting-only, a new event, a corrected semantic expectation, or a relaxed rule.

### Documentation tied to checks

Prefer small `tools/check_*.py` scripts for structured docs and experiment metadata. A doc without a check script can still be useful, but critical pass/fail plans should become checkable.

### Evidence separation

Separate:

- simulation evidence from board evidence
- repository-local build evidence from lab observations
- trace-enabled evidence from baseline/unmodified CVA6 evidence
- performance mode with possible drops from correctness mode with zero drops

Do not convert TODO board rows to PASS without the documented `results/board/.../<run-id>/` artifacts.

### Sideband instrumentation

Trace instrumentation should observe architectural behavior without changing core semantics:

- no trace backpressure into CVA6
- no speculative path reporting
- no hidden dependence on debug/ptrace-like software perturbation for MVP claims
- explicit `EVT_DROP` or drop counters when bandwidth is exceeded

### Reproducible configuration

Keep versions and environment assumptions explicit:

- CVA6 commit and local modifications
- Vivado version and board files
- RISC-V toolchain prefix/version
- board target and Xilinx part
- generated output directories

Use `pyproject.toml` `[tool.rv-maltrace]` and `docs/process/version_lock.md` as the primary local anchors.

## Review Heuristics

Ask these before accepting a change:

- Is the change tied to a phase or gate?
- Is the observable behavior captured in JSONL/golden/docs?
- Is there a narrow validation command?
- Are board claims backed by physical artifacts?
- Did the change preserve committed-only semantics?
- Did the change avoid adding trace logic to the core critical path?
- Is fallback behavior explicit when a paper-level feature is not yet implemented?

## Applying These Patterns

For a new feature, create the smallest vertical slice:

1. document the intended event or behavior
2. add RTL/tool support
3. add or update expected trace data
4. add a check or comparison path
5. run the narrowest validation
6. only then broaden to CVA6, board, or Linux

For research-plan updates, avoid claims that sound complete before evidence exists. Prefer wording like:

- "planned gate"
- "required evidence"
- "repository-local PASS"
- "TODO(BOARD)"
- "blocked pending Vivado/CVA6/board evidence"
