# 35T Evidence Snapshot: 35t-smallcap-r512-full-synthetic-matrix-20260521

## Scope

Artix-7 35T / LiteX / VexRiscv only.

## Claim Level

35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## What Is Included

This directory contains committed lightweight summary artifacts for the primary 35T run:

- `run_config.json`
- `gate_report.json` and `gate_report.md`
- `semantic_failure_triage.json` and `semantic_failure_triage.md`
- `process_chain_capacity_debug.json` and `process_chain_capacity_debug.md`
- `sample_matrix_summary.json` and `sample_matrix_summary.md`
- `case_study_artifact_index.json`
- `fd_path_flow_summary.json` and `fd_path_flow_summary.md`
- `process_tree_summary.json` and `process_tree_summary.md`
- `source_attribution_summary.json` and `source_attribution_summary.md`
- `explanation_readiness_summary.json` and `explanation_readiness_summary.md`
- `board_validation_plan.json` and `board_validation_plan.md`
- `board_validation_runbook.json` and `board_validation_runbook.md`
- `board_validation_status.json` and `board_validation_status.md`
- `command_log.md`

## What Is Not Included

This snapshot intentionally does not include large trace dumps, raw UART logs, bitstreams, Vivado builds, board build directories, ELF binaries, or the complete `results/` tree.

## How To Re-check

Run the committed closure checker from the repository root:

```bash
uv run python tools/check_35t_application_closure.py --repo-root .
```

The checker reads the closure document, case-study document, and this evidence manifest. It does not require hardware, Vivado, board artifacts, or the full local `results/` directory.

To prepare a candidate 35T board-validation result bundle from a local run, use:

```bash
uv run python tools/package_35t_board_validation.py --repo-root .
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results
```

The current local bundle remains `CANDIDATE_PARTIAL` because fd/path flow and process-tree closure are still `PARTIAL`. That failure is expected until a targeted 35T board run captures the required path, fd, clone/wait, and ownership evidence.

To run the actual targeted 35T board-validation sequence, follow:

```bash
uv run python tools/prepare_35t_board_validation_run.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522
```

The generated `board_validation_runbook.md` keeps the source evidence run fixed at `35t-smallcap-r512-full-synthetic-matrix-20260521` while using a separate validation run id for the future board capture.

## Artifact Index

See `evidence_manifest.json` for hashes and source paths. See `case_study_artifact_index.json` for indexed case-study source artifacts that are referenced but not committed in this lightweight snapshot. The fd/path and process-tree summaries are initial `PARTIAL` interpretation artifacts and do not claim complete semantic reconstruction.

`explanation_readiness_summary.md` records the current local closure boundary: the 35T synthetic behavior-audit prototype evidence chain is ready for targeted board validation, while fd/path strings, strict process-tree parent-child closure, and source-line attribution still require stronger capture or side-channel evidence.

`source_attribution_summary.md` records function-level attribution availability and keeps source-line attribution explicitly unavailable until source-location evidence exists.

`board_validation_plan.md` and `board_validation_status.md` define the targeted 35T board-validation artifact set. The current status is `AWAITING_BOARD_RUN`; hardware validation remains false until those board artifacts are captured.

`board_validation_runbook.md` records the exact command sequence for the next real 35T board run. It is a run plan, not board evidence.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
