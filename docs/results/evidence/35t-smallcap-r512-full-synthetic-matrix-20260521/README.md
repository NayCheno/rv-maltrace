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
- `function_attribution_summary.json` and `function_attribution_summary.md`
- `source_attribution_summary.json` and `source_attribution_summary.md`
- `explanation_readiness_summary.json` and `explanation_readiness_summary.md`
- `board_validation_attempt_summary.json` and `board_validation_attempt_summary.md`
- `board_validation_plan.json` and `board_validation_plan.md`
- `board_validation_preflight.json` and `board_validation_preflight.md`
- `board_validation_runbook.json` and `board_validation_runbook.md`
- `board_validation_status.json` and `board_validation_status.md`
- `paper_evidence_check.json` and `paper_evidence_check.md`
- `command_log.md`

## What Is Not Included

This snapshot intentionally does not include large trace dumps, raw UART logs, bitstreams, Vivado builds, board build directories, ELF binaries, or the complete `results/` tree.

## How To Re-check

Run the committed closure checker from the repository root:

```bash
uv run python tools/check_35t_application_closure.py --repo-root .
```

The checker reads the closure document, case-study document, and this evidence manifest. It does not require hardware, Vivado, board artifacts, or the full local `results/` directory.

Run the paper evidence checker when the full local `results/` directory is available:

```bash
uv run python tools/check_35t_paper_evidence.py --repo-root .
```

Current paper support status is `SUPPORTED_WITH_BOUNDED_CLAIMS`. The same check records `strict_single_run_status: PASS` in `dual_channel` mode: the trace-gate channel is 13/13 strict sample-gate PASS, while the side-channel semantic channel remains 9/13 and must not be described as a single-trace all-gates PASS.

To prepare a candidate 35T board-validation result bundle from a local run, use:

```bash
uv run python tools/package_35t_board_validation.py --repo-root .
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/board_validation_bundle --require-results
```

The primary evidence run bundle remains useful as a local candidate check. The completed board-validation evidence is the separate targeted run `35t-targeted-board-validation-20260522`, which was captured on the 35T board with the syscall side channel enabled.

To inspect the targeted 35T board-validation sequence, follow:

```bash
uv run python tools/prepare_35t_board_validation_run.py --repo-root . --validation-run-id 35t-targeted-board-validation-20260522
```

The generated `board_validation_runbook.md` keeps the source evidence run fixed at `35t-smallcap-r512-full-synthetic-matrix-20260521` while using a separate validation run id for the board capture.

Before running the board stage, use the preflight checker:

```bash
uv run python tools/check_35t_board_preflight.py --repo-root .
```

The preflight status only checks host tools, scripts, runbook consistency, and whether the requested UART port is visible. It does not prove the 35T board image is running and does not count as board validation.

The completed targeted validation bundle is checked with:

```bash
uv run python tools/check_35t_board_validation.py --repo-root . --results-root results/experiments/35t/35t-targeted-board-validation-20260522/board_validation_bundle --require-results
```

Current selected-artifact validation result: `PASS`; hardware validation is true for this 35T prototype closure. The targeted validation bundle is `dual_channel`: the trace-gate artifact is 13/13 strict sample-gate PASS, and the side-channel run supplies semantic fd/path and process-tree evidence. The side-channel run itself still has 13/13 `sample_status` PASS but 9/13 strict `samples[].gate_status` PASS, so it is semantic closure evidence, not the trace-gate result. Source attribution remains `PARTIAL`, so this still does not claim complete semantic reconstruction.

## Artifact Index

See `evidence_manifest.json` for hashes and source paths. See `case_study_artifact_index.json` for indexed case-study source artifacts that are referenced but not committed in this lightweight snapshot. The committed fd/path and process-tree summaries are now synchronized from the targeted board-validation bundle and record `PASS`; neither claims complete semantic reconstruction.

`explanation_readiness_summary.md` records the local closure boundary used before the targeted validation run. The follow-up side-channel validation closed fd/path and process-tree summaries; source-line attribution still requires retained source-location evidence.

`function_attribution_summary.md` records function-level attribution `PASS` from ELF symbol ranges. `source_attribution_summary.md` records function-level attribution availability and keeps source-line attribution explicitly unavailable until source-location evidence exists.

`board_validation_plan.md` and `board_validation_status.md` define the targeted 35T board-validation artifact set. The current status is `PASS`; hardware validation is true for the 35T targeted validation bundle.

`board_validation_runbook.md` records the exact command sequence for the targeted 35T board validation run. It is command provenance; the board evidence is in the checked validation bundle and attempt summary.

`board_validation_preflight.md` records the current host and UART readiness for that run plan. It is a readiness check, not board evidence.

`board_validation_attempt_summary.md` records the targeted 35T validation attempt `35t-targeted-board-validation-20260522`: the dual-channel validation bundle is `PASS`, the trace-gate channel is 13/13 strict sample-gate PASS, and the side-channel semantic channel remains 9/13 strict sample-gate PASS. The selected-artifact validation bundle is `PASS`, with fd/path flow and process-tree summaries also `PASS`.

`paper_evidence_check.md` records the paper-facing gate: the primary run supplies the 13/13 strict full-matrix trace result, while the targeted side-channel run supplies fd/path and process-tree semantic closure. It explicitly forbids single-trace all-gates wording for the side-channel semantic capture.

`board_syscall_side_channel_smoke.md` records the follow-up syscall side-channel work: the new runner builds into the 35T rootfs, the board was rebooted through the LiteX serial image path, and `35t-sidechannel-smoke-20260522e` closed fd/path and process-tree smoke evidence. The later targeted validation bundle passed for selected semantic artifacts after that boot.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
