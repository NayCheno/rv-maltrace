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
- `command_log.md`

## What Is Not Included

This snapshot intentionally does not include large trace dumps, raw UART logs, bitstreams, Vivado builds, board build directories, ELF binaries, or the complete `results/` tree.

## How To Re-check

Run the committed closure checker from the repository root:

```bash
uv run python tools/check_35t_application_closure.py --repo-root .
```

The checker reads the closure document, case-study document, and this evidence manifest. It does not require hardware, Vivado, board artifacts, or the full local `results/` directory.

## Artifact Index

See `evidence_manifest.json` for hashes and source paths. See `case_study_artifact_index.json` for indexed case-study source artifacts that are referenced but not committed in this lightweight snapshot. The fd/path and process-tree summaries are initial `PARTIAL` interpretation artifacts and do not claim complete semantic reconstruction.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
