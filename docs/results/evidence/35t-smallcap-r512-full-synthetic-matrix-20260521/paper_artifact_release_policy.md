# 35T Paper Artifact Release Policy: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

| Class | Release Mode | Count | Action |
| --- | --- | ---: | --- |
| `run_config` | `include_or_reference` | 1 | may be included directly in a public lightweight artifact package |
| `raw_uart_log` | `local_only_or_sanitized_excerpt` | 2 | keep local by default; publish only after sanitization or explicit controlled-release approval |
| `decoded_trace_jsonl` | `local_only_or_sanitized_excerpt` | 65 | keep local by default; publish only after sanitization or explicit controlled-release approval |
| `runtime_process_map` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `code_map` | `summary_or_hash_only` | 13 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `trace_code_map_summary` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `semantic_events` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `behavior_graph` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `behavior_audit` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `alignment` | `summary_or_hash_only` | 65 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `metrics` | `include_or_reference` | 2 | may be included directly in a public lightweight artifact package |
| `resource_timing_reports` | `summary_or_hash_only` | 4 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `elf_hashes` | `summary_or_hash_only` | 39 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `bitstream_metadata` | `summary_or_hash_only` | 4 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `scripts_and_commands` | `include_or_reference` | 40 | may be included directly in a public lightweight artifact package |
| `synthetic_extension_sources` | `include_or_reference` | 14 | may be included directly in a public lightweight artifact package |
| `synthetic_extension_behavior_smoke_evidence` | `summary_or_hash_only` | 3 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `qemu_plugin_baseline_evidence` | `summary_or_hash_only` | 3 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `raw_artifact_sanitization_evidence` | `include_or_reference` | 2 | may be included directly in a public lightweight artifact package |
| `pointer_snapshot_design_review_evidence` | `include_or_reference` | 4 | may be included directly in a public lightweight artifact package |
| `raw_artifact_escrow_package` | `local_only_or_sanitized_excerpt` | 6 | keep local by default; publish only after sanitization or explicit controlled-release approval |
| `negative_failed_cases` | `summary_or_hash_only` | 9 | publish summaries, class digests, representative hashes, and paths; do not require raw payload release |
| `reproduction_readme` | `include_or_reference` | 3 | may be included directly in a public lightweight artifact package |

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
