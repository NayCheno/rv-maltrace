# 35T Artifact Package Readiness: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: LIGHTWEIGHT_PACKAGE_READY_FULL_REPRO_DEFERRED

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Checks

- results_root_exists: PASS
- evidence_root_exists: PASS
- all_required_classes_accounted: PASS
- raw_large_artifacts_have_policy: PASS
- non_claims_present: PASS

## Artifact Classes

| Class | Status | Count | Policy | Bytes |
| --- | --- | ---: | --- | ---: |
| `run_config` | `READY_PUBLIC` | 1/1 | `public` | 2110 |
| `raw_uart_log` | `READY_LOCAL_ONLY` | 2/1 | `local_only_raw_or_sanitized_excerpt` | 2113924 |
| `decoded_trace_jsonl` | `READY_LOCAL_ONLY` | 65/13 | `local_only_hash_or_summary` | 2624240 |
| `runtime_process_map` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 753951 |
| `code_map` | `READY_PUBLIC_SUMMARY_OR_HASH` | 13/13 | `public_or_summary` | 4711845 |
| `trace_code_map_summary` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 134581 |
| `semantic_events` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 11354901 |
| `behavior_graph` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 13741455 |
| `behavior_audit` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 779853 |
| `alignment` | `READY_PUBLIC_SUMMARY_OR_HASH` | 65/13 | `public_or_summary` | 114157 |
| `metrics` | `READY_PUBLIC` | 2/1 | `public` | 50343 |
| `resource_timing_reports` | `READY_PUBLIC_SUMMARY_OR_HASH` | 4/3 | `public_summary` | 10731 |
| `elf_hashes` | `READY_PUBLIC_SUMMARY_OR_HASH` | 39/13 | `public_hashes` | 6864 |
| `bitstream_metadata` | `READY_PUBLIC_SUMMARY_OR_HASH` | 4/1 | `public_summary_no_bitstream_binary` | 12559 |
| `scripts_and_commands` | `READY_PUBLIC` | 40/4 | `public` | 1164190 |
| `synthetic_extension_sources` | `READY_PUBLIC` | 14/14 | `public` | 24069 |
| `synthetic_extension_behavior_smoke_evidence` | `READY_PUBLIC_SUMMARY_OR_HASH` | 3/3 | `public_summary` | 129273 |
| `qemu_plugin_baseline_evidence` | `READY_PUBLIC_SUMMARY_OR_HASH` | 3/3 | `public_summary` | 139539 |
| `raw_artifact_sanitization_evidence` | `READY_PUBLIC` | 2/2 | `public` | 15485 |
| `pointer_snapshot_design_review_evidence` | `READY_PUBLIC` | 4/4 | `public` | 11482 |
| `raw_artifact_escrow_package` | `READY_LOCAL_ONLY` | 6/6 | `local_only_raw_or_sanitized_excerpt` | 94886 |
| `negative_failed_cases` | `READY_PUBLIC_SUMMARY_OR_HASH` | 9/3 | `public_summary` | 316309 |
| `reproduction_readme` | `READY_PUBLIC` | 3/2 | `public` | 159912 |

## Missing Classes

- none

## Local-Only Classes

- raw_uart_log
- decoded_trace_jsonl
- raw_artifact_escrow_package

## Summary/Hash Classes

- runtime_process_map
- code_map
- trace_code_map_summary
- semantic_events
- behavior_graph
- behavior_audit
- alignment
- resource_timing_reports
- elf_hashes
- bitstream_metadata
- synthetic_extension_behavior_smoke_evidence
- qemu_plugin_baseline_evidence
- negative_failed_cases

## Interpretation

- current repository can describe the paper artifact inventory and verify required artifact classes locally
- large raw traces, raw UART logs, generated bitstreams, board build directories, and ELF binaries remain outside the lightweight committed snapshot
- full reproduction packaging remains deferred until raw artifacts are sanitized or explicitly released with hashes and access policy

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
