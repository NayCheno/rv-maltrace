# CCF-A External Closure Operator Packet

Status: `PASS`
Closure status: `OPEN_EXTERNAL_ARTIFACTS_REQUIRED`

This packet is an operator handoff for the remaining non-real-malware external work. It is not evidence that the external work has already been executed.

## Source Artifacts

| Artifact | Status | Closure status |
| --- | --- | --- |
| `external_closure_readiness` | `PASS` | `NOT_APPLICABLE` |
| `external_closure_intake` | `FAIL` | `OPEN_EXTERNAL_ARTIFACTS_REQUIRED` |
| `external_closure_plan` | `PASS` | `NOT_APPLICABLE` |
| `external_closure_preflight` | `PASS` | `NOT_APPLICABLE` |

## Operator Sequence

1. Run the local preflight commands recorded for each external id.
2. Execute the required board, RTL, or host-transport experiment outside the repository-only checker path.
3. Write candidate summaries only from real record-specific external_closure artifacts with matching sha256-backed evidence rows and no template placeholders.
4. Validate each candidate with tools/prepare_genesys2_external_summary.py before moving it into the intake path.
5. Regenerate external_closure_intake.json, then run the intake, operator packet, current-suite, and full reproduction checks.

## External Records

| Order | External id | Intake status | Expected summary | Required artifact kinds |
| ---: | --- | --- | --- | --- |
| 1 | `board_native_dwarf_source_lines` | `EXTERNAL_SUMMARY_ACCEPTED` | `results/evaluation/genesys2-cva6/current/external_closure/board_native_source_lines_summary.json` | `board_capture_manifest`, `debug_elf_manifest`, `joined_trace_code_map_manifest`, `readelf_debug_line_transcript` |
| 2 | `full_hardware_pointer_strings` | `EXTERNAL_SUMMARY_ACCEPTED` | `results/evaluation/genesys2-cva6/current/external_closure/hardware_pointer_strings_summary.json` | `companion_substitution_audit`, `kernel_space_filter_report`, `mem_last_or_terminator_report`, `pointer_capture_manifest`, `pointer_group_reconstruction`, `redaction_policy`, `resource_timing_report`, `rtl_design_manifest` |
| 3 | `production_streaming_dma_trace_sink` | `EXTERNAL_SUMMARY_PRESENT_INVALID` | `results/evaluation/genesys2-cva6/current/external_closure/streaming_dma_throughput_summary.json` | `host_receiver_log`, `noninterference_report`, `resource_report`, `timing_report`, `transport_design_manifest` |
| 4 | `genesys2_board_benign_control` | `EXTERNAL_SUMMARY_ACCEPTED` | `results/evaluation/genesys2-cva6/current/external_closure/board_benign_control_summary.json` | `behavior_audit_manifest`, `behavior_graph_manifest`, `board_capture_manifest`, `false_positive_report`, `semantic_events_manifest` |

## Non-Claims

- This packet does not itself create board-native DWARF source-line attribution evidence; only accepted intake summaries close that item.
- This packet does not itself create full hardware pointer-string reconstruction evidence; only accepted intake summaries close that item.
- This packet does not complete production streaming/DMA throughput evidence.
- This packet does not itself create Genesys2 board benign-control evidence; only accepted intake summaries close that item.
- This packet does not add real-malware validation.
