# 35T Raw Artifact Escrow: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: LOCAL_RAW_ARTIFACT_ESCROW_READY_PUBLIC_RELEASE_DEFERRED

Payload status: LOCAL_CONTROLLED_ESCROW_PACKAGE_READY

Package dir: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/raw_artifact_escrow_package`

## Checks

- results_root_exists: PASS
- raw_sanitization_ready: PASS
- all_raw_classes_present: PASS
- payload_files_present_and_hashed: PASS
- package_manifest_present: PASS
- package_generated_files_present: PASS
- public_release_deferred: PASS

## Raw Artifact Classes

| Class | Files | Bytes | Class Digest |
| --- | ---: | ---: | --- |
| `raw_uart_log` | 1/1 | 1056962 | `a5f6d95cf29dadd7aba37967d6cdf70edf088d0a9b098b0ba77867ba8de9357b` |
| `decoded_trace_jsonl` | 65/13 | 2624240 | `475a8150dad18919cd693c2aadd2be32cb6b0be9386b972cfcf75a94477b9011` |

## Interpretation

- full raw UART and decoded trace JSONL are copied into a local controlled escrow package
- the evidence summary records counts, sizes, and hashes but does not publish raw payloads in docs
- P6 full public raw release remains deferred until an approved release or sanitized replacement exists

## Failures

- none
