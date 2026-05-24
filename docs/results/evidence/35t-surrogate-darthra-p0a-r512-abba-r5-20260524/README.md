# Real-malware-surrogate Evidence Snapshot: 35t-surrogate-darthra-p0a-r512-abba-r5-20260524

Status: PASS

This snapshot records safe, repository-authored surrogate validation on Artix-7 35T. It is not a true real-malware detection result.

## Samples

- `darthra_elf_header_probe`: `PASS`, matched `surrogate_elf_header_probe`
- `darthra_rootkit_device_probe`: `PASS`, matched `surrogate_rootkit_device_probe`
- `darthra_virus_fixture_walk_sim`: `PASS`, matched `surrogate_virus_file_activity`

## Evidence

- `real_malware_surrogate_validation_gate.json`: strict surrogate gate result.
- `gate_report.json`: 35T process-view compatible gate summary.
- `sample_matrix_summary.json`: per-sample trace/semantic/audit summary.
- `raw_artifact_sanitization.json`: hash-only raw UART/trace inventory.
- `evidence_manifest.json`: committed lightweight artifact manifest.

## Non-claims

- surrogate samples are repository-authored safe reimplementations
- no external real-malware payload was stored in this repository
- no external real-malware payload was executed by this checker
- this is not a true real-malware detection PASS
