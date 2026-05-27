# Real-malware-derived Behavior Evidence Snapshot: 35t-surrogate-darthra-p0a-r512-abba-r5-20260524

Status: PASS

This snapshot records safety-controlled real-malware-derived behavior validation on Artix-7 35T. It supports behavior traceability and rule-detection/audit feasibility without claiming payload equivalence or malware-family accuracy.

## Samples

- `darthra_elf_header_probe`: `PASS`, matched `surrogate_elf_header_probe`
- `darthra_rootkit_device_probe`: `PASS`, matched `surrogate_rootkit_device_probe`
- `darthra_virus_fixture_walk_sim`: `PASS`, matched `surrogate_virus_file_activity`

## Evidence

- `real_malware_surrogate_validation_gate.json`: strict real-malware-derived behavior gate result.
- `gate_report.json`: 35T process-view compatible gate summary.
- `sample_matrix_summary.json`: per-sample trace/semantic/audit summary.
- `raw_artifact_sanitization.json`: hash-only raw UART/trace inventory.
- `evidence_manifest.json`: committed lightweight artifact manifest.

## Non-claims

- DarthRa-derived samples are safety-controlled malware behavior cases
- no external real-malware payload was stored in this repository
- no external real-malware payload was executed by this checker
- not payload-equivalence or malware-family accuracy evidence
