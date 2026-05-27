# 35T CCF-A-style Strong Evidence Chain

Status: CCFA_STYLE_STRONG_EVIDENCE_CHAIN_PASS_WITH_BOUNDED_LIMITATIONS

Scope: Artix-7 35T / LiteX / VexRiscv

This package is a CCF-A-style evidence-chain discipline artifact, not an acceptance guarantee.

## Run IDs

- primary_35t: `35t-smallcap-r512-full-synthetic-matrix-20260521`
- surrogate: `35t-surrogate-darthra-p0a-r512-abba-r5-20260524`
- mirai_reference: `35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524`

## Top-level Checks

- primary_evidence_manifest_hashes: PASS
- surrogate_evidence_manifest_hashes: PASS
- mirai_evidence_manifest_hashes: PASS
- real_malware_derived_lineage_manifest_hashes: PASS
- real_malware_derived_baseline_manifest_hashes: PASS
- surrogate_boot_provenance_manifest_hashes: PASS
- paper_claim_table_manifest_hashes: PASS
- real_malware_derived_lineage_pass: PASS
- real_malware_derived_baseline_pass: PASS
- surrogate_boot_provenance_recorded: PASS
- paper_claim_table_pass: PASS
- ccfa_snapshot_manifest_hashes: PASS
- surrogate_run_config: PASS
- mirai_run_config: PASS
- surrogate_gate_pass: PASS
- mirai_gate_pass: PASS
- surrogate_metrics_zero_fp_fn: PASS
- mirai_metrics_zero_fp_fn: PASS
- raw_sanitization_hashes: PASS
- raw_to_derived_hash_inventory: PASS
- tooling_provenance_hashes: PASS
- claim_boundary: PASS
- mirai_board_boot_provenance: PASS

## Gate Summary

- surrogate: PASS (3 samples)
- mirai_reference: PASS (3 samples)

## Evidence Extensions

- real_malware_derived_lineage: REAL_MALWARE_DERIVED_SURROGATE_LINEAGE_PASS (6/6 rows)
- real_malware_derived_baseline_comparison: REAL_MALWARE_DERIVED_BASELINE_COMPARISON_PASS (6/6 rows)
- surrogate_boot_provenance: SURROGATE_BOOT_PROVENANCE_DEFERRED_RUN_SCOPED_LOG_MISSING
- paper_claim_evidence_table: PAPER_CLAIM_EVIDENCE_TABLE_PASS_WITH_SURROGATE_BOOT_DEFERRED

## Claim Boundary

- manifest_schema: PASS
- sample_class_real_malware: PASS
- default_disabled: PASS
- external_quarantine_hash_only: PASS
- repository_payloads_disallowed: PASS
- no_repository_payload_files: PASS
- manual_real_malware_results_absent: PASS
- mirai_network_optional_samples_excluded: PASS

## Limitations

- surrogate_boot_log_not_run_scoped: Surrogate run has board/raw UART and sample artifacts, but no separate Linux boot log under results/board for that run_id; see docs/results/evidence/35t-surrogate-boot-provenance-20260524 for the recorded blocker and capture runbook.
- external_payload_execution_deferred: The strong chain supports real-malware-derived behavior traceability and rule-detection/audit feasibility; uncontrolled or network-enabled external payload execution remains outside the completed claim.
- p0a_arg_mem_disabled: The p0a trace profile proves syscall/control-flow behavior but intentionally does not provide complete fd/path or process-tree reconstruction.
- public_package_lightweight: Raw UART, decoded traces, ELFs, and boot logs are hash-linked local artifacts; public release remains hash/sanitized unless raw escrow is approved.

## Failures

- none
