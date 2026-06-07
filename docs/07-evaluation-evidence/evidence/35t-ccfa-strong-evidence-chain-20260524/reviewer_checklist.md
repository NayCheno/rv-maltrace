# Reviewer Checklist

- [ ] Open `ccfa_evidence_chain.json` and confirm top-level status is PASS_WITH_BOUNDED_LIMITATIONS.
- [ ] Confirm `claim_boundary.json` keeps external-quarantine payload execution separate from the completed real-malware-derived behavior claim.
- [ ] Verify `artifact_hash_manifest.json` class digests for raw UART, decoded trace, semantic, audit, alignment, and build provenance files.
- [ ] Confirm the real-malware-derived lineage package has 6/6 PASS rows and keeps payload-equivalence, network, and accuracy boundaries.
- [ ] Confirm `baseline_comparison.json` has 6/6 PASS rows for host, strace, QEMU, and board medians.
- [ ] Confirm `claim_evidence_table.json` marks completed paper claims as PASS and the surrogate boot claim as DEFERRED when run-scoped boot is absent.
- [ ] Review `surrogate_boot_provenance.json` and `boot_capture_runbook.md` before claiming run-scoped surrogate boot provenance.
- [ ] Run the no-write checker command from `reproduction_commands.md`.
- [ ] Run the two gate checkers and both `rvmt explain:35t --flow` commands for the surrogate and Mirai-reference runs.
- [ ] Review limitations before using the evidence as a paper claim.

## Current Failures

- none
