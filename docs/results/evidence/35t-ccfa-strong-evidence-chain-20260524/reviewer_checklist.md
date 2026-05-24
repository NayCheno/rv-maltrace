# Reviewer Checklist

- [ ] Open `ccfa_evidence_chain.json` and confirm top-level status is PASS_WITH_BOUNDED_LIMITATIONS.
- [ ] Confirm `claim_boundary.json` keeps true real-malware validation blocked until external quarantine evidence exists.
- [ ] Verify `artifact_hash_manifest.json` class digests for raw UART, decoded trace, semantic, audit, alignment, and build provenance files.
- [ ] Confirm the real-malware-derived lineage package has 6/6 PASS rows and keeps surrogate/non-claim boundaries.
- [ ] Run the no-write checker command from `reproduction_commands.md`.
- [ ] Run the two gate checkers and both `rvmt explain:35t --flow` commands for the surrogate and Mirai-reference runs.
- [ ] Review limitations before using the evidence as a paper claim.

## Current Failures

- none
