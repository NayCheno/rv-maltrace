# 35T CCF-A-style Strong Evidence Chain

Status: CCFA_STYLE_STRONG_EVIDENCE_CHAIN_PASS_WITH_BOUNDED_LIMITATIONS

This directory consolidates the primary 35T package, the real-malware-surrogate board run, the non-network Mirai-reference board run, the real-malware-derived behavior lineage matrix, and the real-malware blocked boundary into one machine-checkable evidence chain.

Files:

- `ccfa_evidence_chain.json` / `.md`: top-level evidence-chain report.
- `artifact_hash_manifest.json`: hash-linked local raw-to-derived artifact inventory.
- `claim_boundary.json` / `.md`: real-malware, surrogate, and network-exclusion boundary.
- linked lineage package: `docs/results/evidence/35t-real-malware-derived-lineage-20260524`.
- linked baseline package: `docs/results/evidence/35t-real-malware-derived-baseline-comparison-20260524`.
- linked surrogate boot package: `docs/results/evidence/35t-surrogate-boot-provenance-20260524`.
- linked paper claim table: `docs/results/evidence/35t-paper-claim-evidence-table-20260524`.
- `reproduction_commands.md`: commands reviewers can rerun.
- `reviewer_checklist.md`: concise review path.

The package intentionally records bounded limitations instead of upgrading surrogate evidence into a true real-malware detection claim.
