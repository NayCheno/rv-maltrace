# 35T Paper Claim Evidence Table

Status: PAPER_CLAIM_EVIDENCE_TABLE_PASS_WITH_SURROGATE_BOOT_DEFERRED

Paper claims are only allowed when their machine-checkable evidence row is PASS. DEFERRED rows may be discussed as limitations or required follow-up, not as completed claims.

| Claim ID | Status | Paper wording | Evidence | Limitation |
|---|---|---|---|---|
| `c1_primary_35t_package_integrity` | PASS | The primary 35T evidence package is hash-manifested and locally reproducible. | docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521; tools/check_35t_artifact_package_readiness.py | Primary package is synthetic-behavior 35T evidence, not true real-malware evidence. |
| `c2_surrogate_darthra_board_gate` | PASS | Three DarthRa-derived safe surrogates pass the Artix-7 35T board validation gate. | docs/results/evidence/35t-surrogate-darthra-p0a-r512-abba-r5-20260524; results/experiments/35t/35t-surrogate-darthra-p0a-r512-abba-r5-20260524 | Repository-authored safe reimplementations retain behavior shape only. |
| `c3_mirai_reference_nonnetwork_board_gate` | PASS | Three non-network Mirai-reference behavior simulations pass the Artix-7 35T board validation gate. | docs/results/evidence/35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524; results/experiments/35t/35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524 | Network-required Mirai behavior remains excluded from this non-network claim. |
| `c4_real_malware_derived_lineage` | PASS | Six board-tested behaviors have explicit real-malware-derived lineage, risk removal, and non-claim boundaries. | docs/results/evidence/35t-real-malware-derived-lineage-20260524; experiments/linux_behavior/real_malware_surrogate/behavior_lineage_matrix.json | Lineage is behavior-derived and explicitly not payload-equivalence evidence. |
| `c5_same_set_baseline_comparison` | PASS | The six real-malware-derived behaviors have same-set host, strace, QEMU, and 35T board medians recorded. | docs/results/evidence/35t-real-malware-derived-baseline-comparison-20260524; tools/check_35t_behavior_baseline_comparison.py | Ratios are descriptive; this is not an advanced QEMU-plugin/eBPF comparison. |
| `c6_surrogate_boot_provenance` | DEFERRED | The surrogate run records boot provenance status and explicitly names the run-scoped boot-log blocker. | docs/results/evidence/35t-surrogate-boot-provenance-20260524; tools/check_35t_surrogate_boot_provenance.py | A deferred status means the paper must not claim a surrogate run-scoped Linux boot log until that log is captured. |
| `c7_true_real_malware_boundary` | PASS | True real-malware validation remains a blocked boundary, not a PASS claim. | experiments/linux_behavior/real_malware/manifest.json; results/experiments/real_malware/manual | No true real-malware board-execution evidence is claimed in this package. |

## Deferred Claims

- `c6_surrogate_boot_provenance`

## Failures

- none

## Non-claims

- not true real-malware execution
- not a CCF-A acceptance guarantee
- not payload-equivalence evidence
- not network-enabled malware behavior
- not malware-family classifier accuracy
