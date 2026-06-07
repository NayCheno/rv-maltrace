# 35T Paper Claim Evidence Table

Status: PAPER_CLAIM_EVIDENCE_TABLE_PASS_WITH_SURROGATE_BOOT_DEFERRED

Paper claims are only allowed when their machine-checkable evidence row is PASS. DEFERRED rows may be discussed as limitations or required follow-up, not as completed claims.

| Claim ID | Status | Paper wording | Evidence | Limitation |
|---|---|---|---|---|
| `c1_primary_35t_package_integrity` | PASS | The primary 35T evidence package is hash-manifested and locally reproducible. | docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521; tools/check_35t_artifact_package_readiness.py | Primary package is the synthetic/benign feasibility gate; real-malware-derived behavior evidence is covered by the dedicated lineage rows. |
| `c2_surrogate_darthra_board_gate` | PASS | Three safety-controlled DarthRa-derived malware behavior cases pass the Artix-7 35T board validation gate. | docs/07-evaluation-evidence/evidence/35t-surrogate-darthra-p0a-r512-abba-r5-20260524; results/experiments/35t/35t-surrogate-darthra-p0a-r512-abba-r5-20260524 | Safety controls bound harmful effects; the paper claim is behavior traceability and rule-detection/audit feasibility, not payload equivalence. |
| `c3_mirai_reference_nonnetwork_board_gate` | PASS | Three non-network Mirai-reference malware behavior cases pass the Artix-7 35T board validation gate. | docs/07-evaluation-evidence/evidence/35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524; results/experiments/35t/35t-mirai-reference-nonnetwork-p0a-r512-abba-r5-v3-20260524 | Network-required Mirai behavior remains excluded from this non-network claim. |
| `c4_real_malware_derived_lineage` | PASS | Six board-tested behaviors have explicit real-malware-derived lineage, risk removal, and non-claim boundaries. | docs/07-evaluation-evidence/evidence/35t-real-malware-derived-lineage-20260524; experiments/linux_behavior/real_malware_surrogate/behavior_lineage_matrix.json | Lineage is behavior-derived and explicitly not payload-equivalence evidence. |
| `c5_same_set_baseline_comparison` | PASS | The six real-malware-derived behaviors have same-set host, strace, QEMU, and 35T board medians recorded. | docs/07-evaluation-evidence/evidence/35t-real-malware-derived-baseline-comparison-20260524; tools/check_35t_behavior_baseline_comparison.py | Ratios are descriptive; this is not an advanced QEMU-plugin/eBPF comparison. |
| `c6_surrogate_boot_provenance` | DEFERRED | The surrogate run records boot provenance status and explicitly names the run-scoped boot-log blocker. | docs/07-evaluation-evidence/evidence/35t-surrogate-boot-provenance-20260524; tools/check_35t_surrogate_boot_provenance.py | A deferred status means the paper must not claim a surrogate run-scoped Linux boot log until that log is captured. |
| `c7_external_payload_boundary` | PASS | Direct external-quarantine payload execution remains a separate gated boundary, not a prerequisite for the current real-malware-derived behavior feasibility claim. | experiments/linux_behavior/real_malware/manifest.json; results/experiments/real_malware/manual | No uncontrolled, network-enabled, or payload-equivalent malware execution is claimed in this package. |

## Deferred Claims

- `c6_surrogate_boot_provenance`

## Failures

- none

## Non-claims

- not uncontrolled or network-enabled external-payload execution
- not a CCF-A acceptance guarantee
- not payload-equivalence evidence
- not malware-family classifier accuracy
