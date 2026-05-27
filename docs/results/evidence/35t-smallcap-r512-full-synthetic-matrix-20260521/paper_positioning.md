# 35T Paper Positioning: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: BOUNDED_FEASIBILITY_POSITIONING_READY

Scope: Artix-7 35T / LiteX / VexRiscv.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Checks

- assessment_has_ccfa_boundary: PASS
- assessment_has_supported_positioning: PASS
- assessment_has_forbidden_positioning: PASS
- paper_status_bounded: PASS
- paper_claim_level: PASS
- paper_scope: PASS
- paper_supported_claims_limited: PASS
- paper_forbidden_claims_present: PASS
- paper_non_claims_present: PASS
- paper_limitations_dual_channel: PASS
- paper_doc_supported_wording: PASS
- paper_doc_forbidden_wording: PASS
- closure_doc_has_recommended_wording: PASS
- evaluation_plan_keeps_ccfa_non_goal: PASS
- evaluation_plan_separates_35t_from_cva6: PASS
- assessment_closure_bounded: PASS
- assessment_traceability_bounded: PASS
- remaining_external_work_recorded: PASS
- remaining_records_cover_positioning_blockers: PASS
- no_positive_forbidden_claims: PASS

## Supported Positioning

- prototype feasibility
- small-capacity trace policy evaluation
- low-cost board case study
- engineering validation before CVA6
- low-cost FPGA feasibility / constrained-board prototype evaluation

## Forbidden Positioning

- main malware detection result
- main real-world malware analysis dataset
- main architecture validation for CVA6
- main CCF-A contribution by itself
- real malware detection accuracy
- CVA6 validation
- complete semantic reconstruction
- mature detector

## Evidence

- assessment_source: `D:\Download\rv_maltrace_35t_assessment.md`
- paper_evidence_check: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/paper_evidence_check.json`
- paper_evidence_doc: `docs/results/rv_maltrace_35t_paper_evidence.md`
- application_closure_doc: `docs/results/rv_maltrace_35t_application_closure.md`
- evaluation_plan: `docs/research/evaluation_plan.md`
- assessment_closure: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_closure.json`
- assessment_traceability: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/assessment_traceability.json`
- remaining_external_work: `docs/results/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/remaining_external_work.json`

## Interpretation

- 35T evidence supports a bounded feasibility/constrained-board prototype result
- 35T evidence does not by itself support a CCF-A main contribution, malware-family accuracy, CVA6 validation, or complete reconstruction claim
- paper-facing wording must keep the dual-channel trace-gate and side-channel semantic evidence separated

## Positive Forbidden Findings

- none

## Failures

- none
