# 35T Next Strict Plan Status

Date: 2026-05-20

Board connection: on-board CH340 serial, `COM5`, `921600` baud. User-provided `CMOS5` was treated as `COM5` after local serial-port enumeration.

Boundary: this is Artix-7 35T / LiteX / VexRiscv evidence only. It is not CVA6 board evidence, not real-malware evidence, and not a mature detector claim.

## Main Artifacts

| Purpose | Run or file |
| --- | --- |
| Frozen baseline | `results/experiments/35t/35t-full-20260520` |
| Baseline reanalysis | `results/experiments/35t/35t-full-20260520-reanalyze-20260520` |
| D p0 microbench at 256 | `results/experiments/35t/35t-p0-micro-r256-20260520-com5` |
| E p0 records sweep at 512 | `results/experiments/35t/35t-p0-r512-20260520-com5` |
| E p0a subprofile sweep | `results/experiments/35t/35t-p0a-r512-20260520-com5` |
| E p0b subprofile sweep | `results/experiments/35t/35t-p0b-r512-20260520-com5` |
| E p0c subprofile sweep | `results/experiments/35t/35t-p0c-r512-20260520-com5` |
| H p0c ABBA reps=10 | `results/experiments/35t/35t-p0c-abba-r512-20260520-com5` |
| Resource report | `docs/reports/artix7_35t_resource_report.md` |

## Phase Status

| Phase | Status | Evidence and decision |
| --- | --- | --- |
| A. Freeze baseline | PASS | `35t-full-20260520` bundle/gate checks pass as a frozen 35T/VexRiscv baseline. Baseline remains `prototype_only`: 13/13 samples complete, median DROP is high and semantic recall is low. |
| B. Trace profiles | PASS | `p0_syscall_trap_context`, `p0a_syscall_drop`, `p0b_trap_drop`, and `p0c_syscall_trap_drop` are implemented through run_config and CSR control masks. The dry-run and board runs record selected profiles and masks. |
| C. Gate/report | PASS | `tools/check_35t_next_gate.py` writes JSON/Markdown gate reports with sample status, DROP/cap, event set, alignment, and audit-rule summaries. Gate logic now fails samples with unexpected trace events, missing expected rules, or unexpected rule matches. |
| D. p0 microbench | PASS-BLOCKED | The required four-sample p0 microbench was run on board at 256 records because 1024 cannot place on 35T. `35t-p0-micro-r256-20260520-com5` has complete bundle/gate artifacts. All four samples are blocked or failed by cap/DROP/alignment/audit results; p0 forbidden events are absent. |
| E1. Records sweep | PASS-BLOCKED | 256 and 512 were built and run on board; 1024 was attempted and failed during Vivado place with LUT-as-memory/RAMD64E over-utilization. 2048 is left blocked because 1024 already exceeds device distributed-RAM capacity. |
| E2. Subprofile sweep | PASS-BLOCKED | p0a, p0b, and p0c were run on board at 512 records. p0c removes context traffic and reduces DROP to about 1.9-2.5% with no cap hits, so context/privilege traffic is the primary bandwidth pressure. It is still not promoted because audit and alignment gates fail. |
| F. Alignment/recovery schema | IMPLEMENTED-FAIL | `semantic_events.json` and `alignment.json` include syscall pairing, args/return/duration/confidence, DROP context, ordered LCS, return-sign, and argument metrics. Candidate p0c still fails promotion: `hello` ordered_lcs_ratio is about 0.385, below the 0.5 threshold, and `illegal_trap` expected behavior is missing in p0c. |
| G. Audit rules | IMPLEMENTED-FAIL | Offline rule fixtures and self-tests pass, and gate reports separate missing expected behavior from unexpected matches. Current p0c evidence still has benign `hello` matching `illegal_instruction_trap`, `batch_open_read_write` missing `batch_file_read_write`, and `illegal_trap` missing its expected rule. |
| H. Runtime methodology | PASS | `35t-p0c-abba-r512-20260520-com5` completed on board with ABBA ordering, one warmup rep, and 10 measured reps. Per-sample `board/timings.jsonl` records mode, rep, order_index, warmup, runtime_ns, trace_count, and drop. Measured trace ratios are about 1.006-1.012. |
| I. Resource/timing report | PASS-BLOCKED | `artix7_35t_resource_report.md` includes baseline, p0 trace 256, p0 trace 512, and the 1024 DRC failure. p0 trace 512 costs +7482 LUT (+104.2%) and +1417 FF (+21.0%) over baseline with WNS 1.362 ns at 50 MHz. |
| J. Full matrix | BLOCKED | Not run by design. D/E/F/G do not meet strict promotion criteria, so a full 13-sample matrix would create misleading evidence. |
| K. Case studies | BLOCKED | `tools/generate_35t_case_studies.py` refuses promotion when `claim_level` is `prototype_only`; this was verified on the p0c ABBA run. |

## Capacity Decision

`p0c_syscall_trap_drop` at 512 records is the current capacity candidate, not a semantic-detector candidate. It removes context events and solves the immediate trace-capacity problem for the microbench set, but the behavior recovery and audit rules still need work before any full-matrix or case-study promotion.

Next engineering target: fix semantic recovery/audit false positives on the p0c 512 artifacts, especially the bogus `illegal_instruction_trap` matches in benign/file samples and the missing expected trap/file behaviors.
