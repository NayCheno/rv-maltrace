# RV-MalTrace NDSS Rewrite Plan

## Current State Analysis

The current draft has a **critical style problem**: it is written in an overly defensive, hedging tone. Almost every paragraph contains phrases like:
- "this draft does not claim..."
- "the current evidence does not..."
- "outside the evaluated scope"
- "we do not evaluate..."

This is **not how NDSS papers are written**. NDSS papers are confident, direct, and quantitative. They state what they do and support it with evidence. Limitations are mentioned briefly and clearly, not repeatedly throughout every section.

## Key Problems to Fix

| Issue | Current State | NDSS Standard |
|-------|---------------|---------------|
| Tone | Overly defensive, apologetic | Confident, direct, quantitative |
| Abstract | Mostly lists what is NOT done | Problem → Solution → Key Results |
| Introduction | No challenge list, no insight | Standard 7-paragraph structure |
| Related Work | Standalone section at end | Merged with Background or distributed |
| Design | No challenge-response structure | C1, C2, C3 → design subsections |
| Evaluation | 4 tiny RQs, no numbers | Quantified metrics, baselines, cases |
| Limitations | 4 paragraphs of "we don't evaluate" | 1 brief paragraph in Discussion |
| Conclusion | Reads like a todo list | Summarizes contributions + future work |

## Rewrite Strategy

### Structural Changes

1. **Merge Background and Related Work** into a single "Background & Related Work" section (standard NDSS pattern)
2. **Reorder sections**: Introduction → Background & Related Work → Threat Model → Design → Implementation → Evaluation → Discussion → Conclusion → Ethics
3. **Add a Discussion section** (missing in current draft) for brief limitations and future work
4. **Move Ethics to the end** (before references, per NDSS template)

### Content Strategy per Section

#### Abstract (~200 words)
- Open with the concrete problem: malware behavior analysis needs transparent, low-perturbation tracing
- State the gap: software tracers run inside the target environment; hardware traces are too low-level
- Introduce RV-MalTrace as the solution
- State key technical insight: source-labeled reconstruction preserves provenance
- Include quantitative results: trace correctness, attribution coverage, artifact reproducibility
- Single paragraph, confident tone

#### Introduction (1.5-2 pages, ~10 paragraphs)
- P1: Big problem — malware behavior analysis at scale needs transparent observation
- P2-3: Prior work categories + specific limitations
  - Software tracers (strace, eBPF, QEMU): detectable, perturbing, incomplete
  - Hardware tracers (ARM ETM, Intel PT): low perturbation but raw events need semantic reconstruction
- P4: Key insight — "Our insight is that hardware trace events can be connected to OS-level behavior semantics when each reconstructed field is labeled with its provenance source."
- P5: Solution overview — RV-MalTrace: CVA6 trace path + offline reconstruction pipeline + source labels
- P6: Technical challenges (C1-C3)
  - C1: How to capture the right architectural events (retire, trap, syscall, privilege) without software interference
  - C2: How to connect raw PC events to executable identity and process context under PIE/ASLR/fork/exec
  - C3: How to ensure reconstructed behavior is auditable by labeling each field with its evidence source
- P7: Bulleted contributions (4 items, specific and quantitative)
- P8: Artifact availability

#### Background & Related Work (1-1.5 pages)
- 2.1: Hardware-Assisted Tracing for Security (ARM ETM/ETB, Intel PT, PMU — Ninja, HART, microAFL)
- 2.2: RISC-V Security Extensions (Raft, CCTAG, etc.)
- 2.3: Semantic Reconstruction from Hardware Traces (what's missing: source labels, provenance)
- Table comparing prior work across dimensions: architecture, target space, perturbation level, semantic reconstruction, provenance labeling
- Position RV-MalTrace: first RISC-V system that connects hardware trace to source-labeled behavior reconstruction

#### Threat Model (0.5 page)
- Explicit attacker model: software-only adversary on a RISC-V Linux system
- Capabilities: can execute arbitrary user-space code, may fork/exec, may load dynamic libraries, may attempt evasion
- Assumptions: attacker cannot modify hardware trace logic, cannot physically access the board, cannot compromise the offline host
- Scope: user-space behavior analysis; kernel-level rootkits are outside scope
- What's NOT evaluated: real malware family accuracy, production transport, cycle overhead (1 brief sentence)

#### Design (3-4 pages)
- Use challenge-response structure: each subsection addresses a challenge from the introduction
- 4.1: Overall Architecture (system diagram)
- 4.2: Hardware Trace Collection (addressing C1: CVA6 adapter, event types, marker windows, SRET qualification)
- 4.3: Source-Labeled Reconstruction (addressing C3: provenance labels, field types, evidence separation)
- 4.4: Code Attribution (addressing C2: ELF identity, PIE/ASLR bias, dynamic libraries, fork/exec, stripped binaries)
- Figures: architecture diagram, source-label pipeline

#### Implementation (1 page)
- 5.1: CVA6 Trace Adapter (Verilog modifications, event encoding)
- 5.2: Genesys2 Board Path (BRAM buffer, marker protocol, controlled workload windows)
- 5.3: Offline Reconstruction Tools (Python pipeline, ELF parsing, process map joining, manifest verification)
- 5.4: Artifact Package (directory structure, SHA-256 checks, reproduction commands)

#### Evaluation (2-3 pages)
- 6.1: Experimental Setup (CVA6/Genesys2 platform, workload suite, reference tools: QEMU, strace)
- 6.2: RQ1 — Trace Correctness (directed tests: event ordering, trap/retire separation, syscall pairing, same-cycle ordering, privilege transitions, negative SRET cases; include pass/fail counts)
- 6.3: RQ2 — Source Labeling (label coverage percentage, field types verified, reference vs hardware field separation)
- 6.4: RQ3 — Code Attribution (attribution accuracy on: ELF identity, PIE/ASLR, dynamic objects, fork/exec, stripped binaries, source-map boundaries)
- 6.5: RQ4 — Reproducibility (quick reproduction time, Docker reproduction time, manifest coverage)
- 6.6: Discussion — Limitations (brief: 1 paragraph on production transport, 1 paragraph on real malware validation, 1 paragraph on cycle overhead)

#### Conclusion (0.5 page)
- Summarize what RV-MalTrace achieves
- Restate the key insight and its implications
- Brief future work (production transport, real malware validation, source-line recovery)
- Artifact availability

#### Ethics Considerations (short paragraph)
- Controlled workloads only; containment procedures for future real-malware experiments
- Artifact sanitization

## Tone Transformation Guide

| Current Phrasing | NDSS Rewrite |
|-----------------|-------------|
| "The current draft does not claim..." | (remove entirely) |
| "This paper is scoped as..." | "We focus on..." |
| "It is not a malware classifier" | (remove; state what it IS) |
| "The main finding is deliberately narrow" | "We demonstrate that..." |
| "The evaluation does not include..." | (move to 1 brief limitation paragraph) |
| "We do not evaluate..." | (remove or rephrase as scope) |
| "controlled workloads do not establish..." | (remove entirely) |
| "Our results might be..." | "Our results show..." |
| "To the best of our knowledge" | "To the best of our knowledge, this is the first..." (when appropriate) |

## Execution Plan

### Stage 1: Parallel Writing (4 workers)
- Worker 1: Abstract + Introduction (most critical, needs full context)
- Worker 2: Background & Related Work (needs reference list)
- Worker 3: Threat Model + Design (needs technical understanding)
- Worker 4: Implementation + Evaluation (needs technical understanding)

### Stage 2: Integration
- Combine all sections into a single LaTeX file
- Ensure consistent terminology, cross-references, and tone
- Verify all \rvmt references work

### Stage 3: Validation
- Review against NDSS style checklist
- Check for any remaining defensive language
- Verify quantitative claims are present
- Ensure proper LaTeX formatting

## Output
- Rewritten paper: `docs/08-publication/ndss2026-rv-maltrace/sections/` (overwrite all .tex files)
- Updated `main.tex` if needed
- `references.bib` if additional citations are needed
