# NDSS Writing Style Guide for Writers

## Core Principle: Confident, Direct, Quantitative

NDSS papers are written in a confident, direct, active voice. They state what they do and support it with evidence. Limitations are mentioned briefly and clearly, not repeatedly throughout every section.

## Tone Transformation

| BAD (defensive) | GOOD (NDSS confident) |
|-----------------|----------------------|
| "The current draft does not claim..." | (remove entirely) |
| "This paper is scoped as..." | "We focus on..." |
| "It is not a malware classifier" | (remove; state what it IS) |
| "The main finding is deliberately narrow" | "We demonstrate that..." |
| "The evaluation does not include..." | (move to 1 brief limitation paragraph) |
| "We do not evaluate..." | (remove or rephrase as scope) |
| "controlled workloads do not establish..." | (remove entirely) |
| "Our results might be..." | "Our results show..." |
| "reported as local attribution evidence rather than board-native source-line recovery" | "we achieve X% attribution accuracy on controlled workloads" |
| "outside the evaluated scope" | (remove from most sections; keep 1 brief mention in Discussion) |

## Standard NDSS Introduction Structure

P1: Real-world problem with concrete impact
P2-3: Prior work categories + specific limitations
P4: Key insight ("Our insight is that...")
P5: Solution overview ("We present SYSTEM, which...")
P6: Technical challenges (C1, C2, C3...)
P7: Bulleted contributions (specific, with "what" and "why")
P8: Artifact / scope note

## Abstract Pattern

~150-250 words, single paragraph:
- Problem → Gap → Solution name → Key mechanism → Quantitative results
- Use: "we propose", "we design", "we demonstrate"

## Design: Challenge-Response Structure

Each design subsection should address a specific challenge from the introduction:
- C1: How to capture the right events without software interference → 4.2 Hardware Trace Collection
- C2: How to connect raw PCs to executable identity under PIE/ASLR/fork/exec → 4.4 Code Attribution  
- C3: How to ensure auditable provenance → 4.3 Source-Labeled Reconstruction

## Evaluation Standards

- Quantified claims with specific numbers
- Comparison with state-of-the-art or baselines
- Multiple metrics (security, performance, accuracy)
- Brief limitations at the END (1 paragraph, not a whole section)

## Related Work

- Categorize prior work, don't just list it
- State what each achieves + its limitation
- Position the paper in a gap
- End with: "To the best of our knowledge, this is the first..." (when justified)

## Key Phrases to Use

- "We propose X, which achieves Y"
- "Our insight is that..."
- "To address this challenge, we..."
- "Our evaluation on X shows that..."
- "Compared to the state-of-the-art, our approach achieves..."
- "To the best of our knowledge, the first..."
- "We consider X as an initial step towards..." (for scope)
- "It is out of our scope to deal with..." (for scope, 1 brief mention)

## Key Phrases to AVOID

- "We attempt to", "We try to"
- "It might be possible that"
- "Due to our limited resources"
- "We consider a simplified version"
- Repeated "we do not evaluate" throughout every section
- "This draft", "the current draft" (use "we" or "this paper")
