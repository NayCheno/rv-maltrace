# NDSS Writing Style Analysis: A Comprehensive Guide

**Date:** 2026-04-10
**Sources:** 5+ full NDSS papers (2021-2025), NDSS CFPs, scholarly meta-research on cybersecurity writing style, and 40+ paper abstracts from Google Scholar.

---

## 1. Typical Paper Structure

### Standard NDSS Section Hierarchy

Based on analysis of NetPlier (2021), NODLINK (2024), DESERIGUARD (2024), SCRUTINIZER (2025), and CCTAG (2025), the canonical NDSS structure is:

```
I. Introduction
II. Background & Related Work (or "Motivation", "Preliminaries")
III. Threat Model
IV. System Design / Methodology
V. Implementation
VI. Evaluation
VII. Discussion
VIII. Conclusion
```

**Key observations:**
- **Background and Related Work are often merged** into a single section (e.g., "Background & Related Work" in CCTAG, "Background and Motivation" in DESERIGUARD). In SCRUTINIZER, they are separated: Background is Section II, and related work is woven throughout rather than a standalone section.
- **Threat Model appears early** — typically Section III or embedded in Background. This is a hallmark of systems security papers. NDSS expects explicit threat modeling before design presentation.
- **Design sections are long and detailed** — often 4-6 pages. The design is usually presented with subsections for each major component.
- **Evaluation is empirically heavy** — NDSS papers typically include: (a) security evaluation, (b) performance evaluation, (c) comparison with state-of-the-art, (d) case studies on real-world scenarios. The SCRUTINIZER paper has §VI-B (security), §VI-C (performance), and §VI-D (application cases).
- **"Discussion" is not always a separate section** — limitations and future work are often integrated into the conclusion or woven into evaluation.

### Variations by Paper Type

- **Systems/Implementation papers** (SCRUTINIZER, CCTAG): Heavy on design details, hardware features, threat model, TCB analysis.
- **Analysis/Measurement papers** (NetPlier, DESERIGUARD): Strong on algorithmic/methodological innovation, formal problem formulation, extensive comparative evaluation.
- **Formal/theoretical papers**: May include "Preliminaries" with mathematical definitions before the main design.

---

## 2. Abstract Characteristics

### Length and Format

NDSS abstracts are **typically 150-250 words** (about 1 paragraph, sometimes 2). They are structured as a single block of text, not itemized.

### What Strong NDSS Abstracts Include (with examples)

**Pattern: Problem → Gap → Solution → Key Mechanism → Results**

**Example 1 — NetPlier (2021):**
> "Network protocol reverse engineering is an important challenge with many security applications. A popular kind of method leverages network message traces. These methods rely on pair-wise sequence alignment and/or tokenization. They have various limitations such as difficulties of handling a large number of messages and dealing with inherent uncertainty. **In this paper, we propose** a novel probabilistic method for network trace based protocol reverse engineering... **Our evaluation on 10 protocols shows** that our technique substantially outperforms the state-of-the-art..."

**Example 2 — SCRUTINIZER (2025):**
> "The number of vulnerabilities exploited in Arm TrustZone systems has been increasing recently. The absence of digital forensics tools prevents platform owners from incident response or periodic security scans. However, the area of secure forensics for compromised TrustZone remains unexplored and presents unresolved challenges. Traditional out-of-TrustZone forensics are inherently hindered by TrustZone protection, rendering them infeasible. In-TrustZone approaches are susceptible to attacks from privileged adversaries, undermining their security. **To fill these gaps, we introduce SCRUTINIZER, the first** secure forensics solution for compromised TrustZone systems. **Our experiments demonstrate**..."

**Example 3 — NODLINK (2024):**
> "Advanced Persistent Threats (APT) attacks have plagued modern enterprises, causing significant financial losses. To counter these attacks, researchers propose techniques that capture the complex and stealthy scenarios of APT attacks by using provenance graphs... **Unfortunately, existing online systems usually sacrifice detection granularity** to reduce computational complexity... **In this paper, we design and implement NODLINK, the first** online detection system that maintains high detection accuracy without sacrificing detection granularity. **Our insight is that**... **We evaluate NODLINK in a production environment.**"

### Abstract Tone

- **Direct and confident**: Phrases like "we propose", "we design and implement", "we introduce", "we evaluate" are standard.
- **Problem-first**: The abstract opens with the real-world problem or security threat, not with methodology.
- **"First" claims are common when justified**: NDSS papers often claim "the first X" but this is usually carefully qualified with scope (e.g., "the first secure forensics solution for compromised TrustZone systems" — not just "the first forensics tool").
- **Quantitative results**: Strong abstracts include specific metrics: "100% homogeneity and 97.9% completeness" (NetPlier), "20x and 49.5% faster" (SCRUTINIZER), "4.71% and 7.93% runtime overhead" (CCTAG).

### Weak Abstract Red Flags

- Vague problem statements without concrete security impact
- Missing quantitative results
- Overclaiming without qualification (e.g., "the first system ever" without domain restriction)
- Excessive hedging ("might", "could potentially", "may perhaps")

---

## 3. Introduction Characteristics

### Length and Organization

NDSS introductions are **typically 1.5-2 pages** (about 6-12 paragraphs in two-column format). They follow a very predictable structure.

### Standard Introduction Template (Observed Pattern)

**Paragraph 1 — The Big Problem/Domain:**
- Open with the real-world security problem or domain importance.
- Example (DESERIGUARD): "Serialization and deserialization are essential mechanisms offered by programming languages such as Java, JavaScript, PHP, and C# for object and byte stream transformation. However, these capabilities also introduce a type of significant vulnerability, which can cause severe consequences such as remote code execution (RCE), denial of service (DoS), and server-side request forgery (SSRF)."
- Example (CCTAG): "Memory safety violations are a significant concern in real-world programs, prompting the development of various mitigation methods."

**Paragraph 2-3 — Existing Approaches and Their Limitations:**
- Survey existing techniques briefly but specifically.
- Use phrases like "Existing works usually...", "However, these techniques...", "The former achieves X but suffers from Y."
- Example (NetPlier): "Existing protocol reverse engineering techniques fall into a few categories... However, most of these techniques require access to program binaries, which is often infeasible in practice."
- Example (SCRUTINIZER): "While existing approaches [39],[47],[55],[65],[73] have been proposed to inspect Rich Execution Environment (REE)... none of these techniques have been applied to target TrustZone systems. However, applying the same methods to TrustZone systems is highly challenging due to several factors."

**Paragraph 4 — Key Insight / Observation:**
- This is the pivot point. State the insight that motivates the paper's approach.
- Example (NetPlier): "We observe that the key to network protocol reverse engineering is to identify the keyword field that determines the type of a message."
- Example (NODLINK): "Our insight is that the APT attack detection process in online provenance-based detection systems can be modeled as a Steiner Tree Problem (STP), which has efficient online approximation algorithms..."

**Paragraph 5 — Overview of Solution:**
- Introduce the system name (often in ALL CAPS or with a specific formatting).
- Describe the high-level approach in 2-3 sentences.
- Example (CCTAG): "In this paper, we present CCTAG, a novel, lightweight tagged architecture designed to be both configurable and combinable, addressing the need for efficient and compatible integration of various defense mechanisms."

**Paragraph 6 — Key Challenges:**
- Enumerate 2-4 specific technical challenges (often labeled C1, C2, C3... in the design section, but introduced here).
- Example (SCRUTINIZER): "However, we face several key challenges to achieving the whole process. C1: While secure memory acquisition is possible in Root world, it could potentially lead to an undue expansion of the codebase..."

**Paragraph 7 — Contributions (often bulleted):**
- NDSS papers almost always have a "Contributions" subsection or paragraph with explicit bullets.
- Contributions are numbered and specific. Each bullet states WHAT was done and WHY it matters.
- Example (NetPlier):
  - "We address a key challenge in network protocol reverse engineering – keyword identification..."
  - "We formulate keyword identification as a probabilistic inference problem..."
  - "We build an end-to-end system NETPLIER..."
  - "We evaluate NETPLIER on 10 protocols..."
- Example (DESERIGUARD):
  - "We propose an automatic policy generation and enforcement framework..."
  - "We implement DESERIGUARD, which synthesizes the allowlist policy..."
  - "We evaluate the DESERIGUARD on 12 real-world vulnerabilities..."

### Tone: Confident vs. Defensive

NDSS introductions are **predominantly confident, not defensive**.

**Confident language patterns (hallmarks of strong NDSS papers):**
- "We propose", "We design", "We demonstrate", "We show"
- "Our insight is that..."
- "Our results show that..." (with specific numbers)
- "To the best of our knowledge, this is the first..." (a classic, careful claim)
- "Substantially outperforms the state-of-the-art" (NetPlier)

**Defensive language (signs of weaker submissions):**
- Excessive hedging: "We attempt to", "We try to", "It might be possible that"
- Apologetic framing: "Due to our limited resources, we only evaluated..."
- Vague scope: "We consider a simplified version of the problem..."

**However**, NDSS papers do use measured hedging for scope limitations:
- "We consider SCRUTINIZER as an initial step towards secure forensics for TrustZone systems." (acknowledges scope without being defensive)
- "It is out of our scope to deal with the application-layer issues..." (clear scope boundary)
- "Note that availability (e.g., DoS prevention) is outside our goals." (SCRUTINIZER — explicit scope statement)

---

## 4. Related Work Writing Style

### How NDSS Papers Compare to Prior Work

**Related work is NOT a standalone literature review.** In NDSS, related work is typically:
1. **Merged with Background** (e.g., "Background & Related Work" in CCTAG, "Background and Motivation" in DESERIGUARD)
2. **Distributed throughout the paper** — prior work is cited when introducing each design component, not just in a dedicated section

### Comparison Patterns

**Pattern 1: Categorize and Contrast**
- Papers are grouped into categories. The paper positions itself in a gap between categories.
- Example (CCTAG): "Many runtime defense mechanisms have been developed... Below, we discuss mainstream approaches and introduce representative works. 1) Spatial Memory Safety Enforcement... 2) Temporal Memory Safety Enforcement... 3) Control Flow Integrity..." Then CCTAG shows how it integrates across these categories.

**Pattern 2: Limitation-Driven Contrast**
- For each prior approach, the paper states what it achieves and then its specific limitation that motivates the current work.
- Example (NetPlier): "The alignment-based clustering methods work on an assumption that messages are of the same type if they have similar sequences of values. However, this assumption is not true all the time..." (followed by concrete failure examples)
- Example (NODLINK): "Rule-based systems suffer low node-level accuracy due to the incomplete rule set... On the flip side, learning-based systems have low node-level precision due to over-approximation."

**Pattern 3: Table-Based Comparison**
- Strong NDSS papers often include a comparison table positioning their work against prior art across multiple dimensions.
- Example (CCTAG): Table II comparing "CCTAG and other tagged architectures in terms of versatility, efficiency, and overhead."

### Related Work Tone

- **Respectful but critical**: "X et al. achieved Y, which is effective for Z. However, their approach assumes A, which does not hold in our scenario because B."
- **Never dismissive**: NDSS papers do not say "prior work is wrong" — they say "prior work addresses a different problem" or "prior work makes assumptions that limit applicability."
- **Self-positioning**: The related work section always ends with a clear statement of where the paper fits: "None of these techniques have been applied to target TrustZone systems." (SCRUTINIZER)

---

## 5. Evaluation Writing Style

### Metrics and Organization

NDSS evaluation sections are typically **3-5 pages** and are organized into clear subsections:

**Standard Evaluation Subsections:**
1. **Experimental Setup** — datasets, platforms, baselines
2. **Security Evaluation** — does the system actually prevent/detect the attacks it claims to?
3. **Performance Evaluation** — overhead, latency, throughput
4. **Comparison with State-of-the-Art** — head-to-head against 2-3 baselines
5. **Case Studies / Real-World Deployment** — (for strong papers) real-world scenarios
6. **Ablation Studies** — (for strong papers) which components matter most?

### Evaluation Claims: Confident and Quantified

**Strong NDSS evaluation language:**
- "Our results show that NETPLIER can achieve 100% homogeneity and 97.9% completeness, whereas the state-of-the-art techniques can only achieve around 92% homogeneity and 52.3% completeness." (NetPlier — specific, comparative)
- "SCRUTINIZER is 20x and 49.5% faster for the memory acquisition and access traps, respectively." (SCRUTINIZER — precise multiples)
- "DESERIGUARD successfully blocks all deserialization attacks on 12 real-world vulnerabilities... restricts 99.12% more classes... induces a negligible time overhead of 2.17%." (DESERIGUARD — absolute success rate + comparative + overhead)
- "NODLINK outperforms two state-of-the-art... by achieving magnitudes higher detection and investigation accuracy while having the same or higher timeliness." (NODLINK — qualitative + quantitative)

### Evaluation Red Flags (Weak Papers)

- Using toy datasets without real-world validation
- Only evaluating on synthetic data
- Missing comparison with state-of-the-art
- Vague claims: "our system performs well" without numbers
- Not reporting false positives (critical for security systems)
- Missing overhead measurements for systems work

---

## 6. Overall Tone and Style

### Direct, Active, and System-Focused

NDSS writing has a distinctive **active, system-oriented voice**:

- **Active voice dominates**: "We propose", "We design", "Our system achieves"
- **System names are treated as proper nouns**: "NETPLIER takes network traces as input", "SCRUTINIZER leverages CCA hardware features"
- **Technical precision**: Every claim is tied to a specific mechanism, feature, or metric.

### Concise but Technical

- NDSS papers favor **density over verbosity**. Sentences are packed with technical content.
- Example: "We propose a protective layer in the Root world that delegates an agent to execute in Secure world, ensuring the agent remains isolated against the TrustZone systems." (SCRUTINIZER — one sentence = mechanism + location + property)
- **No fluff**: Introductions get to the point quickly. There is no "In recent years, with the rapid development of the Internet..." style padding.

### Use of "We"

- The first-person plural "we" is standard and expected in NDSS. It is used for:
  - Stating contributions: "We propose..."
  - Describing design decisions: "We choose to use the VAE model because..."
  - Interpreting results: "We consider SCRUTINIZER as an initial step..."

### Defensive Hedging: When It Appears

NDSS papers do hedge, but strategically:
- **Scope boundaries**: "It is out of our scope to deal with..."
- **Assumptions**: "We assume that protection against side-channel attacks... is beyond the scope."
- **Limitations of specific components**: "Although NODLINK may achieve better process embedding by leveraging more complex graph embedding techniques... these techniques... are too heavy for an online detection system." (acknowledges better approaches exist but justifies the practical choice)

---

## 7. Key Differences Between Strong and Weak NDSS Papers

| Dimension | Strong NDSS Papers | Weaker NDSS Submissions |
|-----------|-------------------|------------------------|
| **Problem Motivation** | Concrete, real-world security problem with clear impact ($ losses, CVE counts, attack statistics) | Abstract or generic problem; unclear why it matters |
| **Related Work** | Precise categorization; clear gap identified with specific limitations of prior work | Literature dump without clear positioning |
| **Technical Insight** | One clear, non-obvious insight that drives the design | Incremental combination of known techniques |
| **Threat Model** | Explicit, well-scoped, with clear assumptions and limitations | Missing or vague; "we assume the attacker is powerful" |
| **Design** | Novel mechanism clearly explained; components justified by challenges | Black-box description; no design rationale |
| **Evaluation** | Real-world datasets, real baselines, head-to-head comparison, multiple metrics | Synthetic data only, no baselines, missing false positives |
| **Writing** | Confident, precise, quantitative; every claim is supported | Hedging, vague, hand-wavy; claims without evidence |
| **Artifact** | Open-source code, public datasets (NDSS strongly encourages artifact evaluation) | No artifact or closed evaluation |

### Hallmarks of Top-Tier NDSS Papers (Distinguished Papers)

1. **Real-world deployment or open-world evaluation**: NODLINK evaluated in a production SOC environment. DESERIGUARD tested on 12 real-world vulnerabilities and 109 developer policies.
2. **Theoretical grounding + practical implementation**: NODLINK formalizes APT detection as an STP problem with approximation bounds, then implements and deploys it.
3. **Novel hardware/software co-design**: SCRUTINIZER leverages CCA hardware (RME) with novel software architecture. CCTAG modifies RISC-V processor on FPGA.
4. **First real-world system in a new domain**: "The first secure forensics solution for compromised TrustZone systems" (SCRUTINIZER), "the first online detection system that maintains high detection accuracy without sacrificing detection granularity" (NODLINK).
5. **Artifact evaluation**: NDSS introduced artifact evaluation in 2024. Strong papers submit open-source artifacts.

---

## 8. Common Writing Patterns in Good NDSS Papers

### Phrase Templates (Observed in Strong Papers)

**Problem Statement:**
- "X has become a major threat to..."
- "The number of vulnerabilities in Y has been increasing..."
- "Existing approaches [cite] have difficulties in..."
- "Unfortunately, existing systems usually sacrifice A to achieve B..."

**Insight/Contribution:**
- "Our insight is that..."
- "The key observation is that..."
- "To fill this gap, we introduce..."
- "We propose a novel approach that..."

**Design Description:**
- "Specifically, we..."
- "To address this challenge, we..."
- "Our design proposes X that decouples Y from Z..."
- "We leverage standard hardware features to enable..."

**Evaluation:**
- "Our evaluation on X shows that..."
- "Compared to the state-of-the-art [system], our approach achieves..."
- "To the best of our knowledge, this is the first..."
- "We release [system] and data at [URL]"

**Scope and Limitations:**
- "We consider X as an initial step towards..."
- "It is out of our scope to deal with..."
- "We assume a trusted Y, so attacks on Z are beyond the scope."
- "Note that A is outside our goals."

### Structural Patterns

1. **Challenge-Response Structure**: Each design subsection addresses a specific challenge (C1, C2, C3...). This is extremely common in NDSS systems papers.
   - Example: SCRUTINIZER introduces C1-C4 in the introduction and then (a)-(d) design solutions in the design section.

2. **Two-Step Universal Process**: "Tagged memory architectures in defense solutions typically adhere to a universal two-step process: The first step involves... If this verification passes, the system will..." (CCTAG)

3. **Motivation Example → General Design**: Papers often start with a concrete motivating example (with a figure), then generalize to the design. NetPlier, DESERIGUARD, and CCTAG all use this pattern.

4. **Formalization + Approximation**: For algorithmic papers, the pattern is: (a) Formalize the problem, (b) Show it's NP-hard or has known bounds, (c) Propose an approximation algorithm, (d) Prove competitive ratio, (e) Implement and evaluate. NODLINK follows this exactly.

---

## 9. Recent Trends (2022-2025)

### Generative AI Impact on Writing Style

According to the 2026 meta-research paper "ChatGPT, is this real?" analyzing 25 years of NDSS, USENIX Security, IEEE S&P, and ACM CCS papers:

- **Post-2022 increase in lexical complexity**: Mean word length and long-word rate (words ≥7 characters) have increased since 2022-2023.
- **Decrease in readability**: Flesch Reading Ease scores have gradually declined since 2022.
- **"Marker words" increasing**: Words like "underscoring", "enhancing", "delve", and "leveraging" show sharp post-2022 increases.
- **NDSS was the first A* venue to formalize a GenAI policy** (for 2025), ahead of USENIX, IEEE S&P, and ACM CCS.

**Implication for authors**: Avoid over-reliance on LLM-polished language. The NDSS CFP explicitly encourages writing that is "accessible and compelling to a general security researcher." Overly complex or "academic-sounding" prose may actually hurt accessibility.

### NDSS CFP Writing Guidance (Direct Quotes)

From the NDSS 2025-2026 CFPs:
> "Authors are encouraged to write the abstract and introduction of their paper in a way that makes the results accessible and compelling to a general security researcher."

> "The target audience includes everyone interested in practical aspects of network and distributed system security, with a focus on system design and implementation."

This means:
- Write for a general security researcher, not just a subfield specialist
- Make the problem and results accessible in the abstract/introduction
- Focus on practical system design and implementation

---

## 10. Summary Checklist for Writing an NDSS-Style Paper

**Abstract:**
- [ ] Opens with concrete problem (not generic background)
- [ ] States specific limitations of existing approaches
- [ ] Introduces solution with system name
- [ ] Includes key quantitative results
- [ ] ~150-250 words, single paragraph

**Introduction:**
- [ ] Paragraph 1: Real-world problem with concrete impact
- [ ] Paragraphs 2-3: Prior work categories + specific limitations
- [ ] Paragraph 4: Key insight (the "aha" moment)
- [ ] Paragraph 5: High-level solution overview
- [ ] Paragraph 6: Specific technical challenges (C1, C2, C3...)
- [ ] Paragraph 7: Explicit bulleted contributions
- [ ] Uses confident active voice ("we propose", "we demonstrate")
- [ ] Ends with scope statement or artifact availability

**Related Work:**
- [ ] Categorizes prior work, not just lists it
- [ ] Identifies specific gaps/limitations for each category
- [ ] Clear statement of how this paper differs
- [ ] Includes comparison table (for strong papers)

**Design:**
- [ ] Addresses each challenge from introduction
- [ ] Justifies each design decision
- [ ] Uses diagrams/figures to explain architecture
- [ ] Explicit threat model before or alongside design

**Evaluation:**
- [ ] Real-world or representative datasets
- [ ] Comparison with 2+ state-of-the-art baselines
- [ ] Multiple metrics (security, performance, accuracy)
- [ ] False positive/negative analysis (for detection systems)
- [ ] Overhead measurements (for systems work)
- [ ] Case studies or real-world deployment (for top papers)
- [ ] Artifact released (strongly encouraged)

**Overall:**
- [ ] Confident, direct, quantitative tone
- [ ] Active voice with "we"
- [ ] System name treated as proper noun
- [ ] Every claim supported by evidence or citation
- [ ] Accessible to general security researchers (per CFP)
- [ ] No excessive hedging or defensive language
