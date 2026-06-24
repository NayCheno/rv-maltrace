# Slide Visual Audit for V5

V5 keeps the paper-centered story and removes or defines nonstandard terminology.

Core application status: the repository supports trace-backed behavior analysis, not a mature malware detector. The 35T path supports an end-to-end prototype for hardware trace + local code attribution + rule-based malware-behavior analysis under controlled limits. The Genesys2/CVA6 path supports scoped paper evidence through board runs, safe surrogate case studies, local code fixtures, and containment records, but it does not support real-malware accuracy, payload equivalence, or board-native source-line attribution.

| Slide | Professional slide issue found | Final correction / role |
| --- | --- | --- |
| 01 | Cover previously framed the meeting rather than the paper. | Paper title, one scope statement, and a standard signal: TRACE EVENTS FIRST. |
| 02 | Problem statement was too card-heavy for a research deck. | Two spacious contrast boxes explain why software observers are insufficient. |
| 03 | The thesis needed to separate hardware observations from semantic labels. | Use trace events and provenance, with provenance defined as source tags. |
| 04 | Contribution text risked becoming a shopping list. | Three equal cards map directly to trace collection, semantic reconstruction, and validation artifacts. |
| 05 | Core application was not explicit enough. | Make the application the slide: trace-backed behavior analysis. |
| 06 | Pipeline labels were previously too long and likely to wrap badly. | Use standard pipeline language: data sources, code map, semantic events, behavior rules. |
| 07 | Status page text was still too verbose after the first v4 pass. | Shorten to three rows: 35T end-to-end, CVA6 scoped, limits explicit. |
| 08 | System overview could be mistaken for a complete detector architecture. | Keep only the CVA6 trace-to-validation path and one scoped claim. |
| 09 | Trace semantics needed a contract view rather than raw detail. | Four compact rows cover control, syscall, context, and accounting records. |
| 10 | Local code analysis was under-explained. | Three cards cover ELF identity, trace-to-code join, and the missing source-line claim. |
| 11 | 35T evidence had to be connected to the implemented path. | Use four numeric cards and a red caveat to show end-to-end support without overclaiming. |
| 12 | CVA6 evidence needed implementation status, not vague progress. | Four rows separate board evidence, surrogate coverage, fixtures, and nonclaims. |
| 13 | Evaluation slide risked mixing proof, scope, and blockers. | Use supported / limited / unsupported claim categories. |
| 14 | Main empirical result could be buried among small metrics. | Use 122 as the hero number and push supporting counts to the right. |
| 15 | Workload discussion could imply in-the-wild malware benchmarking. | Three horizontal groups state safe baseline, surrogate workloads, and benign controls. |
| 16 | Perfect metrics could be misread as detector accuracy. | Large metric blocks plus a red footer: controlled workload analysis only. |
| 17 | Resource result needed a cost claim, not runtime-overhead wording. | Bar chart keeps resource deltas visible and states overhead is unsupported. |
| 18 | Reproducibility page was too close to project-management status. | Artifact package rows show manifest, archive, checkers, and paper maturity. |
| 19 | Claim boundary needed to be paper-centered. | Ledger says what to write, what to limit, and what not to claim. |
| 20 | Story slide had to center the paper rather than advisors. | Four cards connect problem, mechanism, application, and boundary. |
| 21 | Streaming/DMA details were dense and easy to misread. | Three clean rows state target, required throughput, and current future-work item. |
| 22 | Sample names are long and can easily overflow. | Widen the text lane and keep the roster in appendix only. |
| 23 | Resource table labels previously wrapped awkwardly. | Short row labels and wider numeric columns keep the appendix table stable. |
