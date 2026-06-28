# Slide Visual Audit for V6

V6 reorganizes the weekly update around six research-meeting questions: problem, value, conclusion, evidence, boundaries, and next decisions.

Core application status: the repository supports hardware-assisted behavior reconstruction for controlled RISC-V Linux workloads. It does not support real-malware accuracy, payload equivalence, production transport throughput, cycle-level overhead, or board-native source-line attribution claims.

| Slide | Professional slide issue found | Final correction / role |
| --- | --- | --- |
| 01 | The cover did not state the meeting objective. | State the expected belief change, not only the project name. |
| 02 | The talk lacked an explicit checklist. | Add a six-question map that governs the rest of the deck. |
| 03 | The research problem could be mistaken for implementation progress. | Frame the gap between low-level trace and high-level behavior claims. |
| 04 | Motivation needed a research reason, not just a tool description. | Explain why software references are insufficient as the only evidence path. |
| 05 | The conclusion was buried in status pages. | Make the scoped conclusion explicit before showing evidence. |
| 06 | Evidence was previously scattered. | Use one evidence map before detailed results. |
| 07 | The pipeline page needed to support source separation. | Show trace, code maps, runtime maps, and reference logs as distinct inputs. |
| 08 | Trace correctness needed to precede behavior interpretation. | Make the trace contract the first evidence detail. |
| 09 | Source labeling needed a dedicated slide. | Explain that source labels prevent reference logs from becoming hardware claims. |
| 10 | Code attribution was under-explained. | Keep edge cases and the missing source-line claim together. |
| 11 | The strongest empirical result needed visibility. | Use 122 accepted board windows as the hero evidence. |
| 12 | Workload scope could imply real-malware benchmarking. | State controlled workload coverage and its limit. |
| 13 | Perfect metrics could be misread as detector accuracy. | Keep the red footer: reconstruction only, not detector accuracy. |
| 14 | Limitations needed to be part of the argument. | Treat unsupported topics as claim boundaries. |
| 15 | Alternative explanations were absent. | List what the current evidence rules out and what it still cannot rule out. |
| 16 | Cost evidence risked overclaiming runtime overhead. | Separate resource/timing closure from cycle-level slowdown. |
| 17 | The deck lacked a decision request. | End with concrete group decisions rather than a task list. |
| 18 | Reproducibility looked like project administration. | Tie artifact checks to evidence trust. |
| 19 | The story slide did not mirror the six questions. | Close with problem, conclusion, evidence, boundary, and decision. |
| 20 | Streaming/DMA details were dense and easy to misread. | Keep them as future-work appendix material. |
| 21 | Sample names are long and can overflow. | Keep the roster in appendix only. |
| 22 | Resource table labels can wrap awkwardly. | Use compact row labels and wider numeric lanes. |
