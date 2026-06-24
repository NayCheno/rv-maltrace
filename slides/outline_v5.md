# RV-MalTrace Paper-Centered Outline V5

The deck is organized around the paper's trace-backed behavior analysis pipeline: hardware trace plus local code analysis plus rule-based malware-behavior analysis.

## 01. RV-MalTrace

- Section: Paper Framing
- Claim: Hardware-assisted behavior tracing for RISC-V Linux workloads
- Notes: 论文中心叙事：这不是 advisor decision deck，也不是 malware detector。核心论文对象是 hardware-assisted tracing、code attribution 和 provenance-aware semantic reconstruction。provenance 在这里按常规定义使用：每个高层语义标签必须能追溯到 trace、code map 或 oracle/reference field。

## 02. Software-only tracing changes the observation surface

- Section: Research Problem
- Claim: Software tracers are useful references, but visible to workloads.
- Notes: 问题写成 paper problem：strace/QEMU/host logs 是必要 reference/oracle，但对抗性 workload 可感知软件观测面。oracle 是测试领域常用术语；主 slide 使用 reference，避免听众误读。

## 03. Trace events first; derived semantics carry provenance

- Section: Thesis
- Claim: The paper claims a trace-backed behavior analysis pipeline.
- Notes: 论文主张不是泛泛的 trace substrate，而是 hardware trace + code map + rule-based behavior analysis。provenance 是标准数据谱系/证据追踪术语，不是自造词；真实 malware 检测准确率仍不是当前 claim。

## 04. Three contributions define the paper

- Section: Contributions
- Claim: Each contribution maps to code and evidence in the repository.
- Notes: 贡献页只讲三点：CVA6 out-of-band trace collection、semantic reconstruction with provenance、Genesys2/CVA6 validation artifacts。

## 05. The application is trace-backed behavior analysis

- Section: Core Application
- Claim: Hardware trace, local code analysis, and malware-behavior rules are joined.
- Notes: 回应核心问题：应用不是单独的 trace，也不是单独的 malware detector，而是把硬件 trace、本地 ELF/code-map 分析、malware-behavior taxonomy/rules 连接起来。trace-backed behavior analysis 是描述性组合词，页内拆成三列解释。

## 06. Implementation joins three data sources

- Section: How It Works
- Claim: Trace events stay separate from code attribution and behavior labels.
- Notes: 实现路径：trace.jsonl -> semantic_events/behavior_graph；ELF/code_map -> trace-code join；manifest/rules -> rule-based malware-behavior analysis。用 data sources 替代 evidence planes，避免生造术语。

## 07. Implemented as a scoped prototype

- Section: Implementation Status
- Claim: 35T is end-to-end; Genesys2/CVA6 supports scoped evidence.
- Notes: 35T: 13/13 synthetic matrix + 6/6 malware-derived safety-controlled behavior cases。Genesys2/CVA6: 12 controlled case studies, 8 safe surrogate case studies, local code fixtures PASS, but not real-malware validation。scoped prototype 是标准项目/论文表述，比 bounded app 更自然。

## 08. CVA6 commit events feed semantic reconstruction

- Section: System Overview
- Claim: The CVA6 path is sideband trace plus offline reconstruction.
- Notes: 保留 CVA6 的论文贡献：从 commit-time trace 到 semantic event reconstruction，再到 validation scripts/checkers。此处不把它写成完整 malware detector。

## 09. Trace records capture transitions and drops

- Section: Trace Semantics
- Claim: The trace format is the contract between RTL and analysis.
- Notes: 事件类型来自 trace_format.md：retire/control-flow/syscall/trap/context/memory/drop。这里按类别表达，不把所有枚举塞满。

## 10. Code maps make trace evidence attributable

- Section: Local Code Analysis
- Claim: ELF identity, symbols, syscall sites, and runtime maps constrain attribution.
- Notes: 本地代码分析包括 build_code_map、join_trace_code_map、source attribution summary。Genesys2 local fixtures PASS，但 board-native DWARF/source-line 仍不能声称。

## 11. The 35T end-to-end path is implemented

- Section: 35T Closure
- Claim: 35T connects trace capture, code-map join, and behavior rules.
- Notes: 35T evidence: 13/13 synthetic matrix PASS, 512-record trace budget, fd/path and process-tree targeted validation PASS, 6/6 malware-derived safety-controlled behavior cases PASS。

## 12. CVA6 supports the current paper evidence

- Section: Genesys2/CVA6 Status
- Claim: It is not yet a real-malware validation or source-line attribution claim.
- Notes: Genesys2/CVA6 current: case_study_manifest PASS with 12 case studies; 8 safe surrogate case studies; rule-based behavior analysis metrics PASS; local code fixtures PASS_LOCAL_CODE_ANALYSIS_FIXTURES; real malware containment PASS but no payloads in repo。

## 13. Separate supported, limited, and unsupported claims

- Section: Evaluation Design
- Claim: The paper must separate implementation evidence from nonclaims.
- Notes: RQ 不要写成 submission traffic light，而是写成 evaluation design：supported evidence、limited evidence、unsupported claims。

## 14. 122 accepted board runs

- Section: Genesys2/CVA6 Result
- Claim: This is the strongest current CVA6 empirical result.
- Notes: 12 samples, 126 attempts, 122 accepted reps, 4 failed retained, 0 drops/wraps/gaps in accepted windows。

## 15. Controlled workloads, not in-the-wild malware

- Section: Workloads
- Claim: The workload set supports tracing validation under controlled behavior coverage.
- Notes: 4 safe baseline programs, 8 malware-behavior surrogate workloads, 5 benign controls。不要称真实 malware benchmark。surrogate 是安全实验中常用术语，这里指 repo-authored、safety-controlled implementations。

## 16. Rule-based behavior analysis passes scoped checks

- Section: Behavior Audit
- Claim: These metrics validate reconstruction, not detector accuracy.
- Notes: 指标全过容易被误读，所以图内必须写 controlled-only / not detection accuracy。

## 17. Resource cost is measured; overhead is not

- Section: Cost
- Claim: Timing/resource evidence supports implementation cost, not cycle slowdown.
- Notes: LUT +25.32%, FF +16.18%, BRAM18 +5.56%, DSP +0, timing MET slack 0.177 ns。不能写 runtime slowdown。

## 18. The artifact package is reviewable

- Section: Reproducibility
- Claim: Evidence packaging and checkers are ahead of manuscript completeness.
- Notes: raw archive 3160 files / 316.9 MB；repro quick/full pass；paper skeleton builds but content incomplete。

## 19. Claim boundaries are explicit

- Section: Claim Boundaries
- Claim: Unsupported topics become limitations or future work.
- Notes: 以论文写作边界为中心：可以写 trace-backed behavior analysis 和 35T end-to-end prototype，不能写 mature malware detector 或 CVA6 real-malware accuracy。

## 20. Paper narrative

- Section: Paper Story
- Claim: Hardware trace + code attribution + rule-based malware-behavior analysis.
- Notes: 收尾不再让导师拍板，而是给出论文中心叙事：problem -> trace-backed analysis pipeline -> scoped prototype -> limitations/future work。

## 21. Streaming/DMA remains future work (Appendix)

- Section: Appendix
- Claim: Readiness and target profiles are not throughput evidence.
- Notes: target p99 0.0215755 B/cycle; required 0.0323633 B/cycle; at 50 MHz required 1.618 MB/s; current sustained=0, noninterference=false。

## 22. Workload roster (Appendix)

- Section: Appendix
- Claim: Sample names are appendix material, not main-story material.
- Notes: 列出 safe baseline、malware-behavior surrogates、benign controls。P0 safe 是内部分组名，正文不使用。

## 23. Resource detail (Appendix)

- Section: Appendix
- Claim: Resource/timing claim is supported; runtime overhead is not.
- Notes: baseline vs trace-enabled resource table。
