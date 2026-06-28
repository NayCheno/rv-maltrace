# RV-MalTrace Six-Question Weekly Outline V7

The deck is organized so that a listener can answer six questions after the weekly meeting: research problem, motivation, current conclusion, supporting evidence, evidence boundaries, and next decisions.

## 01. RV-MalTrace

- Section: Weekly Thesis
- Claim: What should the group believe after this update?
- Notes: 周会目标：不是复述论文结构，而是让听众能回答研究问题、价值、当前结论、证据、边界和下一步判断。

## 02. The report has to answer six questions

- Section: Six Questions
- Claim: Every slide should help answer one of them.
- Notes: 把导师/同学带到同一条判断链上：先明确问题和价值，再给结论、证据、边界，最后请大家判断下一步。

## 03. What is the research problem?

- Section: Research Problem
- Claim: Hardware trace is low-level; malware behavior claims are high-level.
- Notes: 问题不是能不能记录事件，而是能否把低层硬件事件连接到进程、可执行文件和行为标签，同时不把参考日志误报成硬件恢复结果。

## 04. Why is this worth studying?

- Section: Motivation
- Claim: Software logs are useful references, but they are part of the measured system.
- Notes: 价值要讲清楚：软件 tracing 不是没用，而是不适合单独承担对抗性 workload 的全部证据链；硬件 trace 提供独立观察点，但必须补上归因和边界。

## 05. What is the current core conclusion?

- Section: Current Conclusion
- Claim: RV-MalTrace supports controlled behavior reconstruction, not detector accuracy.
- Notes: 当前结论要一句话说完：在受控 RISC-V Linux workload 下，可以从 CVA6/Genesys2 trace 到 source-labeled reconstruction；不能声称真实 malware accuracy。

## 06. Which evidence supports the conclusion?

- Section: Evidence Map
- Claim: The evidence is useful only if each claim keeps its source and scope.
- Notes: 这页是周会的证据地图：不要先堆图，而是先告诉听众每类证据支持什么，不支持什么。

## 07. How does the evidence flow?

- Section: System Mechanism
- Claim: Trace records, code maps, runtime maps, and references stay separate.
- Notes: 实现页只服务证据逻辑：哪些字段来自硬件 trace，哪些来自 ELF/runtime map，哪些只是 reference log。

## 08. Evidence 1: trace correctness

- Section: Evidence Detail
- Claim: The trace contract is tested before semantic claims are made.
- Notes: 先证明 trace contract：事件顺序、trap/retire、syscall entry/return、drop accounting。不要直接跳到 malware behavior。

## 09. Evidence 2: source-labeled reconstruction

- Section: Evidence Detail
- Claim: Derived fields are marked as hardware, ELF, runtime map, or reference.
- Notes: 回答图表证明了什么：证明 reconstruction 没有把 reference log 当成 hardware output。

## 10. Evidence 3: code attribution

- Section: Evidence Detail
- Claim: ELF identity, symbols, syscall sites, and runtime maps constrain attribution.
- Notes: 说明本地 code attribution 支持哪些边界：PIE/ASLR、dynamic object、fork/exec、stripped binary；但不声称 board-native source-line attribution。

## 11. Evidence 4: board runs

- Section: Evidence Detail
- Claim: 122 accepted CVA6 windows support scoped empirical claims.
- Notes: 把 122 作为目前最强的 CVA6 empirical result，同时说明 4 failed retained、0 drops/wraps/gaps in accepted windows。

## 12. Evidence 5: controlled workloads

- Section: Evidence Detail
- Claim: The workload set checks behavior reconstruction, not real-world coverage.
- Notes: 明确 workload 的用法：controlled behavior coverage，而不是 in-the-wild malware benchmark。

## 13. Evidence 6: behavior checks

- Section: Evidence Detail
- Claim: Perfect scoped metrics validate reconstruction, not detector accuracy.
- Notes: 这页必须带红线：1.0/0.0 的指标不能被听众理解成检测器准确率。

## 14. What are the boundaries?

- Section: Boundary
- Claim: Unsupported topics stay as limitations or future work.
- Notes: 这页回答证据边界：real malware、production transport、cycle overhead、JTAG RAM boot 不能放进当前主结论。

## 15. What else could explain the result?

- Section: Alternative Explanations
- Claim: The current evidence rules out some failures, but not all external validity concerns.
- Notes: 博士周会要主动讲替代解释：是不是 software reference 帮太多？是不是 local fixture 不等于 board evidence？是不是 controlled workload 太窄？

## 16. What cost is measured?

- Section: Cost
- Claim: Resource and timing evidence support implementation cost, not runtime slowdown.
- Notes: 成本页保留，但必须说清楚：resource delta and timing closure，不是 cycle-level overhead。

## 17. What should the group help decide?

- Section: Next Step
- Claim: The next work is not more running; it is claim selection and one evidence gap.
- Notes: 最后必须给导师可判断的问题：主 claim 是否足够，是否补一个 board-native evidence，哪些 nonclaims 放 limitations。

## 18. The artifact package is reviewable

- Section: Reproducibility
- Claim: The paper should cite reproducible evidence, not untracked experiment memory.
- Notes: reproducibility 不再作为项目管理状态，而是作为证据可信度的一部分。

## 19. Paper narrative

- Section: Takeaway
- Claim: Problem -> conclusion -> evidence -> boundary -> decision.
- Notes: 收尾把六问串起来，不再停在“这周做了哪些事情”。

## 20. Streaming/DMA remains future work (Appendix)

- Section: Appendix
- Claim: Readiness and target profiles are not throughput evidence.
- Notes: target p99 0.0215755 B/cycle; required 0.0323633 B/cycle; at 50 MHz required 1.618 MB/s; current sustained=0, noninterference=false。

## 21. Workload roster (Appendix)

- Section: Appendix
- Claim: Sample names are appendix material, not main-story material.
- Notes: 列出 safe baseline、malware-behavior surrogates、benign controls。长样本名只放在附录，不进入主线叙事。

## 22. Resource detail (Appendix)

- Section: Appendix
- Claim: Resource/timing claim is supported; runtime overhead is not.
- Notes: baseline vs trace-enabled resource table。
