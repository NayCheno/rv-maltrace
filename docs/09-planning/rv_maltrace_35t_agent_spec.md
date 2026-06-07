# RV-MalTrace 35T 应用闭环收口任务规格

> 适用对象：工程 / 论文 agent
> 适用范围：**Artix-7 35T / LiteX / VexRiscv**
> 明确排除：**CVA6**、真实恶意样本执行、真实 malware detection accuracy、mature detector claim

---

## 1. 当前判断

只判断 35T；CVA6 暂不纳入。

当前 35T 状态应被表述为：

> RV-MalTrace 已在 Artix-7 35T / LiteX / VexRiscv 上打通一个受控原型闭环：硬件 trace、runtime process attribution、本地 ELF/code-map 辅助分析、synthetic malware-like 行为规则审计。

当前 **不能** 表述为：

> RV-MalTrace 已完成真实 malware 分析系统、真实 malware detector、CVA6 board validation，或具备真实 malware detection accuracy 结果。

简化判断：

| 目标 | 35T 当前状态 | 判断 |
|---|---|---|
| 硬件 trace | 35T board capture / analysis / report / gate / triage 已形成证据链 | 已达成 35T 原型条件 |
| 本地代码分析 | 已有 code map、trace-code join、runtime process map 结合 | 部分达成，足够支撑原型审计；不是完整代码理解 |
| malware 分析 | 当前为 synthetic malware-like 样本和 rule-based audit | 未达成真实 malware 分析；已达成 synthetic behavior audit |

---

## 2. Agent 必须先核验的仓库证据

Agent 执行任务前，必须先检查这些文件和结果路径，不能只凭本文件下结论。

### 2.1 当前计划与主证据

检查：

```text
docs/09-planning/rv_maltrace_35t_gap_and_next_steps.md
```

必须确认并引用：

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
triage: full_matrix_ready = True
blocked_reasons: none
```

并确认当前 non-claims：

```text
不是 CVA6 board validation
不是真实恶意样本检测结果
不是 mature malware detector
不是完整 semantic reconstruction
```

### 2.2 35T 实验与 gate 工具

检查：

```text
tools/experiment_35t.py
tools/check_35t_next_gate.py
tools/triage_35t_semantic_failures.py
src/rv_maltrace/trace_profiles.py
```

必须确认：

- `35t_small_capacity` profile policy 存在；
- `illegal_trap` 使用 trap-capable profile；
- 其他 synthetic / benign 样本使用更轻量 syscall/drop/marker profile；
- gate 检查 marker scope、runtime process attribution、UNKNOWN/corrupt、DROP、cap hit、strong evidence；
- 报告中必须保留 non-claims：no CVA6 claim、no real malware detection claim、no mature detector claim。

### 2.3 本地代码分析工具

检查：

```text
tools/build_code_map.py
tools/join_trace_code_map.py
```

必须确认：

- code map schema 为 `rvmt.code_map.v1`；
- code map 包含 ELF、hash、load ranges、sections、symbols、syscall sites、trap sites；
- trace-code join 可结合 runtime process map；
- 当前 code-map attribution 有局限：PC-in-ELF 是静态代码区间证据，不等于完整 process ownership；强归属仍需要 marker scope、PID/SATP/ASID 或 runtime load-map 证据。

### 2.4 malware-like 样本边界

检查：

```text
experiments/linux_behavior/malware_like/manifest.json
experiments/linux_behavior/behavior_audit_rules.json
docs/04-runtime-linux/linux_behavior_audit.md
```

必须确认：

- 当前样本类别是 `malware_like_synthetic`；
- `real_malware: false`；
- 行为审计是 controlled synthetic behavior-rule audit；
- 不得声称真实 malware detection quality、classifier accuracy、family/IOC/TTP coverage。

---

## 3. 本次 agent 应完成的核心交付物

### P0：35T evidence bundle / result card

创建或更新一个结果固化文档，推荐路径：

```text
docs/08-publication/rv_maltrace_35t_application_closure.md
```

若仓库没有 `docs/08-publication/`，可以创建。若已有更合适结果目录，使用仓库现有规范，但必须在最终回答中说明实际路径。

文档必须包含以下章节：

```text
# RV-MalTrace 35T Application Closure Result Card

## Scope
## Current Claim Level
## Evidence Bundle
## Hardware Trace Result
## Local Code Analysis Support
## Synthetic Malware-like Behavior Audit Result
## Full Matrix Summary
## Case Study Index
## What This Proves
## What This Does Not Prove
## Regression Commands
## Remaining Work
## Recommended Paper Wording
```

### P0.1 Evidence Bundle 必填字段

必须写入：

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
full_matrix_ready: True
```

必须引用或列出这些结果路径：

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
```

### P0.2 Full Matrix Summary 必填表格

表格至少包含：

| Sample | Class | Profile | Gate | Strong Evidence | Notes |
|---|---|---|---|---|---|
| hello | benign | p0a_syscall_drop | PASS | yes | baseline |
| ls | benign | p0a_syscall_drop | PASS | yes | benign overlap must be explained |
| cat | benign | p0a_syscall_drop | PASS | yes | baseline |
| cp | benign | p0a_syscall_drop | PASS | yes | baseline |
| sha256sum | benign | p0a_syscall_drop | PASS | yes | baseline |
| file_scan | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |
| batch_open_read_write | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |
| self_copy_sim | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |
| abnormal_syscall_sequence | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |
| illegal_trap | malware_like_synthetic | p0c_syscall_trap_drop | PASS | yes | trap profile needed |
| process_chain | malware_like_synthetic | p0a_syscall_drop | PASS | yes | capacity risk resolved under 512 |
| dynamic_executable_memory | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |
| anti_debug_like | malware_like_synthetic | p0a_syscall_drop | PASS | yes | synthetic only |

Agent 必须从仓库结果中核验表格内容；若实际结果与上表不一致，以仓库结果为准，并在文档中写出差异。

---

## 4. P1：应用闭环回归保护

在 result card 中加入回归命令和状态。

### 4.1 已有 35T gate/self-test

必须运行或列为待运行：

```bash
uv run python tools/experiment_35t.py --stage self-test
uv run python tools/check_35t_next_gate.py --self-test
uv run python tools/triage_35t_semantic_failures.py --self-test
uv run python -m compileall tools src/rv_maltrace
```

### 4.2 应用闭环相关 self-test

必须检查是否存在这些工具；存在则运行，不存在则在文档中说明缺失：

```bash
uv run python tools/recover_behavior.py --self-test
uv run python tools/audit_behavior.py --self-test
uv run python tools/build_code_map.py --self-test
uv run python tools/join_trace_code_map.py --self-test
```

如果某个命令失败，agent 不得隐瞒。必须写入：

```text
command
status: PASS / FAIL / MISSING / NOT_RUN
reason
next action
```

---

## 5. P2：端到端 case studies

在 result card 中加入 `Case Study Index`，并创建或更新一个 case study 文档。推荐路径：

```text
docs/08-publication/rv_maltrace_35t_application_case_studies.md
```

若希望只维护一个文件，也可以把 case studies 放进 `rv_maltrace_35t_application_closure.md`，但结构必须清晰。

### 5.1 必选 case study

至少覆盖 3 个样本：

1. `illegal_trap`
   - 展示为什么需要 `p0c_syscall_trap_drop`；
   - 展示 trap evidence；
   - 明确这是 synthetic trap 行为，不是真实 malware exploit。

2. `process_chain`
   - 展示 runtime process attribution；
   - 展示 512 record 下 no cap hit / DROP 可控；
   - 说明 process_chain 不再是 35T blocker。

3. `dynamic_executable_memory`
   - 展示 `mmap` / `mprotect` / executable memory 相关行为审计；
   - 明确这是 synthetic malware-like behavior，不代表真实 malware detection。

建议增加第 4 个：

4. `file_scan` 或 `batch_open_read_write`
   - 用于展示 benign overlap 和 weak/strong evidence 边界；
   - 说明为什么不能把普通文件遍历直接解释成 malware。

### 5.2 每个 case study 的固定模板

每个 case study 必须包含：

```text
## Case Study: <sample_id>

### Goal
### Trace Profile
### Raw Trace Evidence
### Marker Scope Result
### Runtime Process Attribution
### Code Map / Trace-Code Join Evidence
### Recovered Behavior
### Audit Rule Hits
### Strong Evidence
### Weak Evidence / Benign Overlap
### What This Case Proves
### What This Case Does Not Prove
```

如果仓库结果中缺少某一项，不得补造；必须写：

```text
Not available in current evidence bundle.
Needed next: <具体下一步>
```

---

## 6. P3：解释质量增强 backlog

agent 不一定要在本轮全部实现，但 result card 必须列出下一步 backlog，并按优先级排序。

推荐优先级：

1. `fd/path flow recovery`
   - 目标：恢复 `openat/read/write/execve` 等 syscall 中 fd 与 path 的关系；
   - 价值：增强 file scan、batch read/write、self-copy 的解释质量。

2. `process tree explanation`
   - 目标：显式输出 fork/clone/exec/wait 的 parent-child 关系；
   - 价值：增强 process_chain 的应用展示。

3. `function/source-line attribution`
   - 目标：把 PC 归属从 ELF section/symbol 提升到 function 或 source line；
   - 价值：增强“本地代码分析”claim 的可信度。

4. `strong/weak/benign-overlap separation`
   - 目标：把 strong evidence、weak shape、benign expected overlap 分层展示；
   - 价值：避免把 benign 行为误写成 malware detection success。

---

## 7. 必须使用的 claim 边界

### 7.1 可以写

```text
We validated the current RV-MalTrace prototype on an Artix-7 35T LiteX/VexRiscv board using controlled benign and synthetic malware-like workloads.
```

```text
Under a 512-record trace budget, the 13-sample synthetic matrix passes marker scope, runtime process attribution, UNKNOWN/corrupt, DROP, capacity, and strong-evidence gates.
```

```text
The current 35T result demonstrates a hardware-trace-assisted synthetic behavior audit prototype, not a mature real-malware detector.
```

### 7.2 不得写

```text
RV-MalTrace detects real malware.
```

```text
The current result validates CVA6.
```

```text
The current synthetic matrix measures real malware detection accuracy.
```

```text
The full matrix passed because the trace capacity was increased.
```

```text
The system has complete semantic reconstruction.
```

---

## 8. 验收标准

本任务完成后，应满足以下条件：

- [ ] 新增或更新了 35T application closure result card。
- [ ] 文档中明确限定 scope：35T / LiteX / VexRiscv only。
- [ ] 文档中明确排除 CVA6、real malware claim、mature detector claim。
- [ ] 文档中引用 `35t-smallcap-r512-full-synthetic-matrix-20260521`。
- [ ] 文档中写明 `trace_records=512`，不得暗示靠 1024/BRAM 才通过。
- [ ] 文档中解释 `35t_small_capacity` profile policy。
- [ ] 文档中列出 13/13 PASS synthetic matrix。
- [ ] 文档中包含至少 3 个端到端 case studies，或明确说明 case study evidence 缺失项与下一步。
- [ ] 文档中包含应用闭环 regression commands 与执行状态。
- [ ] 若修改代码，必须运行相关 self-test 和 compileall。
- [ ] 最终回答中列出修改文件、运行命令、通过/失败状态、未完成项。

---

## 9. Agent 执行提示词

将下面提示词交给 coding / repo agent。

```text
你正在处理 NayCheno/rv-maltrace 仓库。请只处理 35T / LiteX / VexRiscv 当前阶段，不要开始 CVA6，不要声称真实 malware detection。

请先阅读并核验以下文件：
- docs/09-planning/rv_maltrace_35t_gap_and_next_steps.md
- tools/experiment_35t.py
- tools/check_35t_next_gate.py
- tools/triage_35t_semantic_failures.py
- src/rv_maltrace/trace_profiles.py
- tools/build_code_map.py
- tools/join_trace_code_map.py
- experiments/linux_behavior/malware_like/manifest.json
- experiments/linux_behavior/behavior_audit_rules.json
- docs/04-runtime-linux/linux_behavior_audit.md

然后按本任务规格完成 35T 应用闭环收口：
1. 创建或更新 docs/08-publication/rv_maltrace_35t_application_closure.md。
2. 必须写明当前 claim level：35T hardware-trace-assisted synthetic malware-like behavior audit prototype。
3. 必须引用 run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521，trace_records=512，trace_profile_policy=35t_small_capacity，13/13 PASS，full_matrix_ready=True。
4. 必须明确 non-claims：no CVA6 board claim, no real malware detection claim, no mature detector claim, no complete semantic reconstruction claim。
5. 创建或更新 docs/08-publication/rv_maltrace_35t_application_case_studies.md，至少覆盖 illegal_trap、process_chain、dynamic_executable_memory；建议增加 file_scan 或 batch_open_read_write。
6. 每个 case study 必须按模板写：Goal、Trace Profile、Raw Trace Evidence、Marker Scope、Runtime Process Attribution、Code Map / Trace-Code Join、Recovered Behavior、Audit Rule Hits、Strong Evidence、Weak Evidence / Benign Overlap、What This Proves、What This Does Not Prove。
7. 如果某项证据在仓库结果中不存在，不要编造，写 Not available in current evidence bundle，并给出具体 next action。
8. 在 result card 中加入 regression commands 与执行状态。优先运行：
   - uv run python tools/experiment_35t.py --stage self-test
   - uv run python tools/check_35t_next_gate.py --self-test
   - uv run python tools/triage_35t_semantic_failures.py --self-test
   - uv run python tools/recover_behavior.py --self-test
   - uv run python tools/audit_behavior.py --self-test
   - uv run python tools/build_code_map.py --self-test
   - uv run python tools/join_trace_code_map.py --self-test
   - uv run python -m compileall tools src/rv_maltrace
9. 如果命令失败或工具不存在，必须如实记录 FAIL/MISSING/NOT_RUN，不要隐藏。
10. 最终回复请给出：修改文件列表、关键结论、运行命令和状态、未完成项、是否满足 35T 应用闭环目标。

验收边界：
- 可以说：35T 上已完成 hardware trace + local code-map assisted analysis + synthetic malware-like behavior audit prototype。
- 不可以说：已完成真实 malware 分析系统、真实 malware detector、CVA6 validation、真实 malware accuracy。
```
