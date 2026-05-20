# RV-MalTrace 35T-Only 下一步严格可行计划

生成日期：2026-05-20
建议放置路径：`docs/planning/35t_next_strict_plan.md`

## 0. 计划边界

### 0.1 当前硬件边界

当前没有 CVA6 可用板卡，因此**所有上板测验均限定为 Artix-7 35T + LiteX/VexRiscv**。

本计划中：

- `BOARD` 只指 `artix7_35t_litex`。
- CVA6 不进入任何上板验收项。
- CVA6 只保留为后续迁移对象，可做文档、接口保持、仿真对照；不能写入 35T 上板 PASS 结论。
- 35T 结果只能支撑“低成本 VexRiscv 原型链路”和“合成行为审计实验”，不能支撑真实恶意软件检测结论。

### 0.2 现有结果基线

基线 run：`35t-full-20260520`
结果根目录：`results/experiments/35t/35t-full-20260520`
板卡串口：`COM5` / `921600` baud
重复次数：5
trace records per dump：256
样本矩阵：13 = 5 benign + 8 malware-like synthetic
网络样本：禁用
真实恶意软件：禁止

当前关键结果：

| 指标 | 当前值 |
| --- | ---: |
| 矩阵完成度 | 13/13 PASS |
| sample-level TP/FP/TN/FN | 1 / 3 / 2 / 7 |
| sample-level accuracy | 23.1% |
| sample-level precision | 25.0% |
| sample-level recall | 12.5% |
| rule-level TP/FP/TN/FN | 2 / 8 / 472 / 38 |
| rule-level precision | 20.0% |
| rule-level recall | 5.0% |
| median alignment precision | 12.5% |
| median alignment recall | 8.3% |
| median argument availability / accuracy | 39.6% |
| median trace-on/off runtime ratio | 0.882 |
| median trace events/sec | 1548.4 |
| median JSONL bytes/sec | 202166.0 |
| median DROP rate | 66.8% |
| worst DROP rate | 92.8%，`process_chain` |

结论：当前链路已经能跑通，但高 DROP 和低 alignment 说明它还不是成熟语义恢复结果。

## 1. 全局验收规则

每一步必须产生独立验收材料。没有验收材料，不允许把结果写成 PASS。

### 1.1 证据目录规则

35T 实验矩阵类结果放在：

```text
results/experiments/35t/<run-id>/
```

35T 板卡 bring-up / 单项板卡证据放在：

```text
results/board/artix7_35t_litex/<run-id>/
```

每个 run 至少包含：

```text
run_config.json
aggregate/metrics.json
aggregate/metrics.csv
aggregate/accuracy_report.md
aggregate/bandwidth_report.md
aggregate/overhead_report.md
aggregate/artifact_index.md
aggregate/gate_report.md
aggregate/gate_report.json
```

### 1.2 不允许升级的结论

在本计划完成前，不允许写：

- “CVA6 已经上板验证”。
- “真实恶意软件检测准确率”。
- “35T trace 没有扰动”。
- “compact trace 已经降低硬件带宽”。
- “syscall 语义恢复已经成熟”。

允许写：

- “35T/VexRiscv synthetic matrix 已完成”。
- “drop accounting 可观测”。
- “35T route 已跑通 ground truth、board trace、recovery、audit、alignment、aggregate report”。
- “当前瓶颈是 DROP、alignment 和审计规则”。

### 1.3 晋级规则

本计划区分两类标准：

| 类型 | 含义 |
| --- | --- |
| 步骤验收标准 | 判断该步骤是否完成，必须可检查。 |
| 晋级标准 | 判断是否允许进入更强 claim 或下一阶段全量实验。 |

如果步骤完成但未达到晋级标准，应记录为 `PASS-BLOCKED`，不能跳过问题。

## 2. 阶段 A：冻结当前 run，形成可引用基线

### A1. 固化 `35t-full-20260520` 结果

目的：把当前结果固定成“已完成但有限制”的基线，不再混入后续重跑结果。

执行：

```powershell
uv run python tools/check_35t_experiment_bundle.py --run-id 35t-full-20260520 --reps 5
```

需要归档：

```text
results/experiments/35t/35t-full-20260520/run_config.json
results/experiments/35t/35t-full-20260520/aggregate/current_results_summary.md
results/experiments/35t/35t-full-20260520/aggregate/metrics.json
results/experiments/35t/35t-full-20260520/aggregate/metrics.csv
results/experiments/35t/35t-full-20260520/aggregate/accuracy_report.md
results/experiments/35t/35t-full-20260520/aggregate/bandwidth_report.md
results/experiments/35t/35t-full-20260520/aggregate/overhead_report.md
```

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| bundle checker | 返回码为 0；若 CLI 参数形式不同，记录实际命令和返回码。 |
| aggregate 文件 | 上表文件全部存在。 |
| 结论边界 | summary 中明确写明“35T/VexRiscv only；no CVA6 board claim；no real malware claim”。 |
| 当前瓶颈 | summary 中列出 median DROP 66.8%、alignment recall 8.3%、sample recall 12.5%。 |

晋级标准：

- 允许作为后续对照基线。
- 不允许作为成熟检测结果。

## 3. 阶段 B：先加严格 profile，不直接扩大样本

当前 DROP 过高，下一步不能先扩大样本或上 CVA6。应先把 35T trace profile 分层。

### B1. 新增 35T trace profile 文档

新增文档：

```text
docs/board/artix7_35t_trace_profiles.md
```

至少定义以下 profile：

| Profile | 目的 | enable_syscall | enable_trap | enable_context | enable_drop | enable_branch | enable_retire | enable_jump | ARG_MEM |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `p0_syscall_trap_context` | correctness first | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `p1_branch_context` | 加入控制流片段 | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 |
| `p2_pointer_snapshot` | 指针语义实验 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | gated |

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| 文档存在 | `docs/board/artix7_35t_trace_profiles.md` 存在。 |
| profile 边界 | 明确禁止第一阶段 full retire、full jump、load/store stream。 |
| DROP 原则 | 明确 trace full 时 drop/account，不允许 core backpressure。 |
| CVA6 边界 | 明确 profile 是 35T/VexRiscv board profile，不修改 CVA6 signal map。 |

### B2. 给实验 runner 增加 `--trace-profile`

目标：`exp:35t` 可以记录并使用 profile，不再只靠隐含配置。

建议 CLI：

```powershell
uv run rvmt exp:35t --stage board --run-id 35t-profile-dryrun --dry-run --trace-profile p0_syscall_trap_context --sample hello --reps 1
```

如果暂时不改 CLI，则必须提供等价配置文件：

```text
configs/35t_trace_profiles.json
```

并在 `run_config.json` 中写入：

```json
{
  "trace_profile": "p0_syscall_trap_context",
  "trace_controls": {
    "enable_syscall": true,
    "enable_trap": true,
    "enable_context": true,
    "enable_drop": true,
    "enable_branch": false,
    "enable_retire": false,
    "enable_jump": false,
    "enable_arg_mem": false
  }
}
```

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| dry-run | dry-run 输出包含 selected profile、sample list、artifact root。 |
| run_config | 正式 run 的 `run_config.json` 包含 `trace_profile` 和 `trace_controls`。 |
| 事件限制 | 对 p0 run，`trace.jsonl` 中除 `DROP` 外只能出现 `SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`CSR`、`SATP`、`PRIV`。 |
| 失败处理 | 出现 `RETIRE`、`BRANCH`、`JUMP`、`ARG_MEM` 时，该 run 标记为 FAIL，不允许进入 full matrix。 |

晋级标准：

- p0 profile 可配置、可记录、可检查后，才能执行下一阶段 microbench。

## 4. 阶段 C：增强 gate/report，不先碰板子

目的：当前 aggregate 报告能看到总 TP/FP/FN，但不足以定位规则和 trace 失败。先增强工具，再重跑板子。

### C1. 新增 gate report

建议新增工具：

```text
tools/check_35t_next_gate.py
```

输入：

```text
results/experiments/35t/<run-id>/aggregate/metrics.json
results/experiments/35t/<run-id>/samples/**/status.json
results/experiments/35t/<run-id>/samples/**/behavior_audit/behavior_audit.json
results/experiments/35t/<run-id>/samples/**/alignment/alignment.json
```

输出：

```text
aggregate/gate_report.json
aggregate/gate_report.md
```

`gate_report` 至少包含：

| 字段 | 内容 |
| --- | --- |
| `sample_status` | 每个样本 trace-on/off、groundtruth、analyze 是否完成。 |
| `drop_summary` | 每个样本 median drop、drop rate、是否 capped at trace_records。 |
| `event_summary` | 每个样本各事件类型计数。 |
| `alignment_summary` | precision、recall、ordered_lcs、return_sign_match、argument_accuracy。 |
| `audit_rule_summary` | expected、matched、missing、unexpected matched。 |
| `claim_level` | `prototype_only` / `microbench_ready` / `full_matrix_ready`。 |

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| 当前 run 可解析 | 对 `35t-full-20260520` 运行工具无异常。 |
| gate JSON | `aggregate/gate_report.json` 存在且是合法 JSON。 |
| gate MD | `aggregate/gate_report.md` 存在并包含每个样本的 PASS/FAIL/BLOCKED。 |
| rule 细节 | 每个 malware-like sample 至少列出 expected/matched/missing。 |
| false positive 细节 | 每个 benign sample 至少列出 unexpected matched rules。 |

### C2. 扩展 bandwidth report

当前 bandwidth report 应增加：

- trace records cap 是否触顶。
- `captured_events == trace_records` 的样本列表。
- `drop / (drop + captured_events)`。
- 每类事件的占比。
- `DROP` 与 alignment recall 的关系。

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| cap 检测 | 当前 13 个样本应全部报告 `captured_events == 256`。 |
| worst case | 报告中明确列出 `process_chain` 是当前 worst DROP 样本。 |
| 结论 | 报告明确写明“当前 bandwidth 不足以支撑成熟语义恢复”。 |

## 5. 阶段 D：p0 microbench correctness，不跑全矩阵

目的：先证明最小事件语义，不被 full matrix 和 branch 流量淹没。

### D1. p0 microbench run

建议 run id：

```text
35t-p0-micro-<date>
```

样本选择：

| 样本 | 目的 |
| --- | --- |
| `hello` | 最小 syscall/write 路径。 |
| `batch_open_read_write` | open/read/write/close 顺序。 |
| `illegal_trap` | trap/cause/context。 |
| `anti_debug_like` | ptrace/timing-like syscall shape。 |

命令：

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-p0-micro-<date> --port COM5 --baud 921600 --reps 5 --trace-records 1024 --trace-profile p0_syscall_trap_context --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0-micro-<date> --reps 5
uv run python tools/check_35t_next_gate.py --run-id 35t-p0-micro-<date>
```

如果 `--trace-profile` 尚未实现，不能执行该阶段；先回到 B2。

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| matrix 完成 | 4/4 样本 PASS，每个样本 5 次 trace-on/off。 |
| groundtruth | 每个样本存在 host_native、host_strace、qemu_native、qemu_strace。 |
| trace 文件 | 每个 trace-on rep 存在 `trace.jsonl`。 |
| 事件集合 | p0 禁止事件为 0：无 `RETIRE`、`BRANCH`、`JUMP`、`ARG_MEM`。 |
| syscall entry | `hello`、`batch_open_read_write`、`anti_debug_like` 至少出现 `SYSCALL_ENTRY`。 |
| trap | `illegal_trap` 至少出现 `TRAP`。 |
| DROP 可解释 | 每个 rep 的 `drop` 字段存在；不存在“无 drop 字段”的 trace。 |
| gate report | `aggregate/gate_report.md/json` 存在。 |

晋级标准：

| 指标 | 进入 D2 的最低要求 |
| --- | ---: |
| `hello` median DROP rate | <= 5% |
| `illegal_trap` median DROP rate | <= 5% |
| `batch_open_read_write` median DROP rate | <= 15% |
| `anti_debug_like` median DROP rate | <= 15% |
| alignment recall on `hello` | >= 50% |
| alignment recall on `batch_open_read_write` | >= 40% |
| illegal trap expected matched | true |

如果步骤验收 PASS 但晋级标准 FAIL，记录为：

```text
PASS-BLOCKED: p0 microbench artifacts complete, but semantic/drop gate failed.
```

然后进入阶段 E 的容量/过滤 sweep，不允许跑 full matrix。

## 6. 阶段 E：trace capacity 与 event filtering sweep

目的：找到 35T 上可承受的最小 trace 配置。这里不是为了“必然通过”，而是为了形成严格决策表。

### E1. records sweep

固定 profile：`p0_syscall_trap_context`
固定样本：D1 四个 microbench
固定 reps：3 或 5；建议 3 用于快速 sweep，最终候选用 5 复验。

命令：

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-p0-r256-<date>  --port COM5 --baud 921600 --reps 3 --trace-records 256  --trace-profile p0_syscall_trap_context --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
uv run rvmt exp:35t --stage all --run-id 35t-p0-r512-<date>  --port COM5 --baud 921600 --reps 3 --trace-records 512  --trace-profile p0_syscall_trap_context --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
uv run rvmt exp:35t --stage all --run-id 35t-p0-r1024-<date> --port COM5 --baud 921600 --reps 3 --trace-records 1024 --trace-profile p0_syscall_trap_context --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
uv run rvmt exp:35t --stage all --run-id 35t-p0-r2048-<date> --port COM5 --baud 921600 --reps 3 --trace-records 2048 --trace-profile p0_syscall_trap_context --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
```

每个 run 后：

```powershell
uv run python tools/check_35t_next_gate.py --run-id <run-id>
```

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| sweep 完整 | 至少完成 256、512、1024 三档；2048 若资源或时间失败，记录失败原因。 |
| 每档有 gate report | 每个 run 都有 `aggregate/gate_report.md/json`。 |
| cap 曲线 | 报告中列出每档 `captured_events == trace_records` 的样本数。 |
| DROP 曲线 | 报告中列出每档 median drop rate 和 worst drop rate。 |
| 资源状态 | 若更大 records 需要重新 bitstream，必须记录 Vivado utilization/timing。 |

候选选择标准：

选择满足以下条件的最小 records 配置：

| 指标 | 候选标准 |
| --- | ---: |
| `hello` median DROP rate | <= 5% |
| `illegal_trap` median DROP rate | <= 5% |
| D1 四样本整体 median DROP rate | <= 15% |
| p0 forbidden events | 0 |
| bitstream timing | WNS >= 0 或文档解释为非最终 timing blocked |
| board 稳定性 | 3 reps 无串口解析失败、无 Linux boot failure |

如果 2048 仍不满足，则结论不是继续扩大样本，而是：

```text
35T p0 capacity insufficient under current export/ring design.
Next action: reduce emitted events further or redesign export/ring before full matrix.
```

### E2. p0-subprofile sweep

如果 E1 不满足，继续减少事件：

| Subprofile | enable_syscall | enable_trap | enable_context | enable_drop | 目的 |
| --- | ---: | ---: | ---: | ---: | --- |
| `p0a_syscall_drop` | 1 | 0 | 0 | 1 | 只看 syscall entry/ret 与 DROP。 |
| `p0b_trap_drop` | 0 | 1 | 0 | 1 | 只看 trap。 |
| `p0c_syscall_trap_drop` | 1 | 1 | 0 | 1 | 去掉 context 流量。 |

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| subprofile 记录 | `run_config.json` 记录具体 subprofile。 |
| 事件集合 | 只出现 subprofile 允许事件和 DROP。 |
| 结论 | 明确指出是哪类事件导致 DROP 上升。 |

晋级标准：

- 至少一个 subprofile 在 `hello`、`batch_open_read_write`、`illegal_trap` 上达到 median DROP <= 5%。
- 如果没有任何 subprofile 达标，停止 full matrix，优先改 ring/export。

## 7. 阶段 F：修复 alignment 与语义恢复输出

目的：当前 alignment recall 只有 8.3%，必须先提升语义层可解释性。

### F1. 扩展 `semantic_events.json`

`recover_behavior.py` 的 syscall 输出应至少包含：

```json
{
  "seq": 12,
  "name": "openat",
  "nr": 56,
  "entry_pc": "0x...",
  "return_pc": "0x...",
  "args": {
    "a0": "0x...",
    "a1": "0x...",
    "a2": "0x...",
    "a3": "0x...",
    "a4": "0x...",
    "a5": "0x...",
    "a6": "0x...",
    "a7": "0x..."
  },
  "return_value": "0x...",
  "duration": 123,
  "drop_before": 0,
  "drop_after": 0,
  "confidence": "paired_entry_return"
}
```

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| schema | `semantic_events.json` 中 syscall event 至少包含 `nr/name/args/return_value/duration/confidence`，缺失时写 `null`，不能省略字段。 |
| pairing | 已配对 entry/return 标记为 `paired_entry_return`。 |
| unpaired | 未配对 syscall 标记为 `entry_only` 或 `return_only`，不能静默丢弃。 |
| drop context | 每条 syscall 附近记录 drop snapshot 或 drop interval。 |

### F2. 扩展 alignment 层级

`alignment.json` 应拆成三层：

| 层级 | 指标 |
| --- | --- |
| family set | syscall family precision/recall。 |
| ordered sequence | LCS、edit distance、ordered recall。 |
| paired semantics | return sign、return value、arg availability、fd transition。 |

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| family set | 保留当前 precision/recall。 |
| ordered | 增加 `ordered_lcs`、`ordered_lcs_ratio`。 |
| paired | 增加 `paired_return_ratio`、`return_sign_match_ratio`。 |
| drop-aware | alignment report 中显示该样本 drop rate，避免把 DROP 造成的缺失误判为规则错误。 |

晋级标准：

- 在 D/E 选出的候选 p0 run 上，`hello` ordered_lcs_ratio >= 0.5。
- `illegal_trap` trap target/cause 可在 semantic report 中定位。

## 8. 阶段 G：重写行为审计规则，先降低 false positive

目的：当前 benign false positive 是主要论文风险。先基于已有 trace 和 semantic artifacts 做 offline rule 修复，不必每次上板。

### G1. 增加 per-rule regression fixtures

新增或扩展：

```text
experiments/linux_behavior/behavior_audit_rules.json
experiments/linux_behavior/rule_regression_fixtures/
```

每条规则至少有：

```text
positive fixture
negative benign fixture
edge-case fixture
```

重点规则：

| 规则 | 当前风险 | 修复方向 |
| --- | --- | --- |
| `batch_file_read_write` | `cat` / `cp` 易误报 | 增加文件数量、路径变化、staging 行为条件。 |
| `self_copy_simulation` | 普通 read/write 易误报 | 要求 self path、executable path 或源/目标关系证据。 |
| `many_file_scan` | 普通 `ls` 风险 | 要求 getdents/openat 多次组合，而不是单个目录行为。 |
| `anti_analysis_indicator` | timing syscall 过宽 | 区分 ptrace 类与普通时间读取。 |
| `dynamic_executable_memory` | 单点 mmap 不足 | 要求 mmap + mprotect(PROT_EXEC) 顺序。 |

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| fixture | 每条规则至少 1 个 positive、1 个 negative。 |
| self-test | `uv run python tools/audit_behavior.py --self-test` 返回 0。 |
| rule report | `behavior_audit_report.md` 输出 matched/missing/unexpected。 |
| benign negative | fixtures 中 benign negative 不触发 malware-like rule。 |

### G2. 用当前 run 离线重分析

不重跑板子，只重新跑 analyze/report：

```powershell
uv run rvmt exp:35t --stage analyze --run-id 35t-full-20260520 --reps 5
uv run rvmt exp:35t --stage report  --run-id 35t-full-20260520 --reps 5
uv run python tools/check_35t_next_gate.py --run-id 35t-full-20260520
```

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| 离线重分析 | 不访问板子即可完成 analyze/report。 |
| FP 定位 | gate report 明确列出 `cat`、`cp`、`sha256sum` 是否仍有 unexpected matched rules。 |
| FN 定位 | gate report 明确列出 7 个 FN 的 missing rules。 |

晋级标准：

| 指标 | 进入 full matrix rerun 的目标 |
| --- | ---: |
| benign false positives | <= 1/5 |
| malware-like expected matched | >= 3/8，在 DROP 未改善前可作为弱目标 |
| rule-level precision | >= 40% |
| rule-level recall | >= 20% |

如果没有达到，不跑 full matrix；继续修规则或修 trace 语义。

## 9. 阶段 H：严谨 runtime methodology

目的：当前 trace-on/off ratio < 1，不能解释为 trace 加速。下一步必须固定测量协议。

### H1. 修改 runner 的测量顺序

新增配置：

```text
--runtime-order abba
--warmup 1
--reps 10
```

推荐顺序：

```text
warmup trace-off, warmup trace-on
rep0: trace-off
rep0: trace-on
rep1: trace-on
rep1: trace-off
repeat ABBA
```

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| run_config | 记录 `runtime_order=abba`、`warmup=1`、`reps=10`。 |
| timing JSONL | 每条 timing 记录 mode、rep、order_index、warmup 标记。 |
| dump 隔离 | workload runtime 与 trace dump time 分开记录。 |
| 报告 | overhead report 输出 median、min、max、spread，建议增加 IQR。 |
| 结论 | 若 ratio < 1，只写 measured ratio，不写 acceleration。 |

晋级标准：

- 至少在 microbench 候选 profile 上完成 reps=10 的 ABBA run。
- 所有样本 trace-on/off 都有相同 rep 数。

## 10. 阶段 I：35T resource/timing 报告

目的：35T 的价值之一是低成本 FPGA 原型；必须补 35T 自己的资源/时序表。

### I1. 新增 35T resource report

新增：

```text
docs/reports/artix7_35t_resource_report.md
```

至少包含：

| 配置 | LUT | FF | BRAM18 equiv | DSP | WNS | Fmax/clock target | trace_records | profile |
| --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | --- |
| baseline LiteX/VexRiscv | TBD | TBD | TBD | TBD | TBD | TBD | 0 | no-trace |
| p0 trace 256 | TBD | TBD | TBD | TBD | TBD | TBD | 256 | p0 |
| p0 trace 512 | TBD | TBD | TBD | TBD | TBD | TBD | 512 | p0 |
| p0 trace 1024 | TBD | TBD | TBD | TBD | TBD | TBD | 1024 | p0 |
| p0 trace 2048 | TBD | TBD | TBD | TBD | TBD | TBD | 2048 | p0 |

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| baseline | 至少有 no-trace LiteX/VexRiscv utilization/timing。 |
| trace configs | 至少有一个 trace-enabled config utilization/timing。 |
| delta | 报告 absolute delta 和 percentage delta。 |
| timing | WNS、clock target、是否 routed 全部记录。 |
| blocked 记录 | 如果某档无法实现或 timing fail，写入 FAIL/BLOCKED 原因。 |

晋级标准：

- 选中的 full matrix 配置必须有 resource/timing 数据。
- 没有 resource/timing 时，不能写硬件成本结论。

## 11. 阶段 J：候选 profile 的 full matrix rerun

只有当 D/E/F/G/H/I 的核心门槛达成后，才跑全矩阵。

### J1. full matrix run

建议 run id：

```text
35t-p0-full-<date>
```

命令：

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-p0-full-<date> --port COM5 --baud 921600 --reps 10 --duration 3600 --trace-records <selected-records> --trace-profile <selected-profile>
uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0-full-<date> --reps 10
uv run python tools/check_35t_next_gate.py --run-id 35t-p0-full-<date>
```

步骤验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| matrix 完成 | 13/13 样本 PASS。 |
| reps | 每样本 trace-on/off 都是 10 reps，warmup 不计入统计。 |
| groundtruth | 每样本四个 required baselines 都存在。 |
| trace profile | `run_config.json` 记录 selected profile 和 controls。 |
| aggregate | metrics、accuracy、bandwidth、overhead、gate report 全部存在。 |
| no network/real malware | run_config 明确记录 network disabled、real malware forbidden。 |

研究晋级标准：

| 指标 | 目标 |
| --- | ---: |
| median DROP rate | <= 15% |
| worst DROP rate | <= 40%，`process_chain` 可单独解释但必须记录。 |
| median alignment recall | >= 30% |
| benign false positives | <= 1/5 |
| malware-like expected matched | >= 4/8 |
| sample-level precision | >= 60% |
| sample-level recall | >= 50% |
| illegal_trap expected matched | true |
| dynamic_executable_memory expected matched | true，若 ARG_MEM 未启用可标注 partial。 |
| anti_debug_like expected matched | true 或明确说明 trace 缺失位置。 |

如果步骤验收 PASS 但研究晋级标准 FAIL，报告结论写：

```text
35T full matrix completed, but semantic/audit promotion gate failed.
```

不能写 mature detector。

## 12. 阶段 K：case study 与论文可用材料

只有 J1 达成至少部分研究晋级标准后，才写 case study。

### K1. 选择 3 个 case study

建议：

| Case | 目的 |
| --- | --- |
| `illegal_trap` | trap/context correctness，当前唯一已匹配 expected behavior 的样本。 |
| `anti_debug_like` | evasion-resistance 方向，但必须避免 detection claim。 |
| `dynamic_executable_memory` | mmap/mprotect 行为图，适合作为语义恢复案例。 |

每个 case 输出：

```text
results/experiments/35t/<run-id>/case_studies/<sample-id>/case_study.md
results/experiments/35t/<run-id>/case_studies/<sample-id>/trace_excerpt.jsonl
results/experiments/35t/<run-id>/case_studies/<sample-id>/semantic_excerpt.json
results/experiments/35t/<run-id>/case_studies/<sample-id>/behavior_graph_excerpt.json
```

验收标准：

| 检查项 | PASS 条件 |
| --- | --- |
| trace reference | case study 引用具体 trace record / syscall seq。 |
| semantic reference | 引用 semantic event 和 behavior graph。 |
| limitation | 写明 DROP rate、alignment recall、是否缺失 pointer semantics。 |
| no overclaim | 不出现真实恶意软件检测、CVA6 上板、泛化准确率结论。 |

## 13. CVA6 后续规则

当前没有 CVA6 板子，因此 CVA6 只做以下工作：

| 工作 | 允许吗 | 验收标准 |
| --- | --- | --- |
| CVA6 signal map 文档维护 | 允许 | 不为了 VexRiscv 弱化 CVA6 语义。 |
| CVA6 仿真 smoke | 允许 | 只标记为 simulation evidence。 |
| CVA6 board result | 不允许 | 没有板卡时不能出现 PASS。 |
| 把 35T 结果写成 CVA6 结果 | 不允许 | 任何文档中出现即 FAIL。 |
| CVA6 migration plan | 允许 | 明确依赖未来板卡或更大 FPGA。 |

CVA6 启动条件：

1. 有可用 CVA6 目标板或等价资源级 FPGA。
2. 35T p0/p1 语义链路已经稳定。
3. 35T 的 JSONL、recovery、audit、gate report 工具已经成熟。
4. CVA6 board evidence 目录与 35T evidence 目录完全分开。

## 14. 推荐执行顺序

| 顺序 | 阶段 | 是否需要上板 | 预计输出 |
| ---: | --- | --- | --- |
| 1 | A：冻结当前 run | 否 | current baseline summary。 |
| 2 | B：trace profiles | 否/少量 smoke | profile 文档、run_config controls。 |
| 3 | C：gate/report | 否 | gate_report.md/json。 |
| 4 | D：p0 microbench | 是 | 4-sample correctness evidence。 |
| 5 | E：capacity/filter sweep | 是 | records/drop/resource 决策表。 |
| 6 | F：alignment/recovery | 否 | enriched semantic/alignment schema。 |
| 7 | G：audit rules | 否 | rule fixtures、FP/FN 明细。 |
| 8 | H：runtime methodology | 是 | ABBA reps=10 overhead evidence。 |
| 9 | I：35T resource/timing | 否/综合 build | 35T resource report。 |
| 10 | J：full matrix rerun | 是 | 13-sample p0/p1 full matrix。 |
| 11 | K：case studies | 否 | 论文材料。 |

## 15. 下一次可立即执行的最小任务清单

无需等新板子，立即做：

```text
1. 新增 docs/board/artix7_35t_trace_profiles.md。
2. 新增或扩展 runner，使 run_config.json 记录 trace_profile 和 trace_controls。
3. 新增 tools/check_35t_next_gate.py。
4. 用 35t-full-20260520 离线生成 gate_report.md/json。
5. 修 audit report，输出 expected/matched/missing/unexpected rules。
6. 准备 p0 microbench run，不直接跑全矩阵。
```

第一轮目标不是提高准确率，而是把失败原因分成三类：

```text
trace capacity problem
semantic recovery problem
audit rule problem
```

只有这三类问题被区分清楚后，下一轮 35T 上板数据才有论文价值。
