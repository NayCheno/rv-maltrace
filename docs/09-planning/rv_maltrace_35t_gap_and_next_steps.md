# RV-MalTrace 35T 当前差距分析与下一步计划

生成日期：2026-05-21
适用范围：Artix-7 35T / LiteX / VexRiscv 原型链路

---

## 0. 当前结论

35T/VexRiscv 当前阶段的主要 blocker 已从：

```text
full matrix 不能通过
process_chain 容量不足
stage2 / process attribution 仍需推进
```

更新为：

```text
35T-only optimized small-capacity full synthetic matrix 已通过。
下一步重点是结果固化、边界表述、回归保护和后续工程优化。
```

最新主证据：

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
triage: full_matrix_ready = True
blocked_reasons: none
```

当前仍然不是：

```text
真实恶意样本检测结果
CVA6 board validation
mature malware detector
完整 semantic reconstruction
```

---

## 1. 证据边界

### 1.1 已成立证据

| 项目 | 当前状态 | 说明 |
|---|---|---|
| 35T Linux / LiteX / VexRiscv 上板 | 已成立 | 已完成 board capture、analysis、report、gate、triage。 |
| trace profile / mask | 已成立 | `p0a_syscall_drop`、`p0c_syscall_trap_drop` 等 profile 可通过 runner 控制。 |
| marker-scoped gate | 已成立当前阶段 | 最新 full matrix 每个 trace-on rep marker 均 PASS。 |
| runtime process attribution | 已成立当前阶段 | 最新 full matrix 每个 trace-on rep runtime process map 均 PASS。 |
| strong/weak evidence gate | 已成立当前阶段 | strong evidence 按 stable matched expected 判定；weak evidence 仅报告。 |
| full synthetic matrix | 已通过 | 13/13 PASS，`full_matrix_ready: True`。 |
| process_chain | 已通过 | 小容量策略下 no cap hit、DROP 0、strong expected matched。 |
| benign overlap | 已处理 | `ls` 目录遍历触发 `many_file_scan` 作为 benign expected overlap，不算 unexpected strong。 |

### 1.2 未成立证据

| 项目 | 当前状态 | 说明 |
|---|---|---|
| CVA6 board claim | 未成立 | 当前范围限定为 35T/VexRiscv-only。 |
| real malware claim | 未成立 | 当前没有运行真实恶意样本。 |
| mature detector claim | 未成立 | 当前是 controlled synthetic behavior audit prototype。 |
| 大容量 trace ring 结论 | 非当前 blocker | 1024/BRAM 可继续优化，但不是当前 35T 小容量验收条件。 |
| malware family/IOC/TTP 输出 | 未建立 | 不应从 synthetic matrix 推导真实恶意软件分析能力。 |

---

## 2. 为什么不继续把“大容量”当 blocker

之前 p0c/r512 full matrix 的失败主要来自：

```text
process_chain + 全局 p0c_syscall_trap_drop
  -> 大量 kernel_or_loader_trap
  -> 512-record trace ring 被填满
  -> cap hit / DROP 高 / marker 和 runtime attribution gate 失败
```

这个失败说明：

```text
对所有样本使用同一个较重 profile 不适合 35T 小容量 full matrix。
```

它不说明：

```text
35T 必须扩大 trace ring 才能证明方法 work。
```

当前通过的优化是 per-sample minimal profile：

| 样本 | Profile | Control mask | 解释 |
|---|---|---:|---|
| `illegal_trap` | `p0c_syscall_trap_drop` | `0x42c` | 需要 TRAP 作为 illegal instruction strong evidence。 |
| 其他 12 个样本 | `p0a_syscall_drop` | `0x424` | 只需要 syscall entry/return、DROP、MARKER；TRAP 噪声不是必要证据。 |

这个策略更贴合 35T 低配置论证：

```text
在固定 512-record 预算内，用最小必要 trace 事件完成 synthetic matrix。
```

---

## 3. 最新 full matrix 结果

报告路径：

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
```

### 3.1 样本结论

| 样本 | Profile | Gate |
|---|---|---|
| `hello` | `p0a_syscall_drop` | PASS |
| `ls` | `p0a_syscall_drop` | PASS |
| `cat` | `p0a_syscall_drop` | PASS |
| `cp` | `p0a_syscall_drop` | PASS |
| `sha256sum` | `p0a_syscall_drop` | PASS |
| `file_scan` | `p0a_syscall_drop` | PASS |
| `batch_open_read_write` | `p0a_syscall_drop` | PASS |
| `self_copy_sim` | `p0a_syscall_drop` | PASS |
| `abnormal_syscall_sequence` | `p0a_syscall_drop` | PASS |
| `illegal_trap` | `p0c_syscall_trap_drop` | PASS |
| `process_chain` | `p0a_syscall_drop` | PASS |
| `dynamic_executable_memory` | `p0a_syscall_drop` | PASS |
| `anti_debug_like` | `p0a_syscall_drop` | PASS |

### 3.2 Gate 条件

| 条件 | 结果 |
|---|---|
| marker PASS every trace-on rep | PASS |
| runtime_process_map PASS every trace-on rep | PASS |
| UNKNOWN/corrupt == 0 | PASS |
| median DROP <= 5% | PASS |
| no cap hit | PASS |
| strong evidence matched | PASS |
| weak evidence 不计 strong | 保持 |

### 3.3 process_chain 容量结果

报告路径：

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
```

结果摘要：

```text
rep_00..rep_04: 154 events each
DROP: 0
DROP rate: 0.000000
cap: False
TRAP: 0
strong: True
```

结论：

```text
process_chain 不再阻断 35T-only full synthetic matrix。
```

---

## 4. 当前代码与工具状态

| 文件 | 当前作用 |
|---|---|
| `tools/experiment_35t.py` | 支持 `--trace-profile-policy 35t_small_capacity`，board 阶段按 profile 拆 runner 命令。 |
| `tools/check_35t_next_gate.py` | 支持 per-sample profile allowed events、marker/runtime gate、benign expected overlap。 |
| `tools/triage_35t_semantic_failures.py` | 支持 full matrix readiness 判定，输出 `optimized_35t_small_capacity_matrix_ready`。 |
| `tools/debug_process_chain_capacity.py` | 用于确认 process_chain cap/DROP/TRAP 结构。 |
| `src/rv_maltrace/trace_profiles.py` | 定义 `p0a_syscall_drop`、`p0c_syscall_trap_drop` 等 profile。 |

---

## 5. 下一步计划

### 5.1 P0：固化当前证据

目标：

```text
把 35T-only small-capacity full synthetic matrix 作为当前主线结果固定下来。
```

需要做：

```text
1. 在报告中引用 run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521。
2. 附 gate_report、semantic_failure_triage、process_chain_capacity_debug。
3. 明确写 trace_records=512，没有扩大容量。
4. 明确写 profile policy 是 small-capacity optimization，不是 full p0c everywhere。
```

### 5.2 P1：回归保护

目标：

```text
防止后续修改破坏 marker/runtime attribution/gate 规则。
```

建议保留或新增检查：

```powershell
uv run python tools/experiment_35t.py --stage self-test
uv run python tools/check_35t_next_gate.py --self-test
uv run python tools/triage_35t_semantic_failures.py --self-test
uv run python -m compileall tools src\rv_maltrace
```

### 5.3 P2：资源工程优化，不作为当前 blocker

BRAM-backed trace ring 仍有价值，但定位应调整为：

```text
engineering/resource-efficiency improvement
```

而不是：

```text
35T full synthetic matrix blocker
```

建议继续做：

```text
1. 同步 BRAM-backed trace ring。
2. 重新生成 512/1024 resource report。
3. 如果 1024 place 通过，只作为扩展容量证据，不覆盖 small-capacity result。
```

### 5.4 P3：提高解释质量

当前 matrix 已通过，但还可以增强：

```text
1. fd/path flow recovery。
2. process tree / parent-child evidence explanation。
3. source-line attribution。
4. 更清晰地区分 strong evidence、weak shape、benign expected overlap。
```

这些改进服务于解释和论文质量，不应改变当前 35T-only synthetic matrix 的通过结论。

---

## 6. 推荐写入论文/报告的当前表述

### 6.1 可以写

```text
We validated the current RV-MalTrace prototype on an Artix-7 35T LiteX/VexRiscv
board using controlled benign and synthetic malware-like workloads.

Instead of increasing trace capacity, we use a small-capacity profile policy that
emits only the events needed by each sample. Under a 512-record trace budget, the
13-sample synthetic matrix passes marker scope, runtime process attribution,
UNKNOWN/corrupt, DROP, capacity, and strong-evidence gates.
```

### 6.2 不应该写

```text
RV-MalTrace detects real malware.
The detector is mature.
The result validates CVA6.
The current synthetic matrix measures real malware detection accuracy.
The full matrix passed because trace capacity was increased.
```

### 6.3 推荐术语

| 不推荐 | 推荐 |
|---|---|
| malware detector | synthetic malware-like behavior audit prototype |
| real malware accuracy | controlled synthetic behavior-rule result |
| CVA6 board result | 35T/LiteX/VexRiscv board result |
| complete semantic reconstruction | preliminary trace-derived semantic recovery |
| capacity fix | small-capacity trace profile optimization |

---

## 7. 当前完成状态

| 工作项 | 状态 |
|---|---|
| Stage2 四样本 | 完成 |
| process_chain 单独风险验证 | 完成 |
| full matrix 用户确认后执行 | 完成 |
| 35T small-capacity optimized full matrix | 完成 |
| 文档更新 | 完成本文档后成立 |
| CVA6 验证 | 不在当前范围 |
| real malware workflow | 不在当前范围 |

---

## 8. 参考依据

```text
results/experiments/35t/35t-p0c-r512-stage2-process-attributed-20260521/aggregate/gate_report.md
results/experiments/35t/35t-p0a-r512-process-chain-process-attributed-20260521/aggregate/gate_report.md
results/experiments/35t/35t-p0c-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
tools/experiment_35t.py
tools/check_35t_next_gate.py
tools/triage_35t_semantic_failures.py
tools/debug_process_chain_capacity.py
src/rv_maltrace/trace_profiles.py
```
