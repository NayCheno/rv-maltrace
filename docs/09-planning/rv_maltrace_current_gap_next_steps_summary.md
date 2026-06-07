# RV-MalTrace 当前状态与下一步路线总结

生成日期：2026-05-21
仓库：`NayCheno/rv-maltrace`
适用范围：Artix-7 35T / LiteX / VexRiscv / synthetic malware-like behavior audit

---

## 0. 一句话结论

当前 35T/VexRiscv-only 路线已经从四样本 process-attributed microbench 推进到：

```text
35T-only optimized small-capacity full synthetic matrix ready
```

最新通过的 run：

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate result: 13/13 PASS
triage: full_matrix_ready = True
blocked_reasons = none
```

这说明在 35T 小容量/低配置资源约束下，不需要把 trace ring 容量作为当前验收 blocker。更合适的路线是按样本启用最小必要事件，减少无关事件流量：

```text
默认: p0a_syscall_drop
仅 illegal_trap: p0c_syscall_trap_drop
```

当前可以写：

```text
On Artix-7 35T / LiteX / VexRiscv, RV-MalTrace completes a process-attributed,
marker-scoped, synthetic behavior audit matrix under a 512-record trace budget
using a small-capacity optimized profile policy.
```

当前仍不能写：

```text
real malware detection has been validated.
CVA6 board validation is complete.
semantic recovery is mature.
RV-MalTrace is a mature malware detector.
```

---

## 1. 当前已经完成的能力

| 能力 | 当前状态 | 证据 |
|---|---|---|
| 35T 板级 trace acquisition | 已完成当前阶段 | 35T / LiteX / VexRiscv 可稳定采集 syscall/trap/drop/marker trace。 |
| process-attributed gate | 已完成当前阶段 | marker scope 和 runtime process map 每个 trace-on rep 均 PASS。 |
| Stage2 四样本 | 已通过 | `file_scan`、`self_copy_sim`、`abnormal_syscall_sequence`、`dynamic_executable_memory` 通过 gate。 |
| process_chain | 已通过 | 小容量策略下 `process_chain` drop 0、cap false、strong expected matched。 |
| 35T full synthetic matrix | 已通过 | `35t-smallcap-r512-full-synthetic-matrix-20260521`，13/13 PASS。 |
| UNKNOWN/corrupt gate | 已通过 | 最新 full matrix 所有样本 `UNKNOWN/corrupt == 0/0`。 |
| trace capacity gate | 已通过当前阶段 | 最新 full matrix 无 cap hit，median DROP 均 <= 5%。 |
| benign overlap 处理 | 已更新 | `ls` 的 `directory_listing -> many_file_scan` 作为 benign expected overlap，不算 unexpected strong。 |

---

## 2. 小容量优化策略

此前 p0c/r512 full matrix 的主要 blocker 是：

```text
process_chain 在 p0c_syscall_trap_drop 下被 kernel_or_loader_trap 噪声填满 512-record ring，
导致 cap hit、DROP 高、marker/runtime gate 失败。
```

这不是 FPGA 不能工作的结论，也不是必须扩大容量的结论。它说明 full matrix 不应该对所有样本启用同一高事件量 profile。

当前采用的优化策略：

| 样本集合 | Profile | Control mask | 原因 |
|---|---|---:|---|
| 除 `illegal_trap` 外所有样本 | `p0a_syscall_drop` | `0x424` | 这些规则主要需要 syscall entry/return、DROP、MARKER；不需要 TRAP。 |
| `illegal_trap` | `p0c_syscall_trap_drop` | `0x42c` | 该样本必须保留 TRAP 事件以证明 illegal instruction trap。 |

对应 board runner dry-run 命令形态：

```text
/usr/bin/rvmt_exp_runner 0xf0004000 512 5 abba --control-mask 0x424 --warmup 0 \
  hello ls cat cp sha256sum file_scan batch_open_read_write self_copy_sim \
  abnormal_syscall_sequence process_chain dynamic_executable_memory anti_debug_like

/usr/bin/rvmt_exp_runner 0xf0004000 512 5 abba --control-mask 0x42c --warmup 0 \
  illegal_trap
```

这一路线没有增加 trace capacity，没有切换到 CVA6，也没有引入真实恶意样本。

---

## 3. 最新 gate 结论

报告路径：

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
```

### 3.1 Full matrix

| 项目 | 结果 |
|---|---|
| Samples | 13 |
| PASS | 13 |
| FAIL/BLOCKED | 0 |
| Claim level | `full_matrix_ready` |
| Triage readiness | `full_matrix_ready: True` |
| Blocked reasons | none |

### 3.2 Gate 条件

| Gate 条件 | 最新结果 |
|---|---|
| marker PASS every trace-on rep | PASS，所有样本 5/5 |
| runtime_process_map PASS every trace-on rep | PASS，所有样本 5/5 |
| UNKNOWN/corrupt == 0 | PASS，所有样本 0/0 |
| median DROP <= 5% | PASS，`illegal_trap` 约 3.07%，其余 0% |
| no cap hit | PASS，所有样本 none |
| strong evidence | PASS，期望规则均 stable strong matched |
| weak evidence | 仅报告，不作为 strong 替代 |

### 3.3 process_chain

`process_chain` 在小容量策略下的容量结果：

| Rep | Events | DROP | DROP rate | Cap | Strong |
|---|---:|---:|---:|---|---|
| rep_00..rep_04 | 154 each | 0 | 0.000000 | False | True |

结论：

```text
process_chain 不再是当前 35T-only full synthetic matrix 的 capacity blocker。
```

---

## 4. 已执行命令摘要

```powershell
uv run python tools/experiment_35t.py --stage groundtruth --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order abba --warmup 0

uv run python tools/experiment_35t.py --stage board --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order abba --warmup 0

uv run python tools/experiment_35t.py --stage analyze --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order abba --warmup 0

uv run python tools/experiment_35t.py --stage report --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --trace-profile-policy 35t_small_capacity --runtime-order abba --warmup 0

uv run python tools/check_35t_experiment_bundle.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --reps 5
uv run python tools/check_35t_next_gate.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521 --reps 5
uv run python tools/triage_35t_semantic_failures.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521
uv run python tools/debug_process_chain_capacity.py --run-id 35t-smallcap-r512-full-synthetic-matrix-20260521
```

结果：

```text
experiment bundle: PASS
next gate: PASS
semantic triage: PASS, no BLOCKED output
process_chain capacity debug: PASS
```

---

## 5. 当前仍未成立的能力

| 能力 | 当前状态 | 说明 |
|---|---|---|
| CVA6 board validation | 未声明 | 当前验收范围明确限定为 35T/VexRiscv-only。 |
| real malware execution | 未做 | 当前样本全部是 synthetic malware-like / benign workload。 |
| mature detector claim | 未成立 | 当前是 controlled synthetic behavior audit prototype。 |
| malware family / IOC 分析 | 未建立 | 尚未输出 family、TTP、IOC 或真实样本检测准确率。 |
| 大容量 trace ring | 非当前 blocker | BRAM-backed ring 可作为工程优化，但不是当前 35T 小容量论证的验收条件。 |

---

## 6. 下一步路线

### 6.1 立即做

```text
1. 固化 35t_small_capacity full matrix 结果到报告/论文草稿。
2. 把 35T-only / VexRiscv-only / synthetic-only 边界写清楚。
3. 为最新 run 保留 gate_report、semantic_failure_triage、process_chain_capacity_debug 作为主证据。
4. 增加或保留回归测试，防止 marker/runtime attribution/gate 退化。
```

### 6.2 可以并行做

```text
1. BRAM-backed trace ring 工程优化。
2. 重新生成 512/1024 resource report，作为资源效率补充，而不是当前 blocker。
3. 扩展更多 synthetic 行为前，先保持 no real malware/no mature detector claim。
4. 改善 fd/path/process-tree 细节，用于提高解释质量。
```

### 6.3 暂时不要做

```text
1. 不要把当前结果扩写成真实恶意样本检测。
2. 不要把 35T/VexRiscv 结果扩写成 CVA6 board validation。
3. 不要声称 semantic recovery 已成熟。
4. 不要把 p0c 全局 profile 说成 full matrix 最优策略；当前通过的是 per-sample small-capacity policy。
```

---

## 7. 推荐写入论文/报告的表述

### 可以写

```text
We evaluate RV-MalTrace on an Artix-7 35T LiteX/VexRiscv board using controlled
benign and synthetic malware-like workloads.

Under a 512-record trace budget, a small-capacity profile policy completes the
13-sample synthetic matrix with marker-scoped and runtime process-attributed
evidence.

The full matrix run reports 13/13 PASS, zero UNKNOWN/corrupt records, no trace
capacity cap hit, and median DROP below 5% for every sample.
```

### 不应写

```text
RV-MalTrace detects real malware.
The semantic detector is mature.
The 35T result validates CVA6 behavior.
The current synthetic audit accuracy is real malware detection accuracy.
```

---

## 8. 参考路径

```text
tools/experiment_35t.py
tools/check_35t_next_gate.py
tools/triage_35t_semantic_failures.py
tools/debug_process_chain_capacity.py
src/rv_maltrace/trace_profiles.py
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
```
