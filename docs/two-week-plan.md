# RV-MalTrace 两周推进计划

## 结论

两周内不要把 5 个方向并列推进。建议收敛成一个主线：

> 完成“软件模拟可验证的 RISC-V/CVA6 malware behavior tracing MVP”，输出 `trace -> semantic recovery -> evaluation gate` 的完整证据链。

5 个方向的两周内定位如下：

| 原方向 | 两周内定位 | 处理方式 |
| --- | --- | --- |
| 硬件 malware 分析模块 RISC-V | 主线 | 做 committed syscall/control-flow/trap/context trace + 简单语义恢复 |
| RISC-V fuzzing | 验证手段 | 用 directed/random 程序压力测试 trace，不先做独立 fuzzing 论文 |
| 改进软核性能/能力 | 暂不作为主贡献 | 只保证 trace sideband、不反压 core、记录资源/Fmax/drop |
| 更轻便的分析手段 | 论文潜力点 | 做 compact event + filter + syscall semantic recovery |
| x86 -> RV malware instruction 不一样 | 动机与实验设计 | 不比较 raw instruction，比较行为语义、syscall、规避方式迁移 |

本计划没有重新跑 Vivado；判断基于仓库文档和代码审阅。

## 当前仓库状态判断

仓库已经超过空雏形：已有 commit-level trace MVP、事件格式、RTL/工具链和部分 CVA6 仿真 PASS。主要缺口在完整 SoC、Linux/board 证据、语义恢复与 fuzzing 接入。

- README 已把项目定位为 CVA6/RISC-V hardware-assisted behavior tracing，核心目标是 committed-event trace MVP、JSONL golden comparison，并明确 board/Linux claims 要放在 evidence gates 后面。
- Trace event schema 已覆盖 `RETIRE`、`BRANCH`、`JUMP`、`SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`CSR`、`SATP`、`PRIV`、`ARG_MEM`、`DROP`、`MARKER`。
- CVA6 信号映射已经走 RVFI/commit/trap/CSR/writeback 路径，包括 `commit_pc`、`commit_instr`、`trap_cause`、`priv_lvl`、`satp`、`a0-a7 shadow` 等关键 attachment points。
- 仿真结果文档显示 `trace-unit`、`rvfi_adapter`、`cva6_smoke`、`cva6_branch`、`cva6_jump`、`cva6_ecall`、`cva6_trap_illegal` 等已记录为 PASS。
- Full CVA6 `ariane_testharness` xsim 仍被上游 AXI crossbar/`axi_demux.sv` runtime fatal 阻塞。两周内应继续走 direct-core CVA6 xsim + trace-on/no-trace parity，而不是强攻完整 SoC harness。
- Board 侧文档已明确：board work intentionally after Vivado simulation MVP；已有本地 preflight/bitstream/route/timing artifact，但 clock/reset、UART、bare-metal runtime 仍是 `TODO(BOARD)`，不能提前声称上板成功。

## 两周最终交付

两周后应交付 `RV-MalTrace Simulation Complete Package`：

1. Vivado/direct-core CVA6 trace regression PASS。
2. trace-on / no-trace final state parity PASS。
3. committed-only event correctness PASS。
4. syscall entry/return correlation PASS。
5. trap/context/CSR/SATP event correctness PASS。
6. bounded `ARG_MEM` pointer snapshot synthetic tests PASS。
7. behavior recovery output: `semantic_events.json` + `behavior_graph.json`。
8. fuzz/stress smoke: generated RISC-V programs do not break invariants。
9. resource/timing/drop report updated。
10. board-go/no-go checklist frozen。

这比“完成 trace”更强，因为它形成了 trace 设计、仿真、语义恢复、评估、上板准入的闭环。

## 执行边界和证据口径

这份两周计划只把“软件模拟完成”作为硬目标。所有结论必须按下面口径写入文档或报告：

| 事项 | 两周内允许声称 | 两周内不能声称 |
| --- | --- | --- |
| Trace RTL | synthetic trace-unit 和 direct-core CVA6 xsim 下的 committed-event trace 已验证 | full SoC `ariane_testharness` 已完整通过 |
| CVA6 集成 | direct-core trace-on/no-trace parity 可作为当前本地执行 gate | 真实 SoC/Linux/board 执行已经证明 |
| `ARG_MEM` | default-disabled synthetic pointer snapshot 已验证 guardrails | CVA6 LSU 真实信号接入和 Linux pointer recovery 已完成 |
| Semantic recovery | `trace.jsonl` 可离线生成 `semantic_events.json`、`behavior_graph.json`、`recovery_report.md` | 已具备真实恶意样本检测准确率 |
| Board | 可以冻结 first-board minimal trace profile 和 go/no-go checklist | clock/reset、UART、bare-metal、Linux boot 的实机通过证据已经满足 |
| eBPF/kernel helper | 只能作为后续 enrichment/fallback 方案 | 不能作为 MVP 必需依赖或替代 RTL trace |

核心原则：

- 每个 PASS 都必须绑定 artifact：`trace.jsonl`、`compare.log`、`xsim.log`、`summary.json`、resource/timing report 或 checker 输出。
- 每个 BLOCKED 都必须写清楚 blocker、复现命令、失败 log 路径和 fallback。
- 对 board/Linux/malware 只写计划、准入条件和 TODO 状态，不把 simulation 证据外推成实机证据。
- 默认 trace 内存模式保持 `TRACE_MEM_MODE_NONE`；`ARG_MEM` 只在 synthetic 或明确 gated mode 中出现。

## Malware-like synthetic dataset 设计原则

RISC-V 真实 malware 数据集较少，前期应该用仓库自写的 malware-like synthetic 程序验证 trace 和 semantic recovery。但这些程序必须是“通用恶意行为基准”，不能看起来像为了 RV-MalTrace 的电路事件专门设计的测试向量。

### 目标定位

这类程序的定位是：

```text
repository-authored Linux behavior workload
    -> Docker/RISC-V toolchain build
    -> normal Linux/QEMU/strace behavior sanity check
    -> RV-MalTrace circuit trace collection
    -> offline semantic recovery
    -> compare behavior-level expectations
```

它们不是：

- 真实恶意样本。
- 检测算法训练集。
- 为某个 RTL packet、PC 地址、marker 或 golden trace 特制的程序。
- 只要 RV-MalTrace 能识别就算有效的样例。

### 非专用化约束

| 约束 | 目的 | 可检查方式 |
| --- | --- | --- |
| 行为来自通用 malware technique family | 避免只覆盖电路擅长的事件 | 每个样例必须映射到 file/process/memory/network/anti-analysis 等行为类别 |
| 只使用普通 Linux API 或 syscall | 避免 trace-specific hook | 同一源码能在普通 Linux、QEMU 或 `strace` 下解释 |
| 不读取 RV-MalTrace marker、MMIO、trace buffer 或固定 PC | 避免为硬件通道定制 | 源码 review，禁止 trace-specific include 和 magic address |
| 不依赖精确 syscall 序列作为唯一成功标准 | 避免 libc/kernel 差异导致过拟合 | 以 behavior graph 和 syscall family 为主，exact sequence 只用于 controlled microcase |
| 输入使用 fixture 和参数化路径 | 避免只识别固定字符串 | manifest 记录 fixture，路径可替换但行为不变 |
| 有 benign counterexample | 避免把常见系统行为误写成恶意 | 每类 malware-like 行为至少对应一个 benign workload 或解释 |
| 同源多后端验证 | 避免只在电路上成立 | Docker build、host/QEMU/`strace` sanity、circuit trace 分开记录 |

### 行为覆盖矩阵

两周内不需要一次性实现全部，但 dataset 设计应覆盖这些家族：

| 行为家族 | Synthetic 样例 | 需要恢复的语义 | 备注 |
| --- | --- | --- | --- |
| 文件枚举 | 遍历 fixture 目录并批量 `openat`/`getdents64`/`read` | directory/file access graph | 对应 reconnaissance，不要求真实敏感目录 |
| 批量读取和写出 | 读取多个 fixture，再写入 `/tmp` 输出 | fd graph、read/write volume | 对应 collection/staging |
| self-copy/dropper-like | 读取自身或 fixture，复制到 `/tmp`，可选 `chmod` | source -> output file edge | 不执行复制结果，避免破坏性 |
| 进程链 | `clone`/`fork` -> `execve` -> `wait4` | parent/child/process chain | 用 `/bin/true` 或受控 helper |
| 动态可执行内存 | `mmap` RW、写 buffer、`mprotect` RX | memory permission transition | 不执行 shellcode，可只验证权限变化 |
| anti-debug-like | `ptrace(PTRACE_TRACEME)` 或读取 `/proc/self/status` | anti-analysis indicator | 只观察行为，不做规避对抗 |
| timing check | 多次 `clock_gettime` 并比较 delta | timing syscall pattern | 用于扰动评估，不作为恶意判定 |
| 异常/陷阱 | illegal instruction + signal handler | trap + recovery path | 验证 trap/context，不把 trap 等同恶意 |
| 网络行为模拟 | 本地 loopback 或 disabled-by-default socket case | connect/socket endpoint | 默认不要求外网，避免环境依赖 |

### Docker 编译和 trace 路线

前期应采用三段式路线：

1. 行为源码阶段：在 `experiments/linux_behavior/malware_like/programs/` 编写普通 C 程序，只依赖 Linux syscall/libc 和本地 fixture。
2. 构建阶段：用 Docker 中的 RISC-V Linux toolchain 编译成 RISC-V ELF；同时保留 host build 或 QEMU build 路线用于 sanity check。
3. Trace 阶段：在电路可承载的环境中采集 trace。两周内如果 Linux-on-circuit 还没 ready，就先用 direct-core/bare-metal syscall-shape harness 验证 trace 机制，同时把 Linux ELF execution 保留为 board/Linux gate。

证据必须分层记录：

| 层级 | 证据 | 说明 |
| --- | --- | --- |
| Build evidence | compiler version、ELF hash、source hash | 证明样例可复现 |
| Behavior evidence | host/QEMU/`strace` log 或等价 transcript | 证明行为不是 RV-MalTrace 特有 |
| Circuit evidence | `trace.jsonl`、`compare.log`、`xsim.log` 或 board trace dump | 证明电路能捕获 committed behavior |
| Recovery evidence | `semantic_events.json`、`behavior_graph.json`、`recovery_report.md` | 证明离线语义恢复有效 |

评审风险最高的点是“样例为检测器量身定制”。规避方式是：先定义行为家族和 manifest，再写程序；同一个程序要能用非 RV-MalTrace 的工具解释；评价时看 behavior graph 是否恢复，而不是看某个特定 packet 是否出现。

## 两周工作包拆解

| 工作包 | 目标 | 主要文件或目录 | 产物 | 验收命令 |
| --- | --- | --- | --- | --- |
| WP0 baseline freeze | 冻结当前可复现实验基线 | `docs/sim_results.md`、`results/vivado_sim/` | `summary.json`、per-test logs、baseline notes | `uv run rvmt sim:summary` |
| WP1 event correctness | 打实 branch/jump/syscall/trap/context/drop 语义 | `rtl/trace/`、`sim/golden/`、`sim/tb/` | 新增或确认 golden、compare logs | `uv run rvmt sim:trace-unit` |
| WP2 direct-core CVA6 coverage | 保持真实 CVA6 committed RVFI 路径可跑 | `sim/tb/tb_cva6_direct_xsim_smoke.sv`、`sim/programs/cva6_*` | trace-on/no-trace matrix logs | `uv run rvmt sim:cva6-smoke` |
| WP3 semantic recovery | 把 raw trace 转成可审计行为语义 | `tools/recover_behavior.py`、`experiments/linux_behavior/recovery_targets.json` | `semantic_events.json`、`behavior_graph.json`、`recovery_report.md` | `uv run python tools/recover_behavior.py --self-test` |
| WP4 bounded fuzz/stress | 用生成或 directed 程序压力测试 trace invariants | `sim/programs/`、后续 `tools/check_fuzz_trace.py` | fuzz manifest、per-case compare logs、invariant report | `uv run rvmt sim:cva6-run ...` |
| WP5 lightweight analysis | 证明 event-selective trace 不是 full trace | `docs/trace_format.md`、`tools/compress_trace.py` | compression stats、filter/drop report | `uv run python tools/compress_trace.py ... --check-roundtrip --stats` |
| WP6 evaluation/resource/board gate | 冻结论文级评估与上板准入 | `docs/evaluation_plan.md`、`docs/resource_report.md`、`docs/board_*.md` | RQ gate、resource delta plan、board go/no-go checklist | `uv run python tools/check_evaluation_plan.py` |

## 依赖关系

```text
WP0 baseline freeze
    -> WP1 event correctness
    -> WP2 direct-core CVA6 coverage
    -> WP3 semantic recovery
    -> WP4 bounded fuzz/stress
    -> WP5 lightweight analysis
    -> WP6 evaluation/resource/board gate
```

实际执行时允许 WP3/WP5 与 WP1/WP2 并行推进，但不能在 WP1/WP2 未通过时宣称 trace correctness。

## 两周排期摘要

### 第 1-2 天：冻结当前 baseline

目标：把当前仓库状态变成可复现实验基线。

执行重点：

```powershell
uv run rvmt config:show
uv run rvmt tasks:list
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:summary
```

需要确认：

| Gate | 通过标准 |
| --- | --- |
| `trace-unit` | 所有 synthetic trace tests PASS |
| `cva6-smoke` | direct-core CVA6 trace-on/no-trace 都能到相同 `tohost` PASS |
| `summary` | `results/vivado_sim/summary.json` 更新 |
| `docs` | `docs/sim_results.md` 与实际结果一致 |
| `evidence` | 不能只有口头 PASS，必须有 trace、compare、xsim log |

这里不要急着加新功能。先把现有结果重新跑通并固化。

### 第 3-5 天：打实 committed event correctness

重点检查 4 类事件：

| Event | 必测点 | 失败风险 |
| --- | --- | --- |
| `BRANCH` / `JUMP` | compressed instruction、JAL、JALR、taken/target | `pc + 4` 假设错误，C extension 下应考虑 2-byte instruction |
| `SYSCALL_ENTRY` | 只接受 U-mode ECALL | S/M ECALL 误识别成 Linux syscall |
| `SYSCALL_RET` | SRET-to-U + outstanding syscall | 普通 SRET 被误配成 syscall return |
| `TRAP` | illegal/ebreak/ecall cause/tval/pc | trap 与 retire 混淆 |

`docs/next-plan.md` 已指出几个关键坑：ECALL 不能只从 normal retire path 捕获，compressed instruction 不能默认 `next_pc = pc + 4`，JALR target 要优先用 core resolved target/next_pc，`a0-a7 shadow` 也有 stale 风险。

建议新增或确认以下 regression：

- `cva6_compressed_branch`
- `cva6_jalr_target`
- `cva6_u_ecall_entry`
- `cva6_s_ecall_trap_only`
- `cva6_syscall_ret_sret_to_u`
- `cva6_arg_shadow_same_cycle`

### 第 6-7 天：从寄存器 trace 推进到语义 trace

只拿到 `a7` 和 `a0-a5` 还不够。RISC-V psABI 中 `x10-x17` 对应 `a0-a7` argument registers，且 `a0/a1` 也用于返回值。仓库文档也已把 Linux syscall semantic reconstruction 作为论文级方向：从 syscall number、arguments、return value 恢复 `openat`、`read`、`write`、`execve`、`connect`、`mmap`、`mprotect` 等行为。

两周内不要直接上真实 Linux malware。应做 synthetic semantic tests：

| Test | 目标 |
| --- | --- |
| `openat("/tmp/a.txt")` | 恢复 path string、fd return |
| `write(fd, buf, len)` | 恢复 fd、len、return value |
| `execve(path, argv, envp)` | 恢复 executable path，`argv` 可先简化 |
| `mmap + mprotect RX` | 标记 dynamic executable memory |
| `fork/clone + exec` | 形成 process chain 的最小语义 |

仓库已有 `ARG_MEM` pointer snapshot 方向，并且文档记录 `pointer_string`、`pointer_guardrails` 已覆盖 null-terminated string、page-boundary、max-length、multi-byte load clipping、timeout、unrelated S-mode load rejection。

这一块是最值得保留为论文创新点的部分：轻量硬件 trace + syscall pointer semantic reconstruction。

### 第 8-9 天：把 RISC-V fuzzing 作为 trace validator

不要在这两周内另起一个“RISC-V fuzzing”大坑。正确用法是：

```text
riscv-dv / small generator
    -> random / directed bare-metal programs
    -> CVA6 direct-core simulation
    -> trace checker invariants
    -> 发现 trace 漏报、误报、drop、target mismatch
```

RISCV-DV 是 open-source RISC-V processor verification instruction generator，支持 RV32/RV64、privileged modes、page table randomization、trap/interrupt handling、MMU stress、illegal instruction、random branch、directed instruction mixing、coverage model，以及多 ISS co-simulation。

两周内建议只做 bounded fuzzing：

| Fuzz 类别 | 生成内容 | 检查 invariant |
| --- | --- | --- |
| control-flow fuzz | branch/jal/jalr/compressed mix | target/taken 与 golden/ISS 一致 |
| trap fuzz | illegal、ebreak、ecall | trap cause 合法，不能产生 normal retire |
| syscall fuzz | 随机 `a0-a7` + U-mode ECALL | entry args 与写入值一致 |
| CSR/context fuzz | watched CSR write | CSR/SATP/PRIV event 正确 |
| overflow fuzz | 高 event burst | `EVT_DROP` 可见，core final state 不变 |

第一版 fuzz 不需要追求 processor bug discovery。目标是 trace correctness under stress。

### 第 10-11 天：做更轻便的分析手段

这里应该成为方向 4 的核心：

- 不是 full instruction trace。
- 不是 full memory trace。
- 不是 DBI。
- 不是 eBPF-only。
- 而是 event-selective committed behavior trace。

建议形成 3 层轻量化：

| 层级 | 内容 | 价值 |
| --- | --- | --- |
| L1 event filter | 只开 syscall/trap/context/drop，必要时开 branch | 降低 trace bandwidth |
| L2 compact packet | event-specific payload、cycle delta、pc delta | 降低存储/导出成本 |
| L3 semantic recovery | 离线恢复 behavior graph | 减少硬件复杂度 |

`docs/trace_format.md` 已经有 filter controls 和 compressed trace prototype，包含 `cycle_delta`、`pc_delta`、event-specific payload、context delta 等设计。

两周内应输出：

- `results/vivado_sim/<run>/semantic_events.json`
- `results/vivado_sim/<run>/behavior_graph.json`
- `results/vivado_sim/<run>/recovery_report.md`

最小 behavior graph：

```json
{
  "process": "synthetic_sample",
  "events": [
    {"syscall": "openat", "path": "/tmp/a.txt", "ret": 3},
    {"syscall": "write", "fd": 3, "len": 16, "ret": 16},
    {"syscall": "mprotect", "prot": "RX"},
    {"syscall": "execve", "path": "/tmp/dropper"}
  ]
}
```

这比单纯输出 `trace.jsonl` 更接近 malware behavior analysis。

### 第 12-13 天：整理论文级 evaluation gate

`docs/evaluation_plan.md` 已经把研究问题拆成 correctness、semantic reconstruction、low perturbation、evasion resistance、hardware cost、malware behavior usefulness，并列出 `strace`/`ptrace`、eBPF-only、QEMU plugin、software instrumentation、event-only、pointer snapshot、kernel helper 等 baseline。

两周内不要尝试完成所有 evaluation。应只完成 simulation-level RQ1/RQ2 的证据：

| RQ | 两周内状态 |
| --- | --- |
| RQ1 correctness | 必须完成 |
| RQ2 semantic reconstruction | synthetic 完成，Linux 后置 |
| RQ3 low perturbation | 只记录 no-backpressure + final state parity |
| RQ4 evasion resistance | 只写实验计划，不声称结果 |
| RQ5 hardware cost | 更新 resource/timing/drop report |
| RQ6 malware usefulness | 用 malware-like synthetic case study 预演 |

`docs/resource_report.md` 当前已有 Genesys 2 routed utilization/timing snapshot，以及 trace queue/drop 统计。两周内要补的是 trace-enabled delta，而不是泛泛地说“性能影响小”。

### 第 14 天：冻结上板准入条件

Go to board only if:

1. `sim:trace-unit` PASS。
2. `sim:cva6-smoke` PASS。
3. trace-on/no-trace parity PASS。
4. syscall/trap/context/drop tests PASS。
5. semantic recovery synthetic PASS。
6. board minimal event profile defined。
7. full retire disabled by default。
8. BRAM ring buffer / ILA dump path ready。

上板第一版只开：

- `EVT_SYSCALL_ENTRY`
- `EVT_SYSCALL_RET`
- `EVT_TRAP`
- `EVT_PRIV`
- `EVT_CSR`
- `EVT_SATP`
- `EVT_DROP`

默认关闭：

- full `RETIRE`
- full `BRANCH`
- full `LOAD/STORE` memory trace

原因很直接：带宽、BRAM、timing 风险都太高。

## 每日详细执行清单

### Day 1：证据盘点和状态冻结

目标：确认当前仓库中哪些是 PASS、哪些只是计划，避免两周目标建立在错误状态上。

执行：

```powershell
uv run rvmt config:show
uv run rvmt tasks:list
uv run rvmt sim:summary
uv run python tools/check_trace_boundary.py
uv run python tools/check_timing_principles.py
```

检查项：

- `results/vivado_sim/summary.json` 的 `overall` 必须为 `PASS`，否则先 triage 失败 test。
- `docs/sim_results.md` 中 direct-core CVA6 rows 必须与 `summary.json` 一致。
- full SoC `ariane_testharness` 仍应标为 `BLOCKED`，不能被计入两周通过项。
- `docs/risk_log.md` 中 AXI demux blocker、LSU hook TBD、board TODO 必须保留。

产物：

- 一段 baseline note，记录当前 PASS matrix、BLOCKED matrix、复现命令。
- 若 `summary.json` 与文档不一致，先更新 `docs/sim_results.md`，不要继续扩功能。

验收：

- `sim:summary` 可生成 summary。
- trace boundary 和 timing-principle checks 通过。
- 未新增 board/Linux 成功声明。

### Day 2：重跑最小可复现仿真

目标：把 trace-unit、direct-core CVA6 和 semantic recovery 三条线重新跑通。

执行：

```powershell
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_linux_behavior_recovery.py
uv run rvmt sim:summary
```

重点看：

- `sim:trace-unit` 覆盖 `syscall_ret`、`pointer_string`、`pointer_guardrails`、`backpressure`、`filter`、`board_minimal`、`rvfi_adapter`。
- `sim:cva6-smoke` 必须同时跑 trace-enabled 和 no-trace snapshots。
- no-trace snapshot 必须到相同 `tohost` PASS，不允许只看 trace-enabled trace。

产物：

- `results/vivado_sim/<test>/trace.jsonl`
- `results/vivado_sim/<test>/compare.log`
- `results/vivado_sim/<test>/xsim.log`
- `results/vivado_sim/<test>/xsim_notrace.log`
- 更新后的 `results/vivado_sim/summary.json`

验收：

- 所有当前 synthetic 和 direct-core tests PASS。
- 若失败，Day 3 不进入新 test，先把失败归类为 testbench、golden、RTL、工具链或 Vivado blocker。

### Day 3：control-flow correctness 加固

目标：把 branch/jump/compressed/JALR 这条线的失败模式写成可检查项目。

任务：

- 确认 `BRANCH` 的 `taken` 基于实际 next PC，而不是 `pc + 4` 的固定假设。
- 确认 compressed instruction 使用 instruction length 2/4，而不是默认 4。
- 确认 `JUMP` 优先使用 resolved target 或 `commit_next_pc`，fallback 必须写入文档。
- 确认 direct-core `cva6_branch`、`cva6_jump` 的 golden 包含 expected `target`。

建议新增或补齐的 directed cases：

| Case | 目的 | 最小期望 |
| --- | --- | --- |
| `cva6_compressed_branch` | C extension 下 sequential PC 为 `pc + 2` | non-taken/taken 判断不被 `pc + 4` 污染 |
| `cva6_jalr_target` | 间接跳转 target 正确 | `target` 为实际 committed next PC |
| `cva6_branch_not_taken` | not-taken branch 不误报 taken | `taken=false`，target 为 sequential PC 或按 schema 约定输出 |
| `cva6_branch_after_trap` | branch 后异常不误配 next committed PC | fallback 模式必须拒绝不可靠 target |

验收：

- 每个新增 case 都有 source/mem、expected JSON、`compare.log`。
- 如果两周内不实现新 case，也必须在计划中明确剩余 gap，不能把当前 branch/jump PASS 解释成完整 control-flow coverage。

### Day 4：syscall/trap correctness 加固

目标：避免把所有 ECALL 都当成 Linux syscall，也避免普通 SRET 被误配成 syscall return。

任务：

- `SYSCALL_ENTRY` 只接受 U-mode ECALL + U_ECALL cause。
- S/M-mode ECALL 只能产生 `TRAP`，不能建立 outstanding syscall。
- `SYSCALL_RET` 必须同时满足 SRET、S->U、same hart/context、outstanding syscall。
- `syscall_id` 必须单调，entry/return 一一配对。
- `duration` 必须来自 entry cycle 到 return cycle，不能用 wall time 或 event index 代替。

建议检查：

```powershell
uv run rvmt sim:trace-unit
uv run python tools/recover_behavior.py --trace sim/golden/behavior_recovery.trace.jsonl --out-dir build/behavior_recovery_smoke
```

产物：

- `syscall_ret` regression 的 `trace.jsonl` 和 `compare.log`。
- `build/behavior_recovery_smoke/semantic_events.json` 中 entry/return 字段完整。

验收：

- U-mode syscall entry 和 SRET-to-U return 被恢复为一个 syscall。
- Machine-mode `cva6_ecall` 保持 `TRAP`，不是 `SYSCALL_ENTRY`。
- unmatched return 或 nested syscall 出现时，recovery report 必须显式标出。

### Day 5：context/CSR/SATP/drop 语义收口

目标：把“行为发生在哪个上下文”这件事做成基础语义，而不是后续才补。

任务：

- `PRIV` 事件要记录 `old_priv` 和 `new_priv`。
- `SATP` 要被单独保留为 context 事件，而不是普通 CSR 被吞掉。
- watched CSR 列表和优先级必须写在 `docs/signal_map.md` 或相关文档中。
- `DROP.value` 记录累计 drop count；drop 不是 silent failure。
- filter 后的 dropped/kept 事件口径要能解释。

重点 artifacts：

- `results/vivado_sim/context/trace.jsonl`
- `results/vivado_sim/csr/trace.jsonl`
- `results/vivado_sim/backpressure/trace.jsonl`
- `results/vivado_sim/filter/trace.jsonl`

验收：

- backpressure test 的 drop rows 与 `docs/resource_report.md` 中 drop summary 一致。
- filter test 能证明 event-type、PC range、privilege mask 的组合不会把 drop accounting 吞掉。

### Day 6：semantic recovery schema 细化

目标：定义两周内 semantic recovery 到底恢复什么，不把“语义恢复”说空。

最低输出 schema：

| 输出 | 必须字段 | 来源事件 |
| --- | --- | --- |
| `semantic_events.syscall_sequence[]` | `name`、`number`、`args`、`return_value`、`return_pc`、`duration` | `SYSCALL_ENTRY`、`SYSCALL_RET` |
| `semantic_events.control_flow_segments[]` | `kind`、`pc`、`target`、`taken` | `BRANCH`、`JUMP` |
| `semantic_events.trap_context_transitions[]` | `evt`、`pc`、`priv`、`cause`、`csr`、`value` | `TRAP`、`CSR`、`SATP`、`PRIV` |
| `semantic_events.privilege_boundaries[]` | `kind`、`pc`、`priv`、`old_priv`、`new_priv` | `SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`PRIV` |
| `behavior_graph` | `nodes`、`edges`、`schema` | semantic events |

执行：

```powershell
uv run python tools/recover_behavior.py --self-test
uv run python tools/recover_behavior.py --trace sim/golden/behavior_recovery.trace.jsonl --out-dir build/behavior_recovery_smoke
uv run python tools/check_linux_behavior_recovery.py
```

验收：

- `build/behavior_recovery_smoke/semantic_events.json` 字段稳定、排序 deterministic。
- `recovery_report.md` 明确写明这是 derived trace semantics，不是 malware detection evidence。
- schema gap 进入 TODO，不在论文叙述里偷换成已完成语义。

### Day 7：malware-like synthetic case study 预演

目标：用可控样例预演行为图，而不是直接跑真实恶意样本。

两周内优先 4 个 case：

| Case | 行为 | 需要的 trace 证据 | 输出 |
| --- | --- | --- | --- |
| file activity | `openat` -> `read`/`write` -> `close` | syscall entry/return、fd return | file behavior timeline |
| exec chain | `clone` -> `execve` -> `wait4` | process-related syscall sequence | process chain graph |
| dynamic executable memory | `mmap` -> write/decode -> `mprotect RX` | mmap/mprotect args/return | memory permission event |
| anti-debug-like | `ptrace` or `/proc/self/status` open/read | syscall sequence + path if available | anti-analysis indicator |

现实边界：

- 如果没有 pointer string 语义，只能把 path 标为 `ptr:<addr>` 或 `unknown_path`。
- `ARG_MEM` synthetic PASS 不能自动代表 Linux path recovery PASS。
- 行为规则只做 audit/rule-based summary，不做 classifier accuracy。

验收：

- 每个 case 都能从 `trace.jsonl` 派生出 semantic event row。
- 没有 path/fd 语义时必须保留 `UNKNOWN`，不手工补猜。

### Day 8：bounded fuzz/stress 设计

目标：把 fuzzing 放在 trace validator 位置，不另开一篇 processor fuzzing 论文。

最小设计：

| Fuzz set | 输入空间 | 不变量 |
| --- | --- | --- |
| `fuzz_cf` | branch/jump/JALR/compressed mix | target aligned，taken 与 expected 一致 |
| `fuzz_trap` | illegal/ebreak/ecall mix | trap 不同时产生 normal retire |
| `fuzz_syscall` | U-mode ECALL + randomized `a0-a7` | entry args 与写入值一致 |
| `fuzz_context` | CSR/SATP/privilege transition | context event 顺序可解释 |
| `fuzz_overflow` | burst events / tiny queue | `DROP` 可见且 final state parity 保持 |

建议实现路径：

- 第一版不必接完整 riscv-dv；可以先做 deterministic generator，输出少量 assembly seeds。
- 每个 seed 通过 `uv run rvmt sim:cva6-run --asm ... --name ... --expected ...` 跑 direct-core。
- 如果引入 riscv-dv，只把它作为 seed generator，checker 仍看 RV-MalTrace invariants。

产物：

- `sim/programs/fuzz_*/`
- `sim/golden/fuzz_*.expected.json`
- `tools/check_fuzz_trace.py`
- `results/vivado_sim/fuzz_*/`

验收：

- fuzz 失败必须落到具体 invariant，不能只说 xsim failed。
- fuzz 不阻塞主线；如果 Day 8 未完成，主线仍以 directed regression 为准。

### Day 9：filter/compression/drop 成本模型

目标：把“轻量”落成可量化的 trace volume 和 drop 口径。

执行：

```powershell
uv run python tools/compress_trace.py results/vivado_sim/rvfi_adapter/trace.jsonl --check-roundtrip --stats
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
uv run python tools/generate_resource_report.py
```

需要记录：

- 原始 JSONL event count。
- compact prototype event count 和 payload length stats。
- 过滤前后 event family 分布。
- 每个 correctness mode 是否存在 unaccounted drop。
- backpressure mode 的 expected drop count。

验收：

- compression roundtrip 后语义不变。
- `DROP` 只作为 accounted loss，不作为 silent trace corruption。
- `docs/resource_report.md` 与最新 `summary.json` 的 drop rows 对齐。

### Day 10：noninterference 和资源边界

目标：把“trace 不影响 core”分成当前能证明和未来必须证明两层。

当前能证明：

- trace RTL 没有 ready/stall/backpressure port 暴露给 core。
- `trace_top` 和 `cva6_rvfi_trace_adapter` 默认 `PIPELINE_INPUTS=1`。
- direct-core trace-on/no-trace final state parity PASS。
- queue overflow 走 drop accounting，不 stall core。

仍需后续证明：

- trace-enabled full FPGA build 的 LUT/FF/BRAM/Fmax delta。
- trace path 对 routed timing 的真实影响。
- board trace sink 在 BRAM/ILA/UART/AXI 模式下的 drop rate。

执行：

```powershell
uv run python tools/check_timing_principles.py
uv run python tools/check_timing_principles.py --self-test
uv run python tools/generate_resource_report.py
```

验收：

- 文档中不得把 baseline Genesys 2 routed report 写成 trace-enabled resource overhead。
- 若无 trace-enabled implementation report，只能写“baseline routed snapshot + simulation drop stats”。

### Day 11：board go/no-go 预案

目标：冻结上板前置条件，避免仿真未收口就进入硬件调试。

执行：

```powershell
uv run python tools/check_board_baseline.py
uv run python tools/check_vivado_authorization.py
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_board_trace_programs.py
```

Go 条件：

- simulation summary PASS。
- direct-core trace-on/no-trace parity PASS。
- first-board trace profile 只开 syscall/trap/context/branch/drop。
- `RETIRE`、`JUMP`、`MARKER` 默认关闭。
- board validation program manifest 和 expected trace 已存在。

No-go 条件：

- summary 有 regression FAIL。
- trace sink 需要 backpressure core 才能过。
- first-board profile 依赖 full retire 或 full memory trace。
- 没有 `results/board/genesys2_baseline/<run-id>/` 时声称板上验证已经通过。

产物：

- board go/no-go checklist。
- 如果继续上板，准备 `results/board/genesys2_trace_validation/<run-id>/` 目录模板。

### Day 12：evaluation gate 和 baseline 设计

目标：把论文级评估拆成两周内能完成的 simulation gate 和后续 board/Linux gate。

执行：

```powershell
uv run python tools/check_evaluation_plan.py
uv run python tools/check_linux_behavior_principles.py
uv run python tools/check_linux_benign_dataset.py
uv run python tools/check_linux_malware_like_dataset.py
```

两周内完成：

- RQ1 correctness 的 simulation artifact list。
- RQ2 semantic reconstruction 的 synthetic recovery artifact list。
- RQ5 hardware cost 的当前 baseline/resource/drop artifact list。

两周内只规划：

- RQ3 low perturbation 的 paired run protocol。
- RQ4 evasion resistance 的 controlled suite protocol。
- RQ6 malware usefulness 的 case-study rubric。

验收：

- `docs/evaluation_plan.md` 仍保持 TODO，除非真实 artifact 已存在。
- 每个 baseline 都必须有独立 run config，不能把 `strace` ground truth run 当作 uninstrumented runtime。

### Day 13：研究叙事和消融实验设计

目标：把两周成果组织成论文后续主线，而不是只堆工程 checklist。

核心叙事：

```text
Problem: RISC-V malware/runtime analysis 不能依赖 x86 opcode signature，也不应只依赖 ptrace/DBI/QEMU。
Insight: CVA6 committed execution + syscall ABI + context events 可转成 architecture-neutral behavior graph。
Design: sideband committed trace + syscall return pairing + optional pointer semantic enrichment + offline recovery。
Evidence: simulation correctness + direct-core parity + synthetic semantic recovery + resource/drop accounting。
Next gate: board minimal trace + Linux syscall alignment + evasion/overhead comparison。
```

消融设计：

| Variant | 打开内容 | 回答问题 |
| --- | --- | --- |
| event-only | syscall/trap/context/drop | 不做 pointer snapshot 时能恢复多少行为 |
| event + branch | 加 branch | control-flow sketch 对 audit 是否有价值 |
| event + `ARG_MEM` synthetic | 加 pointer snapshot synthetic | path/argv/sockaddr 语义恢复潜力 |
| event + helper/eBPF later | 加 software metadata alignment | Linux 语义缺口是否需要 trusted helper |

验收：

- 论文主贡献不写成“实现了一个 trace tap”。
- 把 novelty 收敛到 low-perturbation committed semantic tracing + syscall return/context/pointer enrichment route。

### Day 14：冻结交付包

目标：交付一个可复现、可审阅、可继续上板的 simulation package。

最终命令：

```powershell
uv run rvmt config:show
uv run rvmt sim:trace-unit
uv run rvmt sim:cva6-smoke
uv run rvmt sim:summary
uv run python tools/recover_behavior.py --self-test
uv run python tools/check_linux_behavior_recovery.py
uv run python tools/compress_trace.py sim/golden/compression_edges.trace.jsonl --check-roundtrip --stats
uv run python tools/check_timing_principles.py
uv run python tools/check_trace_boundary.py
uv run python tools/check_board_trace_minimal.py
uv run python tools/check_evaluation_plan.py
```

交付包目录建议：

```text
results/vivado_sim/
build/behavior_recovery_smoke/
docs/sim_results.md
docs/resource_report.md
docs/evaluation_plan.md
docs/two-week-plan.md
docs/board_trace_minimal.md
docs/board_trace_validation.md
```

最终验收：

- 所有 simulation gates PASS。
- 所有 board/Linux/malware claims 仍有正确 TODO/BLOCKED 标记。
- 失败项都有 blocker、fallback、next action。

## 风险 burn-down

| 风险 | 两周内处理方式 | 退出标准 |
| --- | --- | --- |
| Full SoC xsim 被 `axi_demux.sv` fatal 阻塞 | 保持 direct-core CVA6 matrix 为本地 execution gate | 不再把 full SoC xsim 作为两周硬目标 |
| CVA6 LSU hook TBD | `ARG_MEM` 只做 synthetic pointer snapshot，不宣称 Linux pointer recovery | `docs/signal_map.md` 明确 mem load hook TBD |
| `a0-a7` shadow stale | MVP 规定 trace from reset；后续 RF snapshot 作为增强 | syscall tests 覆盖 same-cycle write/ECALL |
| compressed/JALR target 错误 | 增加 directed regression 或明确 coverage gap | branch/jump golden 包含 target/taken |
| trace bandwidth/drop | first-board profile 默认关 full retire/jump/memory trace | backpressure/drop test 和 resource report 对齐 |
| 真实恶意样本数据不足或风险高 | 只用 benign + controlled malware-like synthetic suite | policy 保持 real malware forbidden early |
| eBPF 稀释贡献 | eBPF 只作为后续 metadata alignment，不是 MVP dependency | semantic strategy checker 通过 |
| trace-enabled resource delta 缺失 | 当前只报告 baseline routed snapshot + simulation queue/drop | 不声称 trace-enabled Fmax/LUT delta 已测 |

## 5 个方向的具体取舍

### 1. 硬件 malware 分析模块 RISC-V

这是主线，但两周内应该叫：

```text
RISC-V committed behavior tracing for malware-like behavior analysis
```

不要过早说“malware detection module”。当前更稳的是：

```text
trace collection
    -> syscall semantic recovery
    -> behavior graph
    -> rule-based malware-like behavior audit
```

检测规则可以先做：

| 规则 | Trace 证据 |
| --- | --- |
| anti-debug | `ptrace`、读取 `/proc/self/status`、搜索 `TracerPid` |
| dynamic code | `mmap RW` -> write/decode -> `mprotect RX` |
| dropper-like | open/write executable -> `chmod` -> `execve` |
| reconnaissance | scan `/proc`、read `/etc/passwd`、目录枚举 |
| abnormal syscall sequence | 高频 open/read/write/exec/fork |

### 2. RISC-V fuzzing

作为验证工具，不作为当前主贡献。

最小实现：

- `tools/gen_rv_trace_fuzz.py`
- `sim/programs/fuzz_cf/`
- `sim/programs/fuzz_trap/`
- `sim/programs/fuzz_syscall/`
- `sim/golden/fuzz_invariants.json`
- `tools/check_fuzz_trace.py`

Fuzz checker 不需要知道每条指令的完整语义，先检查 invariants：

- `TRAP` event 不能同时作为 normal `RETIRE`。
- U-mode ECALL 必须有 `SYSCALL_ENTRY`。
- S/M-mode ECALL 不能有 `SYSCALL_ENTRY`。
- branch target 必须 aligned。
- `DROP` 出现时 `drop_count` 必须单调/accounted。
- trace-on/no-trace final state 必须一致。

### 3. 改进软核性能/能力

两周内不要改 CVA6 微架构性能。风险太高，而且会稀释主线。

只做 3 件事：

1. trace sideband，不改变 architectural state。
2. trace sink 不反压 core。
3. 记录 LUT/FF/BRAM/Fmax/drop。

真正的“能力提升”应描述为：

> 给 CVA6 增加低扰动行为观测能力，而不是提高 IPC/Fmax。

性能优化可以放到后续：

- compact packet
- event filter
- larger FIFO / BRAM ring
- AXI DMA trace sink
- trace compression

### 4. 更好的、更轻便的分析手段

这是最有论文味的方向。建议命名：

```text
Selective committed semantic tracing
```

它比 full trace 轻：

- 只记录行为相关事件。
- 只记录 committed events。
- 只在 syscall 期间做 bounded pointer snapshot。
- 只离线恢复语义。
- 不做 full load/store trace。
- 不做 DBI。
- 不依赖 `ptrace`。

两周内最重要的输出不是 RTL，而是这个对比表：

| 方法 | 扰动 | 语义 | 抗规避 | 硬件成本 | 备注 |
| --- | --- | --- | --- | --- | --- |
| `strace`/`ptrace` | 高 | 高 | 低 | 0 | 容易被检测 |
| eBPF-only | 中 | 高 | 中 | 0 | 依赖 trusted kernel |
| QEMU plugin | 高 | 高 | 低/中 | 0 | 不是真实硬件执行 |
| full instruction trace | 低/中 | 低 | 高 | 高 | 带宽爆炸 |
| RV-MalTrace event-only | 低 | 中 | 高 | 低/中 | 两周主线 |
| RV-MalTrace + pointer snapshot | 低/中 | 高 | 高 | 中 | 论文潜力点 |

### 5. x86 -> RV malware instruction 不一样

不要试图做 x86 instruction 到 RISC-V instruction 的直接映射。恶意软件分析应该比较 behavior semantics，不是比较 raw opcode。

应这样写：

| 层级 | x86 | RISC-V | 分析策略 |
| --- | --- | --- | --- |
| syscall ABI | syscall 指令，寄存器约定不同 | `ecall`，`a7/a0-a5/a0` | 架构相关 capture，语义统一 |
| control-flow | call/jmp/ret | jal/jalr/branch | 统一成 branch/jump/call-like edges |
| privilege transition | ring/user-kernel | U/S/M mode | 统一成 context transition |
| anti-debug | ptrace/proc/timing | 同样可通过 syscall/proc/timing 表现 | 看行为，不看 ISA |
| packing/dynamic code | mmap/mprotect/jump | mmap/mprotect/jalr/branch | 统一成 executable mapping + control transfer |

最终论文表达：

```text
Instruction-level malware signatures are architecture-dependent.
Behavior-level traces are more portable.
RV-MalTrace translates RISC-V-specific execution events into architecture-neutral behavior graphs.
```

## 两周完成标准

建议把“软件模拟完成”定义成下面 10 条：

- [ ] `[PASS]` trace event schema frozen。
- [ ] `[PASS]` direct-core CVA6 trace-on simulation。
- [ ] `[PASS]` direct-core CVA6 no-trace parity。
- [ ] `[PASS]` branch/jump/trap/syscall/context regression。
- [ ] `[PASS]` U-mode syscall entry + SRET-to-U syscall return。
- [ ] `[PASS]` bounded `ARG_MEM` pointer snapshot synthetic tests。
- [ ] `[PASS]` JSONL parser + golden checker。
- [ ] `[PASS]` `semantic_events.json` + `behavior_graph.json` output。
- [ ] `[PASS]` fuzz/stress invariant checker。
- [ ] `[PASS]` board bring-up go/no-go checklist。

最重要的工程判断：

> 先把 simulation evidence 做成铁证；不要在两周内同时追完整 Linux、真实恶意样本、独立 fuzzing、软核性能优化和上板。

这样做，两周后得到的不是“一个 trace 雏形”，而是可以支撑上板和论文扩展的 RISC-V hardware-assisted malware behavior tracing simulation baseline。
