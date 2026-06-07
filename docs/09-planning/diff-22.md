# RV-MalTrace 与 ISSTA-22 NCScope 的差异

本文记录 `vendor/ISSTA-22-NCScope` 与 RV-MalTrace/RV-MalScope 的技术差异、
可借鉴边界、当前证据状态和后续论文级缺口。本文是设计分析和路线校准，
不是新的 board、Linux 或 malware 实验结果。所有板卡、Linux、真实工作负载
和论文评估结论仍必须以对应 gate 下的 artifact 为准。

## 一句话结论

NCScope 是一个面向 ARM/Android native code 的分析系统。它使用现成的
ARM ETM/CoreSight 执行轨迹作为控制流来源，再结合 eBPF/BCC 采集内存、
API 参数和 Android runtime 语义，最终识别 Android app native/JNI 层的
self-protection 和 anti-analysis 行为。

RV-MalTrace 的主线不同。我们不是把 NCScope 简单移植到 RISC-V，也不是先做
RISC-V eBPF tracing。我们的核心贡献应写成：

```text
CVA6/RISC-V committed execution
  -> sideband RTL event trace
  -> syscall/control-flow/trap/context correlation
  -> optional pointer semantic enrichment
  -> behavior graph / audit output
  -> board, Linux, overhead, and evasion evaluation
```

关键差异不只是 ISA。NCScope 的硬件 trace 能力来自商业 ARM ETM；RV-MalTrace
要把 CVA6 committed-event hardware trace tap 本身做成贡献点，包括
committed-only 事件、不反压 core、显式 `DROP` 记账、可复现 simulation gate、
trace-enabled FPGA cost，以及后续 board/Linux 对齐。

## NCScope 的系统结构

本地 artifact 的 README 给出的 NCScope 工作流可以拆成五层：

1. 平台和采集硬件

   - ARM Juno r2 development board。
   - ARM DSTREAM debug probe。
   - ARM Development Studio / DS-5。
   - Android system image。

2. ETM 控制流采集

   - DS-5 scripts 配置 ETM。
   - 按 app PID、native library 或 JNI function 采集 trace stream。
   - ETM stream 保存为 binary trace。

3. ETM 解码和地址语义

   - `DS5_workspace/DTSLDecode` 解码 ETMv4 stream。
   - `MemoryMap.apk` 和 Android memory map 用来把地址映射到 framework oat、
     system native libraries 和 app native code。
   - 这一层的主要产物是 resolved execution trace，而不是 syscall 级 JSONL。

4. eBPF/BCC 语义日志

   - `eBPF_program/behavior_analysis.py` hook `strcmp`、`open`、`openat`、
     `write`、`access`、`stat`、`mmap`、`mprotect`、`fork`、`connect`、
     Android property 和 ART/JNI 相关函数。
   - 通过 `bpf_probe_read` 读取字符串、参数、内存片段和 runtime 结构。
   - `behavior_filter.py` 和 `behavior_parser.py` 对采集日志清洗和归因。

5. 离线分析

   - 将 ETM 控制流和 eBPF memory data 合并。
   - 对 Android app native code 识别 self-protection / anti-analysis behavior。
   - `ARCUS/tools/angr/analysis_etm.py` 使用 trace 和 memory data 做 offline
     symbolic execution / bug diagnosis。

因此 NCScope 的实际分析能力来自组合：

```text
ARM ETM control-flow trace
  + Android memory map
  + eBPF/BCC semantic probes
  + native library / JNI knowledge
  -> Android native behavior analysis
```

## RV-MalTrace 的系统结构

RV-MalTrace/RV-MalScope 当前仓库目标是 CVA6/RISC-V hardware-assisted
behavior tracing。系统结构应拆成四层：

1. RTL event source

   - `rtl/trace/` 下的 synthesizable trace logic。
   - CVA6 RVFI/direct-core simulation path 用于验证 committed event shape。
   - full SoC xsim probe 通过 `uv run rvmt sim:cva6-full-soc` 验证
     `ariane_testharness` 可以 boot from DRAM 并到达 breakpoint-terminated
     PASS。

2. Committed event model

   - `RETIRE`、`BRANCH`、`JUMP`。
   - `SYSCALL_ENTRY`、`SYSCALL_RET`。
   - `TRAP`、`CSR`、`SATP`、`PRIV`。
   - 可选 `ARG_MEM` 和 `DROP`。
   - JSONL trace 是硬件/仿真输出和 Python 分析之间的稳定接口。

3. Low-perturbation trace transport

   - trace logic 必须 sideband-only。
   - trace sink 不能 backpressure CVA6。
   - 带宽不足时必须丢 trace record 并显式输出/account `DROP`，不能 silent
     corruption。
   - board 上第一版 profile 应保持 syscall/trap/context/branch/drop，默认不开
     full retire 和 full memory trace。

4. Offline semantic recovery

   - syscall entry/return correlation。
   - fd/path/process relationship recovery。
   - pointer string snapshot 或明确 scoped helper/eBPF fallback。
   - behavior graph 和 audit report。
   - 与 `strace`、eBPF-only、QEMU plugin、software instrumentation 对比。

## 核心差异矩阵

| 维度 | NCScope | RV-MalTrace / RV-MalScope |
| --- | --- | --- |
| 目标平台 | ARM/AArch64 Android on Juno | RISC-V/CVA6，先 Vivado xsim，后 FPGA board/Linux |
| 硬件 trace 来源 | 现成 ARM ETM/CoreSight | 自有 CVA6 RTL sideband trace tap + RVFI/direct-core/full-SoC verification |
| 主贡献位置 | ETM trace 与 Android native behavior analysis 的结合 | RISC-V committed-event tracing path 本身，以及 semantic recovery/evaluation |
| 第一证据 gate | DS-5 ETM stream + Android/eBPF behavior workflow | `sim:trace-unit`、`sim:cva6-smoke`、`sim:cva6-full-soc`、JSONL golden comparison |
| 执行粒度 | ETM instruction/control-flow stream | committed architectural events；默认不是 full instruction trace |
| 语义补全 | eBPF/BCC hook 是核心组成部分 | eBPF 不是 MVP 依赖；可作为后续 enrichment 或 comparison |
| 内存语义 | 在 hook 点读取字符串、参数和 memory data | 默认 memory trace 关闭；bounded pointer snapshot 需要独立 gate |
| 低扰动论点 | 比 emulator/debugger 低扰动，但语义侧仍依赖 software probes | RTL sideband observation，不反压 core，有 drop accounting 和 trace/no-trace parity |
| 分析对象 | Android app native/JNI self-protection、anti-analysis | RISC-V Linux userland 和 malware-like native workload |
| 地址/库语义 | Android memory map、oat/native library、ART/JNI 语义 | RISC-V syscall ABI、Linux fd/path/process semantics、ELF/objdump annotation |
| 威胁模型 | Android app native code，kernel/eBPF trusted | 用户态 malware-like workload；kernel/helper 是否 trusted 必须分开写 |
| 评估重点 | 金融 app、恶意 app、Geekbench/DroidScope comparison | correctness、semantic reconstruction、overhead、evasion resistance、resource cost |
| 可移植性论点 | ARM/Android native analysis | 行为语义跨 ISA，trace source 是 RISC-V hardware committed events |

## 不能写成“只是 NCScope on RISC-V”的原因

1. Trace source 不同

   NCScope 没有设计新的 ARM core trace tap。它利用已有 ETM/CoreSight。
   RV-MalTrace 的核心工作是把 CVA6 committed execution 转成可验证、可筛选、
   可导出的 semantic event stream。这个贡献在 RTL 和验证路径上，而不是简单
   替换 ISA。

2. 事件抽象不同

   NCScope 主要从 ETM resolved instruction/control-flow trace 加 eBPF log
   重建 native behavior。RV-MalTrace 的 MVP 不追求完整 instruction trace，
   而是选择 syscall/control-flow/trap/context 这些更接近 malware behavior
   semantics 的 committed events。

3. 扰动边界不同

   NCScope 的语义采集依赖 software probes。RV-MalTrace 的主叙事必须坚持
   RTL sideband、不反压 core、trace-on/no-trace parity、drop accounting。
   如果后续使用 eBPF/helper，也必须写成 semantic enrichment 或 comparison，
   不能替代硬件 trace 贡献。

4. 评估证据不同

   NCScope 的评估是 Android app native behavior analysis。RV-MalTrace 需要
   RISC-V/CVA6 simulation、trace-enabled FPGA resource/timing、physical board
   trace、Linux syscall alignment、semantic recovery、overhead 和 evasion
   comparison。

5. 论文新意位置不同

   NCScope 的新意是“ETM + Android native semantic probes”。我们的新意应是
   “RISC-V committed hardware behavior trace + semantic reconstruction +
   low-perturbation evidence”。

## 可以借鉴 NCScope 的地方

NCScope 对我们有参考价值，但参考点应该放在分析 pipeline 和评估设计，不是
照搬实现。

| NCScope 思路 | 可以如何迁移到 RV-MalTrace |
| --- | --- |
| 控制流 trace 与语义 log 分离 | 保持 hardware event trace 与 semantic enrichment 分层；JSONL 是稳定边界 |
| memory map 辅助地址解释 | Linux/ELF/objdump annotation、symbol map、loaded module map 可作为后续解析层 |
| eBPF 读取字符串和参数 | 作为 fallback/helper baseline；用于比较 hardware-only、hardware+helper、eBPF-only |
| anti-analysis behavior taxonomy | 迁移到 RISC-V Linux malware-like suite：ptrace/proc/timing/direct syscall/packed code |
| performance comparison | 设计 `strace`、eBPF-only、QEMU plugin、software instrumentation baseline |
| offline symbolic/semantic analysis | 后续 behavior graph、taint/slice、case study 可以借鉴其离线分析组织方式 |

## 不能直接复用 NCScope 的地方

1. 不能复用 ETM/DS-5 pipeline

   RISC-V/CVA6 没有 ARM ETM/CoreSight 这条现成路径。我们的 trace source 是
   `rtl/trace/` 和 CVA6 integration，不是 DS-5 decode。

2. 不能把 eBPF 当成核心贡献

   如果 RISC-V Linux 上直接使用 eBPF hook syscall/library，那么贡献会退化成
   software tracing。eBPF 只能是 comparison、helper 或 semantic enrichment。

3. 不能把 Android native taxonomy 原样搬到 Linux

   Android ART/JNI、oat、libart、Android property 的语义不等价于 RISC-V Linux
   userland。我们需要 Linux syscall、fd/path/process、mmap/mprotect、procfs、
   timing 和 direct syscall 行为模型。

4. 不能复用 NCScope 的低扰动结论

   我们必须用自己的 trace-on/no-trace parity、resource/timing delta、runtime
   overhead、drop rate 和 board evidence 支撑低扰动。

5. 不能用 NCScope dataset 直接证明 RISC-V malware tracing

   NCScope 的 finance/malware Android apps 不等价于 RISC-V Linux workload。
   我们需要 controlled malware-like RISC-V native programs，以及后续合法、
   可隔离的真实样本策略。

## 当前已有证据

截至 2026-05-17，`uv run rvmt sim:cva6-full-soc` 已经跑通，`uv run rvmt
sim:summary` 报告本地 Vivado simulation summary 为：

```text
overall: PASS
```

当前已有证据包括：

- Trace-unit synthetic tests 覆盖并通过 retire、branch、jump、ecall、
  syscall return pairing、trap、CSR/SATP/context、filter controls、drop
  accounting，以及 board-minimal event profile。
- `pointer_string` 和 `pointer_guardrails` 作为 default-disabled synthetic
  `ARG_MEM` 测试已通过，覆盖 null-terminated string capture、
  page-boundary continuity、max-length limiting、multi-byte load clipping、
  watch timeout 和 unrelated S-mode load rejection。
- CVA6 RVFI adapter unit test 已通过，覆盖 dual commit ports、U-mode syscall
  entry/return correlation、non-ECALL trap、compressed control flow，以及
  RV64 C.ADDIW non-jump case。
- Direct-core CVA6 xsim 已通过 smoke、branch、jump、machine-mode ecall as
  trap、illegal instruction trap、ebreak 等用例。这些用例包含
  trace-enabled 与 no-trace final-state parity。
- Full CVA6 `ariane_testharness` xsim probe 已通过
  `uv run rvmt sim:cva6-full-soc`。该 probe 编译/elaborate full SoC，从 DRAM
  `0x8000_0000` boot，观测 breakpoint trap，并发布
  `results/vivado_sim/cva6_full_soc_smoke/` artifacts。
- Python checker 和 synthetic behavior recovery self-test 在
  `docs/07-evaluation-evidence/reports/sim_results.md` 中记录为 PASS。
- Genesys 2 baseline 的 repository-local preflight 已有 board files、
  routed baseline bitstream、route/timing reports、DDR/clock IP artifacts 和
  UART source path 证据。

这些说明：当前仓库已经有较扎实的 simulation baseline，包括 full SoC xsim
probe。但这些证据仍不能外推成 physical board、Linux workload 或 malware
analysis 完成。

## 当前仍缺什么

### 1. Production CVA6 RTL integration 仍是 partial

目前部分 Phase 1 结论通过 RVFI/direct-core 或 synthetic path 验证，还不是最终
production raw CVA6 commit/CSR/LSU 内部信号 plumbing。

仍然 open 的点包括：

- 非 verification path 下直接暴露 committed instruction bits。
- 完整 watched CSR address/value plumbing。
- direct-core CSR/SATP program coverage 仍需超过 synthetic semantics。
- 用真实 CVA6 LSU load address/data 接入 pointer snapshot。
- 最终非 RVFI trace hook integration claim。

这不否定当前 MVP 的 simulation evidence，但限制了 production RTL integration
可以声称的范围。

### 2. Full SoC store/tohost path 已拆分验证

`sim:cva6-full-soc` 已经 PASS，但它是 breakpoint-terminated smoke。之前使用
UART/MMIO pseudo-tohost store 作为 completion gate 时，Vivado v2025.2 full SoC
路径会卡在 store 提交前后。后续 `sim:cva6-full-soc-store` 已经把最小
UART/MMIO store-path observation 从 TODO 推到 PASS；`sim:cva6-full-soc-tohost`
现在也通过普通 completion path 观察 committed tohost/MMIO store，不再依赖
`RVMT_STORE_PATH_ONLY` shortcut。

因此当前可以声称：

- PASS：full SoC compile/elaboration/DRAM boot/breakpoint trap probe。
- PASS：full SoC UART/MMIO store-path observation。
- PASS：full SoC normal tohost/MMIO completion path。
- PASS：direct-core tohost-store matrix。

这一区分很重要：full SoC xsim 支持已修复，但这些仍是 repository-local
simulation evidence，不是 physical board peripheral validation evidence。

### 3. Trace-enabled FPGA resource/timing delta 已记录，但仍不是板上证据

仓库已有 Genesys 2 baseline routed bitstream evidence，也已经记录 trace logic
后的 trace-enabled implementation delta。

已记录的具体指标包括：

- LUT delta。
- FF delta。
- BRAM delta。
- Fmax 或 slack delta。
- trace logic 对 routed timing 的影响。

所以当前 resource story 只能写成：

- PASS：baseline routed snapshot、trace-enabled implementation delta 和
  simulation drop accounting。
- TODO：board runtime overhead、trace bandwidth 和 physical trace export
  measurement。

### 4. 物理板证据缺失

Board 文档仍要求以下 physical artifacts：

- clock/reset sanity。
- UART hello。
- CVA6 bare-metal board boot。
- 第一版 trace export path 的 board trace dump。
- decoded board trace JSONL。
- board expected output comparison。

现有 baseline bitstream 和 route/timing report 是 repository-local build
evidence，不等于真实板上 observation。

### 5. Linux workload 证据缺失

Linux 仍是后续 gate。当前缺少：

- RISC-V Linux userland compiler version lock。
- Linux 或 Buildroot boot evidence。
- benign workload traces。
- malware-like synthetic workload traces。
- `strace` 或等价 ground truth runs。
- hardware trace 与 Linux syscall 的 alignment report。

在这些 artifact 存在之前，RV-MalTrace 只能声称 simulation-level syscall
semantics，不能声称 Linux malware behavior tracing 已完成。

### 6. Semantic recovery 仍停在 synthetic 级别

项目已经有有价值的 synthetic semantic recovery 和 pointer snapshot 测试。但
论文级证据需要来自真实 Linux workload 的恢复结果。

还缺：

- 每个 workload 的 `semantic_events.json`。
- 每个 workload 的 `behavior_graph.json`。
- 带 mismatch 和 assumption 的 `recovery_report.md`。
- 从真实 trace 推导出来的 fd/path/process relationship。
- 通过真实 CVA6/Linux LSU 或明确 helper 路线恢复的 pointer strings。

`ARG_MEM` synthetic PASS 很重要，但不能被写成 Linux path recovery PASS。

### 7. Evaluation baselines 还没有完成

`docs/07-evaluation-evidence/evaluation_plan.md` 中的 paper baselines 和 RQs 仍是 TODO。

缺少的 baseline artifacts 包括：

- `strace` / `ptrace` comparison runs。
- eBPF-only comparison，前提是 kernel support 存在。
- QEMU plugin comparison。
- software instrumentation comparison。
- event-only、pointer snapshot、helper/eBPF companion ablation。
- overhead、perturbation、drop-rate、bandwidth measurements。
- evasion-resistance case outcomes。

这是当前工程 MVP 与 paper-ready system 之间最大的差距。

### 8. Dataset manifests 还是计划，不是实验结果

Benign 和 malware-like workload manifests 已存在，但 row 状态仍是
`TODO(EXPERIMENT)`。

每个样例还需要：

- build evidence。
- behavior ground truth。
- simulation、board 或 Linux trace。
- semantic recovery output。
- audit report。

真实恶意样本不应该进入早期成功标准，除非 containment、provenance、legal 和
ethics procedure 都已经写清楚并可执行。

## 推荐论文叙事

### 不推荐

```text
We implement NCScope on RISC-V.
```

这个说法太弱，也不准确。它会让审稿人期待 ETM-like instruction trace +
eBPF semantic probes 的直接移植，而我们的核心工作其实在 CVA6 RTL committed
event tracing。

### 推荐

```text
RV-MalScope is a low-perturbation committed-event tracing system for
RISC-V/CVA6. Unlike ARM ETM-based Android native-code systems such as
NCScope, RV-MalScope builds the tracing substrate in the open CVA6 RTL,
emits selective architectural behavior events, and reconstructs syscall,
control-flow, trap, context, and pointer semantics offline.
```

中文表述可以写成：

```text
NCScope 证明了硬件执行轨迹结合语义日志可用于 native malware behavior
analysis；RV-MalScope 进一步面向开源 RISC-V/CVA6，把低扰动行为观测能力
下沉到 RTL committed-event trace，并以 syscall/control-flow/trap/context
事件恢复跨 ISA 的恶意行为语义。
```

## 与 NCScope 对齐的评估问题

为了和 NCScope 有可比性，但不被限定成移植工作，评估可以这样组织：

1. Correctness

   - 我们是否准确捕获 committed syscall/control-flow/trap/context events？
   - 证据：`sim:trace-unit`、`sim:cva6-smoke`、`sim:cva6-full-soc`、
     JSONL golden comparison。

2. Semantic reconstruction

   - 是否能恢复 syscall arguments、return values、fd/path/process behavior？
   - 证据：controlled Linux workloads、`semantic_events.json`、
     `behavior_graph.json`、`recovery_report.md`。

3. Low perturbation

   - 相比 `strace`、eBPF-only、QEMU plugin、software instrumentation，runtime
     overhead、trace volume、drop rate、detectability 如何？
   - 证据：paired runs、resource/timing reports、drop accounting。

4. Evasion resistance

   - anti-debug、timing check、direct syscall、packed code、mmap/mprotect executable
     memory、fork/exec chain 是否比 software tracing 更难绕过？
   - 证据：controlled malware-like suite 和 per-sample audit。

5. Hardware cost

   - CVA6 trace tap 的 LUT/FF/BRAM/Fmax 成本是多少？
   - 证据：baseline vs trace-enabled FPGA implementation reports。

6. Usefulness

   - 生成的 behavior graph 是否足够支持手动审计或规则匹配？
   - 证据：case studies、audit report、mismatch analysis。

## 建议下一步顺序

1. 先把 full SoC breakpoint、UART/MMIO store-path 和 normal tohost/MMIO
   completion PASS 状态保持稳定。
2. 补齐仍隐藏在 RVFI/direct-core 或 synthetic path 后面的 production CVA6 signal
   plumbing gap。
3. 继续维护已记录的 trace-enabled FPGA implementation resource/timing delta，
   后续只在 synthesis artifact 变化时更新。
4. 收集 physical board baseline evidence：clock/reset、UART、CVA6 bare-metal boot。
5. 启动第一版 board trace export，使用 minimal profile：syscall、trap、context、
   branch、drop；默认关闭 full retire 和 full memory trace。
6. 跑 board trace validation programs，并将 decoded JSONL 与
   `board/trace_validation/expected` 对比。
7. 只有在 board trace evidence 存在后，再推进 Linux workloads 和 `strace`
   alignment。
8. 把 semantic recovery 从 synthetic proof 推进到 per-workload
   `semantic_events.json`、`behavior_graph.json`、`recovery_report.md`。
9. 最后补 paper-level ablation 和 comparison baselines。

这个顺序可以保留当前 simulation PASS 的价值，同时避免对 board、Linux 或
malware-analysis completeness 做没有证据支撑的外推。
