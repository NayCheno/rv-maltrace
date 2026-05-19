# RV-MalTrace 两周计划复核与下一步建议

## 结论

基于当前 `main` 分支的文档和代码审阅，而不是我本地重新跑 Vivado/xsim 或上板测试：

| 问题 | 判断 |
| --- | --- |
| two-week-plan 是否做完 | 仿真 MVP 基本完成；论文级/上板/Linux/malware 评估没有完成。计划中“软件模拟可验证的 RISC-V/CVA6 malware behavior tracing MVP”已经有较完整证据链，但 board、Linux workload、真实 malware、安全隔离、baseline 对比仍是后续 gate。 |
| 目前模拟的 SoC 是否正确 | 局部正确，不可外推为完整 SoC 正确。direct-core CVA6 和 trace-unit 回归很强；full SoC 已有 breakpoint smoke 与 UART/MMIO store-path observation PASS。但 normal full-SoC multi-instruction tohost completion、Linux boot、physical board 都还不能声称正确。 |
| 没有板子测试时能否声称硬件正确 | 不能。当前 board 文档明确说 clock/reset、UART hello、bare-metal runtime 都是 `TODO(BOARD)`；现有 bitstream、route/timing、preflight 只能算 repository-local Vivado evidence。 |
| malware 是否检测准确 | 目前不能声称检测准确率。仓库已有 synthetic malware-like manifest、semantic recovery、rule-based audit，但这些都显式保持 `TODO(EXPERIMENT)` 或标明不是 malware detection quality evidence。 |
| 下一步主线 | 先做“可视化可审计 demo + Linux/QEMU/strace ground truth + board bring-up”，再做 QEMU/Spike/strace/eBPF/QEMU-plugin 对比，最后做 RISC-V vs x86 行为语义对比。 |

## 1. `docs/` 当前状态

### 1.1 文档体系已经比较完整

仓库定位清楚：当前核心是 CVA6/RISC-V committed-event trace MVP，目标是采集 sideband committed execution trace、与 golden JSONL 比对，并把 board/Linux claim 放在 evidence gates 后面。`README.md` 还明确要求 trace sink 不得 backpressure CVA6，带宽不足时要 drop record 并输出/count `EVT_DROP`。

主要文档状态如下：

| 文档/目录 | 状态 | 评价 |
| --- | --- | --- |
| `docs/planning/plan.md` | 完整 | 原始 phase 规划合理：Phase 0/1 仿真优先，Phase 4/5 上板，Phase 6/7 Linux 与 memory semantic enrichment 后置。 |
| `docs/planning/two-week-plan.md` | 很完整 | 已经把目标收敛到 simulation-verifiable MVP，并列出当前 PASS 与不能声称的边界。 |
| `docs/architecture/trace_format.md` | 完整 | Event schema 覆盖 `RETIRE`、`BRANCH`、`JUMP`、`SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`CSR`、`SATP`、`PRIV`、`ARG_MEM`、`DROP`、`MARKER`，并有 filter、compression、`ARG_MEM` 默认关闭策略。 |
| `docs/architecture/signal_map.md` | 较完整，但有 production gap | RVFI/direct-core signal path 写得清楚；但 CVA6 LSU hook、非 RVFI production plumbing 仍是后续工作。 |
| `docs/reports/sim_results.md` | 当前最关键证据 | `trace-unit`、RVFI adapter、direct-core CVA6、full-SoC smoke、full-SoC UART/MMIO store-path 均有 PASS 记录。 |
| `docs/board/board_bringup.md` | 口径正确 | 明确区分 repository-local Vivado evidence 与 physical board evidence；board runtime 仍 TODO。 |
| `docs/reports/resource_report.md` | 已有 trace-enabled delta | 已记录 Genesys 2 baseline vs trace-enabled routed utilization/timing delta。 |
| `docs/research/evaluation_plan.md` | 规划完整，但不是证据 | RQ1-RQ6、baselines、datasets、artifact gates 仍为 TODO；这是 research design，不是 evaluation result。 |
| `docs/validation/fuzz_trace_validation.md` | 计划和工具链有，实验未完成 | fuzz/stress 是 deterministic trace-invariant gate，不是 processor fuzzing claim；各 case 仍是 `TODO(SIM)` / `TODO(HARNESS)`。 |
| `docs/research/diff-22.md` | 有价值，但需要同步 | 对 NCScope 差异分析有用；但里面有些“store-path TODO / resource delta missing”的陈述已经落后于 `sim_results.md` 和 `resource_report.md`。 |

### 1.2 文档里最大的问题

`docs/research/diff-22.md` 有局部过期内容。

现在 `docs/reports/sim_results.md` 已经记录 full-SoC UART/MMIO store-path observation PASS，`docs/reports/resource_report.md` 也记录 trace-enabled FPGA delta；但 `docs/research/diff-22.md` 的“当前仍缺什么”部分仍保留了旧的 TODO 说法。建议把 `docs/research/diff-22.md` 改成：

已更新：

- full-SoC breakpoint smoke: PASS
- full-SoC UART/MMIO store-path observation: PASS
- trace-enabled Genesys 2 resource/timing delta: recorded

仍未完成：

- normal full-SoC multi-instruction tohost completion
- physical board clock/reset/UART/bare-metal runtime
- Linux workload trace
- real malware / paper-level evaluation

## 2. two-week-plan 完成度判断

### 2.1 已完成或基本完成的部分

| two-week-plan 目标 | 当前状态 | 判断 |
| --- | --- | --- |
| `sim:trace-unit` | PASS | 完成。覆盖 syscall return、pointer string、pointer guardrails、drop、filter、board minimal、RVFI adapter。 |
| direct-core CVA6 trace/no-trace parity | PASS | 完成。`sim:cva6-smoke` 要求 trace-enabled 与 no-trace 到达相同 tohost PASS。 |
| committed-only event correctness | 基本完成 | `RETIRE`、`BRANCH`、`JUMP`、`SYSCALL`、`TRAP`、`CSR`、`PRIV`、`DROP` 已有 synthetic + direct-core 证据。 |
| syscall entry/return correlation | PASS in synthetic/RVFI/direct-core | `SYSCALL_ENTRY` 只接受 U-mode ECALL；`SYSCALL_RET` 要 SRET-to-U + outstanding syscall。 |
| `ARG_MEM` pointer snapshot synthetic tests | PASS synthetic | `pointer_string` 和 `pointer_guardrails` PASS；但 CVA6 LSU real hook 仍后置。 |
| semantic recovery outputs | 工具有，self-test PASS | `recover_behavior.py` 可以从 trace 生成 syscall sequence、control-flow、trap/context、privilege boundary、behavior graph。 |
| resource/timing/drop report | 完成 | 已记录 trace-enabled delta：LUT +40,794、FF +2,810、BRAM/DSP 不变、slack/Fmax 未变。 |
| board go/no-go checklist | 完成文档，不是实机 | board bring-up、trace minimal policy、trace export decision 都已有。 |

### 2.2 没有完成的部分

| 缺口 | 为什么重要 |
| --- | --- |
| normal full-SoC multi-instruction tohost completion | 现在 full-SoC 有 breakpoint smoke 和两指令 UART/MMIO store-path observation，但还不是普通较长程序完整跑完。risk log 明确把这点列为 open。 |
| production CVA6 raw signal plumbing | 当前大量证据来自 RVFI/direct-core/synthetic path；非 RVFI production integration 还不能强 claim。 |
| CVA6 LSU real hook for `ARG_MEM` | pointer snapshot 目前是 synthetic；Linux syscall pointer recovery 还未在真实 CVA6 LSU/Linux 上证明。 |
| physical board evidence | clock/reset、UART、bare-metal runtime 均为 `TODO(BOARD)`。 |
| Linux workload trace | evaluation plan 中 Linux syscall trace、semantic reconstruction、case studies 仍 TODO。 |
| malware detection accuracy | synthetic manifest/audit rule 存在，但 status 是 `TODO(EXPERIMENT)`，工具也明确不是 malware detection quality evidence。 |
| fuzz/stress 实验本体 | fuzz plan 和工具存在，但 case 仍是 TODO。 |

判断：two-week-plan 的“仿真闭环 MVP”可以说基本达成；但如果把 two-week-plan 理解成“上板 + Linux + malware 检测准确率 + paper-level evaluation”，则还远未完成。

## 3. 目前模拟的 SoC 是否正确

### 3.1 可以肯定的部分

当前 simulation evidence 很强，尤其是：

- `trace-unit` 覆盖了 synthetic event correctness，包括 syscall return、`ARG_MEM` pointer snapshot、drop/filter 等。
- `cva6_*` direct-core matrix 通过真实 CVA6 committed RVFI events，并且 trace/no-trace final result 要一致。
- full `ariane_testharness` 已经能 compile/elaborate，从 DRAM boot，并在 breakpoint smoke 中观察到预期 breakpoint trap。
- full-SoC UART/MMIO store-path gate 已经观察到 committed RVFI store 到 `0x10000000`。

所以可以写：

```text
Current simulation evidence supports the correctness of the committed-event trace MVP
under synthetic, direct-core CVA6, and short full-SoC probe settings.
```

### 3.2 不能写的部分

不能写：

```text
The SoC is fully validated.
The board works.
Linux syscall tracing works.
Malware behavior detection is validated.
```

原因是：

- board physical clock/reset/UART/bare-metal 均未做。
- evaluation plan 明确所有 paper-level gates 仍是 TODO。
- risk log 仍把 normal full-SoC multi-instruction tohost completion、production RTL integration、memory semantics、real malware 等列为 open。

### 3.3 建议补的 SoC correctness gates

优先补这 6 个：

| Gate | 目的 |
| --- | --- |
| `cva6_full_soc_tohost_normal` | 不用 breakpoint，只用普通 multi-instruction program 写 tohost/MMIO 完成。 |
| `cva6_jalr_target` | 当前 jump program 主要证明 JAL；需要明确证明 JALR target。 |
| `cva6_compressed_branch` | C extension 下 sequential PC 是 `pc+2`，不能误用 `pc+4`。 |
| `cva6_s_ecall_trap_only` | S/M-mode ECALL 不能被当成 Linux syscall entry。 |
| `cva6_sret_not_to_user` | 普通 SRET 不能误配成 syscall return。 |
| `cva6_arg_shadow_same_cycle` | 多 commit port / 同周期 `a0-a7` 更新与 ECALL 的一致性。 |

## 4. malware 检测准确吗

### 4.1 当前不能声称准确率

当前更准确的说法是：

```text
RV-MalTrace currently supports synthetic behavior recovery and rule-based behavior audit.
It does not yet provide validated malware detection accuracy.
```

仓库已有 malware-like synthetic manifest，包含 file scan、batch open/read/write、self-copy simulation、abnormal syscall sequence、illegal trap、process chain、dynamic executable memory、anti-debug-like 等样例；但它们都标记为 `TODO(EXPERIMENT)`，并且 `real_malware=false`。

`behavior_audit_rules.json` 定义了 rule-based audit，例如 file discovery、collection/staging、dropper-like、anti-analysis、memory permission 等，但同时把 “real malware execution”、“malware detection quality claim”、“classifier accuracy claim” 列为 non-goals。

`audit_behavior.py` 的输出也明确说这是 synthetic behavior triage，不是 malware detection quality evidence。

### 4.2 应该如何量化准确率

后续要把“看到了 malware-like 行为”推进到“检测准确”，至少要有这几类指标：

| 层级 | 指标 |
| --- | --- |
| Event 层 | syscall precision/recall、trap precision/recall、branch/jump target accuracy |
| Argument 层 | scalar arg accuracy、return value accuracy、path string reconstruction accuracy |
| Graph 层 | fd graph accuracy、process graph accuracy、file/socket/memory node recovery accuracy |
| Rule 层 | rule-level TP/FP/FN/TN |
| Sample 层 | benign vs malware-like confusion matrix |
| Robustness 层 | anti-debug、timing、direct syscall、mmap/mprotect、packed-code case outcome |
| Perturbation 层 | runtime overhead、trace volume、drop rate、detectability |

最小实验矩阵：

```text
benign samples:
  hello, cat, cp, sha256sum, small network client

malware-like samples:
  file_scan
  batch_open_read_write
  self_copy_sim
  abnormal_syscall_sequence
  illegal_trap
  process_chain
  dynamic_executable_memory
  anti_debug_like
```

每个样例都需要：

- source hash
- ELF hash
- input fixture hash
- strace/QEMU ground truth
- RV-MalTrace `trace.jsonl`
- `semantic_events.json`
- `behavior_graph.json`
- `behavior_audit.json`
- `behavior_audit_report.md`
- manual mismatch notes

## 5. 下一步：怎么更直观看到 malware 被检测到

现在最缺的不是再加一个 event，而是 demo 可视化和 evidence bundle。

### 5.1 建议新增 demo 输出目录

对每个 sample 生成：

```text
results/demo/<run-id>/<sample-id>/
  00_build/
    source.sha256
    elf.sha256
    compiler.txt
  01_ground_truth/
    qemu.log
    strace.log
    expected_behavior.json
  02_trace/
    trace.jsonl
    trace.disasm.jsonl
    compare.log
  03_semantic/
    semantic_events.json
    behavior_graph.json
    recovery_report.md
  04_audit/
    behavior_audit.json
    behavior_audit_report.md
  05_visual/
    timeline.html
    graph.html
    scorecard.md
```

### 5.2 建议加一个统一命令

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend sim
```

内部执行：

```powershell
uv run python tools/recover_behavior.py ^
  --trace results/demo/<run>/<sample>/02_trace/trace.jsonl ^
  --out-dir results/demo/<run>/<sample>/03_semantic

uv run python tools/audit_behavior.py ^
  --semantic results/demo/<run>/<sample>/03_semantic/semantic_events.json ^
  --graph results/demo/<run>/<sample>/03_semantic/behavior_graph.json ^
  --manifest experiments/linux_behavior/malware_like/manifest.json ^
  --sample-id anti_debug_like ^
  --out-dir results/demo/<run>/<sample>/04_audit
```

### 5.3 `scorecard.md` 应该长这样

```markdown
# RV-MalTrace Behavior Audit Scorecard

Sample: anti_debug_like
Class: malware_like_synthetic
Real malware: false

## Observed behavior

- clock_gettime: observed
- ptrace: observed
- openat/read /proc-like status path: observed if pointer recovery is available

## Matched rules

| Rule | Family | Matched | Evidence |
| --- | --- | ---: | --- |
| anti_analysis_indicator | anti_analysis | yes | ptrace or clock_gettime syscall shape |

## Non-claim

This is a synthetic behavior audit result, not real malware detection accuracy.
```

这里不要写：

```text
malware detected: yes
```

更严谨的展示语句是：

```text
Matched malware-like behavior rule: anti_analysis_indicator
```

等 benign/malware-like confusion matrix 做完后，再升级成：

```text
Detection result: suspicious / benign / inconclusive
```

### 5.4 最直观的可视化

建议做三张图：

| 图 | 内容 | 用途 |
| --- | --- | --- |
| `timeline.html` | cycle/time 横轴；syscall/trap/context/branch 事件分层展示 | 一眼看到 syscall/trap 序列 |
| `behavior_graph.html` | Process/File/Socket/MemoryRegion/Syscall 节点和边 | 一眼看到行为图 |
| `audit_scorecard.md/html` | 规则、证据、matched/missing | 一眼看到为何命中 |

最小图形结构：

```text
Process(sample)
 ├── openat -> File(...)
 ├── read   -> File(...)
 ├── ptrace -> AntiAnalysis
 ├── clock_gettime -> TimingCheck
 └── mmap + mprotect(PROT_EXEC) -> ExecutableMemory
```

## 6. 优化手段

### 6.1 RTL / trace 侧优化

当前 trace-enabled resource delta 里，LUT 增量是 +40,794 / +48.04%，FF 增量是 +2,810 / +4.97%，BRAM/DSP 不变，timing slack 没变。这个结果说明 timing 暂时不坏，但 LUT overhead 明显偏高。

优先优化：

| 优化 | 说明 |
| --- | --- |
| event-specific packet | 不要所有 event 都携带超大统一 packet；syscall/trap/context/drop 分开编码。 |
| board minimal profile 默认开启 | 上板默认只开 syscall/trap/context/branch/drop；retire/jump/marker 关闭。现有文档已这样设计。 |
| PC range filter / privilege filter | 只 trace 用户态目标进程或目标地址段，避免 kernel noise。 |
| `cycle_delta` / `pc_delta` compression | `trace_format.md` 已有 compressed trace prototype，下一步应从 JSON prototype 推到 binary packet。 |
| drop-first, no-backpressure | 保持 drop accounting，不让 trace sink 反压 core。`README.md` 已明确这是 evidence policy。 |
| branch/jump 可配置关闭 | malware behavior demo 初期只需 syscall/trap/context；control-flow 可以作为高开销模式。 |
| `ARG_MEM` scoped only | 只在 openat/execve/connect/mprotect 等需要 pointer semantic 的 syscall 期间打开 watch。 |

### 6.2 导出路径优化

当前第一版 board export 选择 BRAM ring buffer + ILA/JTAG dump，这是正确 bring-up 选择，但不是最终高吞吐方案。UART 与 AXI DMA/Ethernet 被推迟。

推荐路线：

```text
Bring-up:
  BRAM ring + ILA/JTAG

Small demo:
  BRAM ring + compact packet + host decoder

Long workload:
  AXI-Stream FIFO -> AXI DMA -> DDR trace buffer -> host dump

Low-bandwidth syscall-only:
  UART compact stream, with drop accounting
```

### 6.3 分析侧优化

| 优化 | 目标 |
| --- | --- |
| `syscall_id`/`context_id` 索引 | 快速关联 entry/return |
| fd table incremental reconstruction | 更直观恢复 file graph |
| path/string cache | 避免重复 `ARG_MEM` 解析 |
| behavior graph streaming update | 长 trace 不必一次性加载 |
| audit rule explainability | 每个命中都给出 syscall、arg、return、cycle 范围 |
| graph diff | 对比 RV-MalTrace vs strace/QEMU 的行为差异 |

## 7. 和 QEMU、Spike、strace/eBPF 怎么比性能

### 7.1 不要把所有东西放在一个“速度排名”里

这些工具层级不同：

| 工具 | 正确用途 | 不适合拿来直接比较的点 |
| --- | --- | --- |
| Spike | RISC-V ISA functional oracle；适合 bare-metal 指令/异常/寄存器结果对齐 | 不是 full SoC/peripheral/Linux behavior tracing baseline |
| QEMU | 快速 user-mode/system-mode emulation；适合 Linux workload、QEMU plugin、行为 ground truth | 不是真实硬件，也不是 cycle-accurate CVA6 |
| Vivado xsim | RTL correctness evidence | wall-clock 非常慢，不适合作为 malware runtime performance baseline |
| FPGA RV-MalTrace | 低扰动 hardware trace 的核心性能证据 | 现在还没 physical board evidence |
| strace/ptrace | syscall semantic ground truth 和软件扰动 baseline | 本身会 perturb 程序，不能作为 uninstrumented performance |
| eBPF-only | software semantic enrichment baseline | 威胁模型不同，kernel trusted |

QEMU 官方文档说明 QEMU 是 dynamic translator，TCG 会把 guest code 转换到 host instruction set，并使用 TB/direct block chaining 等机制提升性能。Spike 官方仓库说明 Spike 是 RISC-V ISA Simulator，实现一个或多个 RISC-V hart 的 functional model，并支持多种 RISC-V ISA extension。

### 7.2 建议性能对比矩阵

| Backend | 运行对象 | 输出 | 指标 |
| --- | --- | --- | --- |
| native x86 Linux | x86_64 同源 C workload | baseline log | wall-clock、syscall count |
| native x86 + strace | x86_64 workload | strace log | overhead、syscall ground truth |
| QEMU user-mode RISC-V | riscv64 ELF | qemu log / strace-like log | wall-clock、syscall behavior |
| QEMU system-mode RISC-V | riscv64 Linux/rootfs | system log | boot/runtime、syscall behavior |
| QEMU plugin | riscv64 workload | plugin trace | trace volume、overhead |
| Spike | bare-metal RISC-V | ISA trace/final state | instruction/trap correctness |
| Vivado xsim direct-core | bare-metal CVA6 | `trace.jsonl` | event correctness |
| Vivado xsim full-SoC | short SoC program | `trace.jsonl` | SoC smoke/store correctness |
| FPGA RV-MalTrace | bare-metal/Linux | hardware trace | runtime overhead、drop rate、trace bandwidth |

### 7.3 公平测量规则

每个 workload 固定：

- same source
- same input fixture
- same compiler flags where possible
- same output correctness check
- same run count
- same host machine
- same CPU governor / pinned cores if on host

报告分开写：

```text
Functional correctness:
  RV-MalTrace trace vs golden / Spike / QEMU / strace

Runtime:
  uninstrumented QEMU/native
  QEMU + plugin
  strace/ptrace
  eBPF-only
  FPGA trace-on vs trace-off, once board exists

Trace cost:
  bytes/event
  bytes/syscall
  dropped events
  queue occupancy
  LUT/FF/BRAM/Fmax
```

不要把 Vivado xsim wall-clock 和 QEMU wall-clock 当成同类“系统性能”比较。xsim 主要是 RTL correctness gate；QEMU 是 emulator runtime baseline；FPGA 才是 hardware-trace runtime baseline。

## 8. RISC-V 和 x86 差异对比怎么做

### 8.1 不比较 raw instruction，比较行为语义

论文里不要写：

```text
x86 has more instructions; RISC-V has fewer instructions.
```

这对 malware behavior tracing 没有说服力。

应该比较：

```text
same behavior family
same source workload
different ISA/ABI/backend
normalized behavior graph
```

也就是：

```text
file_scan.c
  -> riscv64-linux ELF -> RV-MalTrace/QEMU/Spike
  -> x86_64-linux ELF  -> native/strace/perf/Intel PT if available
  -> compare behavior graph, not raw instruction trace
```

Intel 官方软件开发手册覆盖 Intel 64 和 IA-32 的 architecture/programming environment、instruction set reference、system programming、debugging、performance monitoring 等内容，可作为 x86 ABI/系统行为对比的底层参考。

### 8.2 对比维度

| 维度 | RISC-V/CVA6 | x86_64 |
| --- | --- | --- |
| syscall ABI | Linux RISC-V 常用 `a7` 放 syscall number，`a0-a5` 放参数，`a0` 放返回值 | Linux x86_64 常用 `rax` syscall number，`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` 参数，`rax` 返回值 |
| privilege transition | U/S/M，ECALL/SRET 是重点 | ring0/ring3，syscall/sysret/int80/iret 等路径 |
| hardware trace source | 自己在 CVA6 RTL 做 committed-event trace | 可用 Intel PT/LBR/perf 等现成机制，但 CPU RTL 不开放 |
| control-flow complexity | RISC-V + C extension，JAL/JALR/branch | x86 variable-length instruction、legacy modes、复杂 decode |
| anti-analysis | ptrace/procfs/timing/rdcycle/rdtime/direct syscall | ptrace/procfs/timing/rdtsc/cpuid/debugger checks |
| 研究贡献位置 | trace substrate 本身是贡献 | 更偏 trace source 的使用和行为分析，不容易声称 CPU RTL 贡献 |

### 8.3 行为图归一化

定义统一 graph schema：

```json
{
  "nodes": [
    {"kind": "Process"},
    {"kind": "File"},
    {"kind": "Socket"},
    {"kind": "MemoryRegion"},
    {"kind": "Syscall"},
    {"kind": "Trap"}
  ],
  "edges": [
    {"kind": "open"},
    {"kind": "read"},
    {"kind": "write"},
    {"kind": "exec"},
    {"kind": "fork"},
    {"kind": "mprotect_exec"},
    {"kind": "anti_debug"}
  ]
}
```

然后比较：

| 指标 | 含义 |
| --- | --- |
| graph node recall | RISC-V trace 是否恢复出 x86/strace ground truth 中的关键对象 |
| edge recall | open/read/write/exec/mprotect 等关系是否恢复 |
| syscall family match | 不要求 syscall 序列完全相同，要求行为 family 一致 |
| argument accuracy | path、fd、prot、sockaddr 等是否一致 |
| graph edit distance | 行为图差异大小 |
| false positive rate | benign workload 是否误命中 malware-like rule |

## 9. 立即建议做的 10 件事

按优先级：

1. 同步 `docs/research/diff-22.md`：把已完成的 full-SoC store-path 和 trace resource delta 从 TODO 改成 PASS/recorded，保留 normal full-SoC tohost、board、Linux、malware eval 缺口。
2. 新增 `demo:behavior` 命令：一键从 `trace.jsonl` 生成 `semantic_events.json`、`behavior_graph.json`、`behavior_audit.json`、timeline、graph、scorecard。
3. 新增 `render_behavior_timeline.py`：把 syscall/trap/context/drop 做成 HTML/SVG timeline。
4. 新增 `render_behavior_graph.py`：把 behavior graph 输出成 Graphviz/SVG/HTML。
5. 先做 3 个 demo sample：`anti_debug_like`、`dynamic_executable_memory`、`file_scan`。
6. 加入 QEMU/strace sanity path：对 malware-like C programs 先生成 RISC-V ELF，在 QEMU 下跑出 ground truth。
7. 补 `cva6_full_soc_tohost_normal`：新增 `uv run rvmt sim:cva6-full-soc-tohost`，用普通 completion path 单独验证 full SoC tohost/MMIO gate；当前 artifact 口径在观察到 committed tohost store 后可标 PASS，但仍只属于 repository-local simulation evidence。
8. 补 JALR/compressed/direct syscall regressions：特别是 `cva6_jalr_target`、`cva6_compressed_branch`、`s_ecall_trap_only`。
9. 把 `evaluation_plan` 的 RQ1 从 TODO 推到 SIM-PASS：但只在 artifact gate 满足后改，避免过度 claim。
10. 上板顺序不要跳：LED/clock/reset -> UART hello -> baseline CVA6 bare-metal -> trace BRAM/JTAG -> decoded board JSONL -> Linux。

## 最终判断

当前仓库已经不是空架子，仿真层面的 committed-event trace MVP 已经相当扎实。它的强项是：

- trace schema
- synthetic trace-unit
- direct-core CVA6 trace/no-trace parity
- short full-SoC probes
- semantic recovery tool
- rule-based synthetic audit framework
- resource/timing report
- board bring-up plan

但现在还不能把它写成：

```text
board validated malware detector
Linux malware behavior tracing system
measured accurate detector
full SoC production system
```

更稳的论文/项目表述是：

```text
RV-MalTrace has completed a simulation-validated RISC-V/CVA6 committed-event tracing MVP.
It currently supports derived semantic behavior recovery and synthetic rule-based behavior audit.
The next milestone is board-level trace export and Linux/QEMU/strace-aligned behavior evaluation.
```
