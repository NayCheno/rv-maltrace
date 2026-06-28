# RV-MalTrace 周会 slide 讲解文档

适用 slide：`RV-MalTrace_中文汇报版_2026-06-26`

目标：按当前 47 页 slide 顺序，给出一份可以在周会上讲出来的完整讲稿，同时把每个技术点背后的实现、数据通路、数据结构、捕获数据、判断标准和 claim 边界讲清楚。文末补充一页建议新增的 NCScope lineage backup slide 文案，用于同步到对应 Google Slides。

## 0. 总体讲法

这套 slide 的主线不是“我们做了一个 malware detector”，而是：

> RV-MalTrace 在受控 RISC-V Linux workload 上，把 CVA6/Genesys2 的硬件 trace、marker window gate、ELF/runtime context binding、semantic recovery 和 field-level provenance 串成一条可复查的语义重建证据链。

讲的时候始终保持三个层次：

1. 硬件到底捕到了什么：`MARKER`、`TRAP`、`SYSCALL_ENTRY`、`SYSCALL_RET`、`PRIV`、`ARG_MEM`、计数器、sequence、drop/wrap。
2. 离线分析怎么把低语义 trace 变成语义：marker gate 先筛窗口，再用 exact ELF 和 runtime process map 绑定 PC，最后恢复 syscall sequence、fd/path flow、behavior graph。
3. 哪些字段可以进入最终 claim，哪些只能作为 validation：`hardware`、`exact_elf`、`runtime_os_map` 可以支撑报告结论；`validation_oracle` 只能验证、对齐、解释，不能被说成硬件直接恢复。

建议开场先给出一句结论：

> 今天我要汇报的不是一个检测准确率实验，而是 RV-MalTrace 当前已经闭合的一条板级证据链：在 Genesys2/CVA6 上，我们用 marker 限定观测窗口，用 BRAM ring 捕获硬件事件，再通过 ELF 和 runtime process map 把低层 trace 绑定回 workload 语义，最后用 provenance 机制把 reportable evidence 和 oracle validation 分开。

然后用 slide 2 的路线组织全场：

1. 先讲问题和 claim 边界。
2. 再讲 capture/gate/bind/recover/report 的实现链条。
3. 再讲当前 board 结果。
4. 如果老师追问实现细节，跳到 deep-dive 页。
5. 最后用 non-claims 和下一步收口。

### 0.1 与 NCScope 的关系

如果需要解释 RV-MalTrace 最早的问题来源，可以把 NCScope 定位为“早期参考原型 / motivation lineage”，而不是当前实验的 baseline 或 evidence source。

建议讲法：

> RV-MalTrace 的问题意识受到 NCScope 这类硬件 trace 辅助 Android malware analysis 系统启发。NCScope 使用 Arm ETM、Android memory map 和 eBPF memory data，分析 Android native code 的 self-protection / anti-analysis 行为。RV-MalTrace 沿用了“硬件执行事实 + 离线上下文绑定 + 行为语义恢复”的思路，但平台、claim 和证据边界不同：当前系统面向 RISC-V Linux/CVA6/Genesys2，强调 marker-window gate、exact ELF/runtime process binding 和 field-level provenance。

讲的时候要明确三点边界：

1. NCScope 是 external reference，不是 RV-MalTrace 当前可直接运行的 real-malware sample set。
2. NCScope 的 Android ARM64 APK/native-library 数据不能直接作为 Artix-7 35T 或 Genesys2 RISC-V Linux 板级 evidence。
3. RV-MalTrace 当前 claim 是 controlled, provenance-checked semantic reconstruction，不是复现 NCScope 的 Android malware detection 结果。

## 1. 全局数据通路

可以在 slide 7 或 slide 8 前后用这段话解释全局 pipeline：

> 整个系统从一个受控 workload 开始。workload 通过特殊 marker syscall 标记 begin/end，不是为了告诉分析器答案，而是为了限定硬件采集窗口。CVA6 提交路径上的 RVFI 信号进入 `cva6_rvfi_trace_adapter.sv`，adapter 从 PC、instruction、privilege、trap cause、syscall argument register、SRET 返回、CSR/SATP、内存读取片段里生成 `trace_packet_t`。这些 packet 经过 filter 后进入 `trace_bram_ring.sv`，BRAM ring 把它们压成 `trace_compact_record_t`，同时维护 sequence、captured_count、dropped_count、wrap_count。板上读取出来的是 BRAM dump，主机脚本把 dump 解码成 `bram_records.jsonl` 和 `bram_summary.json`。只有 begin/end marker 完整、sequence 连续、drop/wrap 为 0、syscall entry/return 可配对的窗口，才进入后面的 semantic reconstruction。之后用 code map 和 runtime process map 把 PC 绑定到 ELF、symbol、process owner；再恢复 syscall sequence、fd/path graph、behavior graph；最后 provenance checker 把每个字段标成硬件、exact ELF、runtime map 或 validation oracle。

一条完整链路可以写成：

```text
controlled workload
  -> begin/end marker syscall
  -> CVA6 RVFI committed-event signals
  -> cva6_rvfi_trace_adapter.sv
  -> trace_packet_t
  -> trace filter / queue / DROP accounting
  -> trace_bram_ring.sv
  -> trace_compact_record_t in BRAM
  -> ILA/JTAG readout
  -> decode_genesys2_bram_ring_dump.py
  -> bram_records.jsonl + bram_summary.json
  -> marker-window gate
  -> exact ELF code map + runtime_process_map
  -> annotated events
  -> semantic_events.json + behavior_graph.json + fd_path graph
  -> semantic_provenance_summary.json
  -> reportable scoped claims
```

## 2. 关键数据结构

### 2.1 `trace_packet_t`

定义位置：`rtl/trace/trace_pkg.sv`

这是 RTL 内部的完整事件包。它的字段比 BRAM compact record 多，用来承载原始语义：

- `valid`：当前 packet 是否有效。
- `evt`：4-bit event type，如 `EVT_SYSCALL_ENTRY`、`EVT_ARG_MEM`、`EVT_MARKER`。
- `cycle`：trace 本地 cycle counter。
- `pc`、`instr`、`target`、`taken`：控制流和 syscall/trap 发生位置。
- `priv`、`old_priv`、`new_priv`：U/S/M privilege 变化。
- `satp`、`csr`、`value`：上下文切换和地址空间相关证据。
- `cause`、`tval`：trap 证据。
- `syscall_id`、`duration`：syscall entry/return 配对和耗时。
- `a0` 到 `a7`：syscall argument shadow registers。
- `arg_index`、`mem_base`、`mem_addr`、`mem_data`、`mem_size`、`mem_last`：`ARG_MEM` pointer snapshot 片段。

讲的时候要强调：硬件不是直接输出“open/read/write 行为图”，硬件输出的是这些低层事实。语义来自后续 join 和 recovery。

### 2.2 `trace_compact_record_t`

定义位置：`rtl/trace/trace_pkg.sv`

BRAM 空间有限，所以写入 BRAM 的不是完整 `trace_packet_t`，而是 compact record：

- `evt`：4-bit event type。
- `cycle`、`pc`：低 32 bit compact 字段。
- `primary`、`aux`：根据 event type 映射不同含义。
- `seq`：递增 sequence number，用于判断缺口。
- `mem_base_full`、`mem_addr_full`、`mem_data_full`、`syscall_id`、`arg_index`、`mem_size`、`mem_last`：v3 payload 中为 `ARG_MEM` 保留的完整 pointer snapshot 字段。

`primary/aux` 的解释要按 event type 来讲：

- `SYSCALL_ENTRY`：`primary` 是 syscall number，也就是 `a7`；`aux` 是 syscall id。
- `SYSCALL_RET`：`primary` 是 syscall id；`aux` 是 return value，也就是返回时的 `a0`。
- `TRAP`：`primary` 是 cause；`aux` 是 tval。
- `PRIV`：`primary/aux` 是 old/new privilege。
- `ARG_MEM`：`primary/aux` 是 compact 地址/数据，同时 v3 payload 有 full 64-bit base/address/data。
- `MARKER`：`primary` 是 marker value，如 `0xb0000a01` 或 `0xe0000a01`。

### 2.3 `bram_records.jsonl`

这是板上读取后的主机侧可审计记录。以 `hello_write/rep_01` 为例，记录中能看到：

- begin marker：`packed_primary = 0xb0000a01`，`sequence_number = 0`。
- `PRIV` 事件：U/S privilege 切换。
- `TRAP` 事件：U-mode ECALL trap，cause 为 8。
- `SYSCALL_ENTRY`：`a7 = 0x40`，即 RISC-V Linux `write`。
- `ARG_MEM`：例如 `mem_addr = 0x00010170`、`mem_data = 0x72`、`mem_size = 1`，这是用户指针片段，不是完整内存 dump。
- end marker：`packed_primary = 0xe0000a01`。
- 质量计数：`captured_count = 85`、`event_count = 85`、`dropped_count = 0`、`wrap_count = 0`。

这页可以讲成：

> Reviewer 不需要相信我们口头说“trace 是完整的”。每条记录都有 event type、sequence、cycle、PC、payload 和 BRAM 计数器。是否能作为证据，是后面的 gate 按这些字段检查出来的。

### 2.4 `runtime_process_map`

文档位置：`docs/10-process/runtime_process_map_v1.md`

这个结构用于回答“这个 PC 到底属于哪个进程”。关键字段：

- `pid`、`tgid`、`comm`、`exe`：目标进程身份。
- `owners`：按 `runner_parent`、`target_child`、`kernel`、`unknown` 组织的进程角色。
- `maps`：每个进程的 runtime memory map，包含 `start`、`end`、`perms`、`offset`、`inode`、`path`。
- `provenance`：采集方式和状态。
- `status`：只有 `/proc/<pid>/exe`、`comm`、`maps` 在 exec stop 时捕获完整，才算 `PASS`。

强 process attribution 需要同时满足：

- trace window 的 marker scope 是有效的；
- runtime process map 是 `PASS`；
- event PC 落在 target child 的 runtime map 中；
- event PC 又能匹配 target code map site。

### 2.5 `semantic_events.json`

由 `tools/recover_behavior.py` 或 summary 包装产出。主要结构：

- `syscall_sequence`：每个 syscall 的 `nr/name/args/return_value/duration/confidence`。
- `control_flow_segments`：branch/jump 片段。
- `trap_context_transitions`：TRAP/CSR/SATP/PRIV 事件。
- `privilege_boundaries`：syscall entry、syscall return、trap entry、privilege change。
- `marker_scope`：begin/end marker 是否有效。
- `code_map`、`runtime_process_map`：绑定来源摘要。

这部分是“恢复出来的语义”，但每个字段还要看 provenance，不能自动视为硬件 claim。

### 2.6 `behavior_graph.json`

由 `recover_behavior.py` 的 `build_graph` 生成，图结构很简单：

- 根节点：`trace`。
- syscall 节点：按顺序串起来，边为 `next_syscall`。
- control flow 节点：branch/jump。
- context 节点：trap/csr/satp/priv。
- privilege boundary 节点。

它不是完整 OS 行为图。它是从 trace-derived semantic events 中抽出来的行为摘要图。

### 2.7 `field_provenance`

由 `tools/package_genesys2_semantic_provenance.py` 生成并由 `tools/check_genesys2_semantic_provenance.py` 检查。允许标签只有：

- `hardware`
- `exact_elf`
- `runtime_os_map`
- `validation_oracle`

判断原则：

- `trace_source` 必须是 `hardware`。
- ELF、source line、code map 相关字段是 `exact_elf`。
- process owner、runtime mapping 相关字段是 `runtime_os_map`。
- qemu/strace、host/control 字符串、expected sequence、accuracy metric 是 `validation_oracle`。
- oracle-valued field 不能是 `hardware` only。
- full pointer string 不能被 claim 为硬件恢复。

## 3. 关键判断标准

### 3.1 marker-window acceptance

可以直接讲这个公式：

```text
accepted_window(run) :=
  begin_marker_present
  and end_marker_present
  and begin marker before end marker
  and sequence is continuous
  and wrap_count == 0
  and unaccounted_drop == 0
  and syscall entry/return is pairable when required
```

失败不会被删除，而是保留为 failure accounting。当前严格 board 口径是：

- P0 accepted：48 repetitions。
- Safe surrogate accepted：80 repetitions。
- Total accepted：128。
- Board attempts：142。
- Retained failed attempts：14。
- Accepted 窗口最大 drop/wrap/gap 都是 0。

注意：`drop_accounting_summary.json` 是无 drop/wrap 质量账本，`p0_bram_trace_summary.json` 是严格 P0 acceptance 口径。讲 128/142 时用严格 acceptance 口径。

### 3.2 pointer snapshot guardrail

硬件只支持受限 `ARG_MEM`：

- 只对 selected syscall pointer 开启：`openat`、`write`、`execve`。
- 只读 user pointer 范围，不读 kernel address。
- 有 max bytes 和 watch cycles 限制。
- 遇到 NUL 或达到 limit 时结束。
- 产物是 bounded prefix / fragments，不是完整内存 dump。

当前主线 artifact `hardware_pointer_prefix_summary.json`：

- `status = PASS`
- 30 个 BRAM pointer-snapshot repetitions
- 51 个 pointer groups
- 1156 captured bytes
- `hardware_pointer_strings_claimed = false`
- `full_string_claimed = false`
- `kernel_fragment_count = 0`

讲的时候可以说：

> 我们现在能报告的是硬件捕获到了 selected syscall user pointer 的 bounded prefix bytes。我们不能报告“硬件完整恢复了路径字符串”。完整字符串、路径名、host/control 或 qemu/strace 对齐字段，必须继续贴 `validation_oracle` 标签。

补充边界：

- 当前仓库还有一个单独的 `external_closure/hardware_pointer_strings_summary.json`，用于 scoped full hardware pointer-string closure。
- 这份 slide 的主线仍然按 bounded prefix 讲，不把 full string 混进 12 个 workload 的主语义重建 claim。
- 如果老师追问，可以说 full-string closure 是单独 artifact、单独 guardrail、单独 redaction/companion-substitution audit；它不等于 full memory dump，也不等于把 companion string 替代成硬件来源。

### 3.3 semantic reconstruction 判断

当前 summary 中 `semantic_reconstruction_summary.json` 是 `PASS`，但要按 provenance 讲：

- `expected_syscall_recall = 1.0`、`syscall_precision = 1.0` 等 accuracy 字段是 oracle 对齐指标。
- `trace_source` 是硬件。
- `semantic_source` 是 `trusted_qemu_guest_strace_companion_aligned_with_genesys2_trace`。
- field provenance 中，expected syscall、path accuracy、write buffer prefix 等是 `validation_oracle`。

因此正确表述是：

> 在 12 个受控 workload 上，硬件 trace 窗口和 companion oracle 对齐后，语义产物都生成并通过 provenance 检查；这支持 trace-backed controlled reconstruction，不支持 hardware-only full semantic recovery。

## 4. 逐页讲稿

### Slide 1. RV-MalTrace 封面

讲稿：

> 今天我汇报 RV-MalTrace 当前的中文汇报版。核心结论先放在第一页：我们不是在 claim 一个通用 malware detector，而是在受控 RISC-V Linux workload 上，闭合了一条可以复查的行为重建证据链。这个证据链的底座是 Genesys2/CVA6 板上的硬件 trace，核心机制是 marker-window gate、ELF 和 runtime context binding、semantic recovery，以及字段级 provenance。当前可复查的 artifact root 是 `results/evaluation/genesys2-cva6/current`。

实现解释：

- 这页不要展开太多细节，只要把“scope”和“artifact root”讲清楚。
- 如果老师问“是不是检测器”，回答：不是。当前 claim 是 controlled behavior reconstruction。
- 如果老师问“可复现在哪里”，回答：所有 summary、manifest、checker 都在 current evidence root，核心 checker 是 `uv run python tools/run_check_suite.py --suite genesys2-current`。

### Slide 2. 推荐讲解路线

讲稿：

> 我建议按 7 个方法步骤加 1 个结果边界来讲。先定义问题：软件观察者语义丰富但会干扰 workload；硬件 trace 独立但语义很低。然后讲我们怎么从硬件事实往上恢复语义：第一是采集，第二是 marker window 质量门控，第三是 context binding，第四是 semantic recovery，第五是 provenance 过滤，第六是结果和统计，第七是边界和下一步。最后强调 non-claim，避免把 validation oracle 讲成硬件结论。

实现解释：

- 这页是全场导航。讲完之后后面每页都回到“capture/gate/bind/recover/report”。
- 如果时间短，slide 3 到 13 讲问题和 claim，slide 14 到 33 讲实现，slide 34 到 47 讲结果和边界。

### Slide 3. 问题：为什么需要硬件辅助行为 trace

讲稿：

> 这一页先讲“为什么重要”，不要直接进入 trace 字段。关键不是多一种日志，而是建立一条 workload 难以感知、难以伪造、可被审查的 evidence path。软件 observer，比如 strace、eBPF、QEMU，优点是语义丰富，可以直接给 syscall、路径、进程、返回值和 expected order；但在 malware / adversarial workload 场景里，这些 observer 本身处在 workload 可感知、可影响的边界内，可能触发反调试、反沙箱、hook 绕过、observer effect，甚至让样本按是否被观察改变行为。所以 software-only path 的问题不是“没有信息”，而是最终证据的可信边界弱。
>
> 硬件辅助的重要性在于把证据来源下沉到处理器提交路径旁边：workload 不直接控制 trace packet 的生成、marker-window gate、drop/wrap 计数和 provenance 标注。这样后续不是声称“日志说发生了什么”，而是用 hardware trace 加 exact ELF/runtime map 说明“硬件实际提交了哪些事件”，再恢复成可审查的行为语义。RV-MalTrace 要解决的就是这个 gap：在不把 oracle 混进最终 claim 的前提下，把低层硬件事件通过 marker-window gate、ELF/runtime context binding、semantic recovery 和 field provenance 恢复成受控 workload 的可审查行为证据。
>
> 这里如果讲到 MARKER，要避免说成“约束硬件行为”。更准确的说法是：MARKER 只约束观测窗口，不约束硬件执行。begin/end marker 决定哪些硬件事件进入 final evidence path；窗口外事件不参与 claim。也就是说，它给低语义硬件事件加了一个可验证边界，而不是改变 workload 或处理器本身的执行。

实现解释：

- 软件 observer 在当前项目里主要作为 `validation_oracle`，用于确认 expected order、辅助解释和调试，不进入 final claim。
- 硬件辅助的核心价值是“证据独立性”和“可审查性”，不是更方便地打印日志。
- `MARKER` 的作用是定义 marker-bounded observation window；它是 trace gate / evidence scope，不是 hardware behavior constraint。
- 硬件事实来自 CVA6/RVFI、BRAM ring readout 和 marker-window gate；原始事件仍然低语义，所以后续必须做 context binding 和 semantic recovery。
- 后续 slide 4 到 slide 13 继续展开这页的问题：最终证据路径、语义 gap、claim/non-claim 和 provenance boundary。

### Slide 4. 问题模型：最终证据路径和 validation 路径分开

讲稿：

> 这一页要讲清楚两个通道。蓝色路径是最终能支持报告结论的路径：硬件 trace、exact ELF、runtime OS map。灰色或绿色路径是 validation oracle，比如 qemu/strace、host/control transcript，它可以帮助我们确认 expected order 或 companion strings，但不能替代硬件证据。最终 claim 只从蓝色路径和明确标注的 exact ELF/runtime map 来，oracle 字段必须被 provenance 拦住。

实现解释：

- `semantic_provenance_summary.json` 会记录 allowed labels。
- checker 会拒绝 oracle field 被标成 hardware-only。
- 最终报告字段与 validation-only 字段分离，是整个 deck 的安全阀。

### Slide 5. 挑战：硬件 trace 低语义

讲稿：

> 硬件 trace 的直接输出不是行为语义，而是一串事件。比如 `SYSCALL_ENTRY` 只是告诉我们某个 PC 触发了 ECALL，`a7` 是 syscall number，`a0-a7` 是寄存器值；`TRAP` 是 cause/tval；`ARG_MEM` 是某个用户指针附近的有限字节。要从这些字段变成“这个 workload open 了某个路径，然后 read/write/close”，必须有后处理：PC 绑定 ELF，process map 判断 ownership，syscall entry/return 配对，fd graph 更新，最后 provenance 过滤。

实现解释：

- RTL 侧只保证事件和计数可靠。
- 语义恢复由 `recover_behavior.py`、`recover_fd_path_flow.py`、package/checker 脚本完成。
- 不能在这页说硬件直接理解了路径或行为。

### Slide 6. 语义 gap：为什么必须引入 context binding

讲稿：

> 这里的 semantic gap 主要来自两个问题。第一，PC 本身不说明它属于哪个 binary，也不说明它属于 target child 还是 runner parent。第二，syscall 参数里如果是 pointer，硬件看到的是地址和有限字节，不自动等于完整字符串。因此我们必须引入 exact ELF code map 和 runtime OS map。ELF 解决“这个 PC 在哪个 section/symbol/source range”，runtime map 解决“这个地址在运行时属于哪个进程和加载对象”。

实现解释：

- `join_trace_code_map.py` 先做 static PC annotation，再用 runtime owner 判断 process attribution。
- 对 PIE/ASLR/dynamic libs/fork/exec，必须有 runtime map，不能只靠静态 ELF。
- 如果缺失 runtime evidence，就 downgrade 或 block，不强行 claim。

### Slide 7. 解决方案总览

讲稿：

> RV-MalTrace 的解法是把低层硬件事实和高层语义恢复拆成几个可检查阶段。硬件侧负责捕获 CVA6 committed-event trace，BRAM 侧负责保存 marker window 内的 compact records。主机侧先做 gate，保证窗口没有 drop、wrap、sequence gap；再做 context binding，把 PC 绑定到 exact ELF 和 runtime process map；再做 semantic recovery，恢复 syscall sequence、fd/path graph 和 behavior graph；最后用 provenance filter 决定哪些字段能进入最终 claim。

实现解释：

- 这页是 pipeline 总图。
- 用这句话收住：硬件给事实，离线分析给语义，provenance 决定 claim。

### Slide 8. How it works：从硬件 trace 到可报告语义

讲稿：

> 这页可以按箭头逐步讲。第一步，workload 打 begin/end marker。第二步，CVA6/RVFI 提供 commit 级信号，adapter 生成 event packets。第三步，BRAM ring 记录 compact event 和质量计数。第四步，主机解码后检查 marker、sequence、drop、wrap。第五步，把 accepted window 里的 PC 和 syscall 事件与 ELF/runtime map 做 join。第六步，恢复行为图。最后，只有 provenance 合法的字段进入 report。

实现解释：

- `cva6_rvfi_trace_adapter.sv` 是 capture 的核心。
- `trace_bram_ring.sv` 是窗口存储和计数核心。
- `decode_genesys2_bram_ring_dump.py` 是板上 dump 到 JSONL 的桥。
- `package_*` 和 `check_*` 脚本把产物变成可复查 summary。

### Slide 9. 架构：RTL 模块和 analysis artifacts

讲稿：

> 架构上分两层。RTL 层有三个关键模块：`cva6_rvfi_trace_adapter.sv` 把 RVFI 和相关信号翻译成 trace packet；`trace_bram_ring.sv` 把 packet 写进 1024 深度的 BRAM ring，并维护 counters；`trace_board_minimal_ctrl.sv` 提供板上控制和 readout。分析层有 `p0_bram_trace_summary.json`、`drop_accounting_summary.json`、`semantic_events.json` 等产物。所有字段最后都要贴 source label，比如 hardware、exact_elf、runtime_os_map、validation_oracle。

实现解释：

- 这页可以把“模块”和“artifact”一一对应。
- RTL 侧解决采集；analysis 侧解决解释；provenance 侧解决 claim。

### Slide 10. Pipeline I/O：每一阶段输入输出和失败处理

讲稿：

> 这一页强调工程闭环。每个 stage 都有明确输入、输出和失败处理。比如 capture 输入是 workload 和板级 trace 配置，输出是 BRAM dump；gate 输入是 `bram_records.jsonl` 和 summary counters，输出是 accepted window 或 retained failure；context binding 输入是 accepted events、code map、runtime map，输出 annotated events；semantic recovery 输出 `semantic_events`、`behavior_graph`、`fd_path_graph`。失败不被丢掉，而是进入 boundary evidence 或 blocked claim。

实现解释：

- `retained_failed_attempts` 是 robustness 的一部分，不是噪声。
- 这页要强调“失败保留”，因为它回应 accepted-window gate bias 的质疑。

### Slide 11. Claim contract：当前可以 claim 什么

讲稿：

> 当前 claim contract 有几个数字。严格 board 口径是 128 个 accepted marker-window repetitions，来自 142 次 board attempts；14 次失败尝试保留但不算 PASS。12 个 board workload 的语义产物都有 provenance 标签。我们能 claim 的是 exact ELF/function/runtime-map/source-line/pointer-prefix 这种有边界的证据。不能 claim 生产级 streaming/DMA、cycle-level overhead、真实 malware detection accuracy。主线语义重建里也不要把 full pointer string 当成普通硬件字段；如果引用 full-string closure，必须单独说明它的 guardrail 和 closure 范围。

实现解释：

- 128/142 来自 P0 48/62 和 surrogate 80/80。
- `statistical_robustness_summary.json` 的 aggregate 记录 accepted、attempt、failed。
- `semantic_provenance_summary.json` 记录 12 个 hardware trace provenance 和 276 个 oracle field count。

### Slide 12. Claim boundary：行为重建，不是检测器

讲稿：

> 这一页必须说清楚：RV-MalTrace 当前不是 malware detector。它不输出“恶意/良性”的泛化检测准确率，也不证明 in-the-wild malware coverage。它做的是在 controlled workload 上，把硬件 trace 变成有 provenance 的行为摘要。这样讲反而更稳，因为我们有板级 trace、artifact、checker 和边界说明。

实现解释：

- 如果有人问 false positive/true positive，回答：当前有 5 个 benign control 证明 scoped unexpected claim 为 0，但不是 production FPR。
- 真实 malware 和 detection accuracy 是 non-claim。

### Slide 13. Scoped closures：把 supported claim 和 non-claim 分开

讲稿：

> 这页是几个收口项。source-line closure 说明当前 board trace 的 source line 不是 native DWARF 完整证据，sidecar 只能有限使用。pointer-string closure 要分两层讲：主线语义重建只使用 bounded prefix；如果讲 full-string closure，就必须说它是单独 external closure，不是 full memory dump，也不是 companion string 替代。board benign-control closure 说明有 5 个 non-network benign control，没有 unexpected scoped claims，但它不等于 malware detector false-positive rate。

实现解释：

- `source_line_attribution_summary.json`：function attribution 可用，board native source-line 不 claim。
- `hardware_pointer_prefix_summary.json`：主线 bounded prefix PASS，full string false。
- `external_closure/hardware_pointer_strings_summary.json`：单独 full-string closure，不能和主线 semantic summary 混讲。
- `external_closure/board_benign_control_summary.json`：5/5 control，unexpected false positive 0。

### Slide 14. BRAM record：trace record 是可检查证据

讲稿：

> 这里进入实现 deep dive。我们不是只说“有 trace”，而是定义了一条 trace record 应该包含什么。BRAM record 里有 event type、sequence number、cycle、PC、primary/aux、ARG_MEM full fields，以及 BRAM ring 的 captured/drop/wrap counters。比如 `hello_write/rep_01` 的记录里，sequence 0 是 begin marker，后面有 PRIV、TRAP、SYSCALL_ENTRY、ARG_MEM、SYSCALL_RET，最后有 end marker；summary 里 captured_count 和 event_count 都是 85，drop/wrap 都是 0。

实现解释：

- RTL 数据结构：`trace_packet_t` 和 `trace_compact_record_t`。
- 主机解码：`decode_genesys2_bram_ring_dump.py`。
- 这页的重点是“证据可审计”，不是只给图。

### Slide 15. Event enum：硬件捕获哪些事件

讲稿：

> Event enum 是 4-bit，定义在 `trace_pkg.sv`。当前主要事件包括 `RETIRE`、`BRANCH`、`JUMP`、`SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`CSR`、`SATP`、`PRIV`、`ARG_MEM`、`DROP`、`MARKER`。其中对周会最重要的是 `MARKER` 用来界定窗口，`SYSCALL_ENTRY/RET` 用来恢复 syscall sequence，`TRAP/PRIV/SATP/CSR` 用来说明上下文，`ARG_MEM` 用来支持 bounded pointer prefix。

实现解释：

- `SYSCALL_ENTRY` 来自 U-mode ECALL trap path。
- `SYSCALL_RET` 来自 S-mode SRET 返回 U-mode，并需要 `rvfi_sret_to_user`。
- `DROP` 是队列或采集压力的 accounting，不是普通行为事件。

### Slide 16. Capture path：CVA6/RVFI 到 trace packet

讲稿：

> Capture 逻辑在 `cva6_rvfi_trace_adapter.sv`。它从 RVFI committed instruction 信号读取 PC、instruction、trap、cause、tval、mode、pc_wdata，也维护 `a0-a7` 的 shadow register。遇到 U-mode ECALL 且 cause 是 user ecall，就产生 `SYSCALL_ENTRY`；遇到 qualified SRET 返回 U-mode，就产生 `SYSCALL_RET`；遇到 marker syscall number 和 marker tag，就产生 `MARKER`；遇到 selected pointer syscall 且 user pointer 合法，就启动 pointer watch，后续 S-mode memory read 命中范围时产生 `ARG_MEM`。

实现解释：

- marker tag：begin 是 `0xb...`，end 是 `0xe...`。
- selected pointer syscall：`openat`、`write`、`execve`。
- pointer guardrail：`ENABLE_USER_POINTER_SNAPSHOT`、`MAX_POINTER_SNAPSHOT_BYTES`、`MAX_POINTER_WATCH_CYCLES`、`USER_POINTER_MAX`。
- `RELAX_SRET_TO_USER_CHECK` 在 paper/board path 不能作为宽松 claim。

### Slide 17. BRAM ring：有限存储和计数器

讲稿：

> BRAM ring 的作用是把 accepted window 中的 compact record 存下来，同时留下完整的质量账本。它的 depth 是 1024，compact record 宽度来自 `trace_compact_record_t`，debug probe payload 当前支持 v3 716-bit。clear 会重置 write index、sequence 和 counters；begin marker 开始新窗口；full 后 captured_count 不再增加，dropped_count 增加；wrap_count 记录环形覆盖风险。当前结果支持 marker-window evidence，不支持 continuous streaming throughput。

实现解释：

- `capture_fire = capture_enable && not freeze unless clear && trace_valid && packet.valid`。
- `next_sequence_q` 每写一条递增。
- `captured_count_q` 统计实际保留记录。
- `dropped_count_q` 和 `wrap_count_q` 是 gate 必查字段。

### Slide 18. Window gate：为什么只有 marker window 进入语义重建

讲稿：

> 这页回答“为什么不是所有 trace 都直接分析”。BRAM 有限，板上 readout 也可能出现失败或不完整，所以我们只允许 marker-bounded window 进入 semantic reconstruction。accepted window 必须满足 begin/end marker 完整、sequence 连续、wrap_count 为 0、unaccounted_drop 为 0，并且 syscall entry/return 在需要时可配对。任何 parse/drop/wrap/gap 都进入 retained failure。

实现解释：

- 这就是避免“拿不完整 trace 做漂亮结论”的防线。
- `package_genesys2_p0_bram_trace.py` 的 `parse_success` 逻辑体现了这些条件。
- 失败样本保留在 `failed_attempts`，不会算到 PASS。

### Slide 19. Accepted window 定义和 hello_write 例子

讲稿：

> 以 `hello_write` 为例，begin marker 是 `0xb0000a01`，end marker 是 `0xe0000a01`。`rep_01` 中 sequence 从 0 到 84，event_count 是 85，captured_count 是 85，wrap 是 0，drop 是 0，所以它可以进入后续语义恢复。P0 的严格结果是：`hello_write` 10/10，`file_open_read_write` 11/12，`fork_exec` 17/30，`illegal_instruction` 10/10，失败 14 次保留。

实现解释：

- 不要把 `drop_accounting_summary` 中的 no-drop 统计和 strict accepted 统计混在一起。
- 最终 slide 使用的 48 P0 accepted 来自 strict gate。

### Slide 20. Gate failure：失败样本如何处理

讲稿：

> 这页强调失败不是被隐藏。14 个 retained failures 都有 reason，比如 parse failure、marker 不完整、pairing 不满足、窗口质量不达标等。它们不会进入 PASS 分母里的 accepted repetition，但会进入 robustness 统计，说明这个系统的成功口径不是事后挑选。

实现解释：

- `statistical_robustness_summary.json` 有 `retained_failed_attempts` 列表。
- 讲的时候可以说：失败是边界证据，不是成功证据。

### Slide 21. Board matrix：128 accepted / 142 attempts

讲稿：

> 这页给出 board 结果矩阵。12 个 board workloads，其中 4 个 P0 safe、8 个 safe surrogate。严格 accepted 是 128 个 marker-window repetitions，总 attempts 是 142，失败 14 个保留。每个 accepted repetition 的 max accepted drop、wrap、sequence gap 都是 0。这个矩阵是当前 controlled board reconstruction claim 的核心数字。

实现解释：

- P0：48 accepted / 62 attempts。
- Safe surrogate：80 accepted / 80 attempts。
- 5 个 board benign controls 是单独 external closure，不混进 12 个 workload accepted repetition。

### Slide 22. Feature extraction：挑战和机制一一对应

讲稿：

> 这一页把挑战映射成机制。raw trace 低语义，所以做 context binding；BRAM 有限，所以做 marker-window gate；oracle contamination 风险高，所以做 field provenance；失败尝试可能造成选择偏差，所以做 failure accounting；pointer string 容易 overclaim，所以用 bounded ARG_MEM guardrails。这里的 feature 不是最终行为 claim，它只是进入后续 join 和 recovery 的中间证据。

实现解释：

- `ARG_MEM`、`SYSCALL_ENTRY/RET`、`PRIV/TRAP` 都是 pre-join features。
- 语义必须经过 `pc_binding`、syscall pairing、fd graph、provenance filter。

### Slide 23. Provenance before claim：feature 不等于语义结论

讲稿：

> 这里可以用两个样本说明。比如 `file_open_read_write` 有硬件窗口事件、syscall 和 ARG_MEM；`fork_exec` 有更多 syscall 和 ARG_MEM。但这些只是 pre-join features。只有当 PC 能绑定到 exact ELF/runtime map，syscall entry/return 能配对，fd/path graph 能更新，并且字段 provenance 合法时，它才成为可报告语义。否则只能是 raw feature 或 validation artifact。

实现解释：

- 这页可以强调“count 不是 conclusion”。
- ARG_MEM 是 bounded pointer-prefix snapshot，不是完整 path string。

### Slide 24. Provenance checks：检查栈

讲稿：

> Provenance check 是最后一道门。Artifact package 先做 schema 和 sample set 检查，再做 marker gate 和 SHA 引用检查，然后 provenance filter 检查字段来源。允许标签只有 `hardware`、`exact_elf`、`runtime_os_map`、`validation_oracle`。绿色输出是 controlled reconstruction，红色边界是 transport/overhead/real-malware detection 仍然 open。

实现解释：

- `check_genesys2_semantic_provenance.py` 会检查 oracle-valued field 不能 hardware-only。
- `artifact_package_manifest.json` 和 `reproducibility_manifest.json` 提供 reviewer traceability。

### Slide 25. RISC-V syscall/trap path

讲稿：

> 这一页解释为什么我们能从硬件看见 syscall。RISC-V Linux 用户态发 syscall 是 U-mode 执行 ECALL，进入 S-mode trap。我们在 trap path 上捕获 PC、instr、cause、privilege、`a0-a7`，形成 `SYSCALL_ENTRY`；等内核处理完，通过 SRET 回到 U-mode 时，捕获返回值 `a0` 和 return target，形成 `SYSCALL_RET`。entry/ret 用 syscall_id 配对，duration 也可以记录。

实现解释：

- `SYSCALL_ENTRY` 的 syscall number 是 `a7`。
- `SYSCALL_RET` 的 return value 是返回时 `a0`。
- marker syscall 是特殊编号和 marker tag，用于窗口，不是 workload 行为结论。

### Slide 26. CVA6-RVFI trace fields

讲稿：

> CVA6/RVFI 给我们的是硬件事实：PC、privilege、trap、syscall、marker 和 counters。marker 和 counters 决定这个窗口能不能被接受。以 `file_open_read_write` 为例，证据链是：marker window 通过 gate；硬件 syscall event 记录 entry/ret；context binding 判断 PC 和 process；semantic graph 恢复 open/write/read/close；oracle 只用来验证 expected order；最终 claim 是 trace-backed controlled reconstruction。

实现解释：

- path/prefix 如果来自 host/control 或 qemu/strace，要保持 `validation_oracle`。
- 不能说硬件独立完整恢复了所有 path string。

### Slide 27. Provenance label 规则

讲稿：

> 这页是报告规则。`hardware` 表示来自板级 trace 的 event sequence、trap、syscall、marker、counter。`exact_elf` 表示来自被分析 ELF 的 section、symbol、hash、code map。`runtime_os_map` 表示来自 `/proc/<pid>/maps` 这类运行时进程归属。`validation_oracle` 表示 qemu/strace、host/control、expected label、companion string。最终报告只能用 hardware/exact_elf/runtime_os_map 支撑，oracle 只能验证。

实现解释：

- `semantic_provenance_summary.json` 的 `allowed_provenance` 是这四个。
- `oracle_field_count` 当前为 276，说明很多高层字段确实被明确挡在 validation lane。

### Slide 28. ARG_MEM pointer guardrails

讲稿：

> 这页讲 pointer。按这份 slide 的主线，当前板级证据支持的是 bounded/guarded ARG_MEM prefix snapshots。流程是：`SYSCALL_ENTRY` 看到 selected syscall，比如 openat/write/execve；检查用户指针 base 和 length 合法；启动 pointer watch；后续内核 S-mode 读取用户指针范围时，硬件发出 `ARG_MEM(addr,data,size,last)`。guardrail 包括不读 kernel memory、不做 full memory dump、限制 payload 长度。

实现解释：

- 示例 `mem_addr=0x00010170`、`mem_data=0x72`、`arg_index=1` 表示捕到一个字节片段。
- `hardware_pointer_prefix_summary.json` 允许 claim bounded hardware prefixes。
- 主线不要把 full string 讲成普通 semantic 字段；trusted companion strings 仍是 oracle。
- 如果被问到 full-string closure，只说它是 external closure 中的 scoped artifact，不代表 full memory dump 或 companion substitution。

### Slide 29. Context bind：PC 绑定到 ELF 和 runtime map

讲稿：

> Context binding 是把 raw PC 变成可解释行为的关键。输入是 trace event 里的 PC/syscall id，exact ELF code map 里的 sections、symbols、source locations，以及 runtime OS map 里的 process 和 loaded object。`join_trace_code_map` 做 range match 和 owner match，输出 annotated event，例如 binary、symbol、process_owner、source label。对于 PIE、ASLR、dynamic libraries、fork/exec，如果缺 runtime evidence，就不能强 process attribution。

实现解释：

- `pc_binding(pc)` 需要 exact ELF identity、runtime OS map、ASLR/PIE offset、process ownership。
- `static_pc_annotation` 只能说明 PC 在 target ELF range，不等于 process attribution。
- `runtime_owner` 处理 target_child、runner_parent、kernel、ambiguous overlap。

### Slide 30. Context binding 细节页

讲稿：

> 这页可以更具体地讲：我们先用 code map 判断 PC 是否落在 target ELF 的 load range、section、symbol、syscall site 或 trap site。然后再用 runtime process map 判断这个 PC 在运行时属于 target child、runner parent 还是 kernel。只有 marker scope 有效、runtime map 是 PASS、PC 在 target child maps 里，并且静态 code map 也能匹配 target site，才把这个 event 作为 process-attributed strong evidence。

实现解释：

- `process_elf_ownership_summary.json` 当前 12 个 sample 的 `runtime_process_attribution_proven` 都是 true。
- `source_line_attribution_summary.json` 中 function attribution 可用，但 board native source-line 不 claim。
- 这页要避免把 source-line sidecar 讲成 board native DWARF。

### Slide 31. Semantic recovery：从 annotated events 到 behavior graph

讲稿：

> Semantic recovery 的输入是 annotated events。首先恢复 syscall sequence：entry 侧记录 number、args、pc、process owner；return 侧用 syscall_id 和顺序配对，补上 return value、return pc、duration。然后恢复 control-flow segments、trap/context transitions 和 privilege boundaries。最后 `build_graph` 生成 behavior graph：根节点是 trace，syscall 节点按 `next_syscall` 串起来，其他 context/control 节点挂在 trace 下。

实现解释：

- `recover_behavior.py` 的 `recover_syscalls` 处理 entry/ret 配对，也处理 return-only 或 fused target ecall/kernel entry 的情况。
- `recover_fd_path_flow.py` 在 syscall sequence 上维护 fd generation、active fd、close status、unresolved fd/path。
- oracle 只用于 validation，不替代硬件-derived events。

### Slide 32. file_open_read_write 语义恢复例子

讲稿：

> 以 `file_open_read_write` 为例，expected syscall order 是 openat、write、close、openat、read、write、close。硬件窗口提供 marker、syscall、trap、privilege 和可能的 ARG_MEM 片段；semantic recovery 通过 entry/ret 配对拿到 syscall number、args、return value；fd/path graph 把 openat 返回的 fd 和后续 read/write/close 关联起来；路径字符串或 expected sequence 如果来自 qemu/strace，就贴 validation_oracle 标签。最终能说的是这个受控样本的行为被 trace-backed reconstruction 捕获并通过 provenance 检查。

实现解释：

- `results/evaluation/genesys2-cva6/current/samples/file_open_read_write/semantic_events.json` 包装了该样本 semantic row。
- `behavior_graph.json` 中 `has_openat=true`、`has_write=true`。
- 不能把 expected syscall list 当成硬件独立发现的行为标签。

### Slide 33. Output artifact package

讲稿：

> 这一页给 reviewer 路径。所有核心输出集中在 `results/evaluation/genesys2-cva6/current/`。关键文件包括 `p0_bram_trace_summary.json`、`safe_surrogate_bram_trace_summary.json`、`drop_accounting_summary.json`、`semantic_reconstruction_summary.json`、`semantic_provenance_summary.json`、`source_line_attribution_summary.json`、`process_elf_ownership_summary.json`、`hardware_pointer_prefix_summary.json` 和 benign control closure。每个 sample 下面还有 `semantic_events`、`behavior_graph`、`fd_path_graph` 等包装产物。

实现解释：

- reviewer 可以从 manifest 到 raw board root 再到 per-sample artifact。
- claim/non-claim audit 不是口头说明，而是文件和 checker 固化。

### Slide 34. 结果总览：128/142 accepted

讲稿：

> 现在进入结果。当前 controlled board reconstruction 的核心结果是 128 accepted / 142 board attempts。12 个 board workloads 都有 accepted marker-window evidence，并且 accepted 窗口的 max drop、wrap、gap 都是 0。14 个失败尝试被保留，不计入 PASS。这支持 controlled board reconstruction claim。

实现解释：

- `statistical_robustness_summary.json` aggregate：accepted 128，attempt 142，retained failed 14。
- 结果不能外推为 production long-run stability 或 real malware generalization。

### Slide 35. Workload roster：4 个 P0 + 8 个 surrogate + 5 个 benign control

讲稿：

> Workload 分三类。P0 safe 有 4 个：`hello_write`、`file_open_read_write`、`fork_exec`、`illegal_instruction`，共有 48 accepted reps。Safe surrogate 有 8 个，覆盖 file scan、batch open/read/write、self copy、abnormal syscall、illegal trap、process chain、dynamic executable memory、anti-debug-like，共 80 accepted reps。另有 5 个 benign controls，用于 scoped false-positive closure，不混进 12 个 board workload repetition。

实现解释：

- 12 board workloads 是主要 reconstruction matrix。
- 5 benign controls 的结果是 `unexpected_false_positive_count=0`，但不是 production FPR。

### Slide 36. Metric definitions：50/50 和 12/12 怎么讲

讲稿：

> 这里要解释 metric 的含义。50/50 expected syscall labels matched 是在 12 个受控 workload 范围内，根据 expected syscall labels 和 qemu/strace companion 对齐得到的 validation metric。12/12 semantic artifacts 表示每个 board workload 都有语义产物并通过 provenance 检查。5/5 benign controls 表示 scoped benign control closure 通过。它们不是 malware detection accuracy，也不是 production false-positive rate。

实现解释：

- expected labels 和 accuracy 字段多数是 `validation_oracle`。
- 可报告的是“语义产物生成且 provenance 合法”，不是“检测准确率 100%”。

### Slide 37. Supported claims 和 deployment evidence

讲稿：

> 这一页把 supported claim 和 open evidence 分开。已经支持的是受控 workload 的 marker-window hardware trace、语义产物、provenance boundary、bounded pointer prefix、board repetition robustness。仍然 open 的是 deployment 级 streaming/DMA、生产环境吞吐、cycle-level runtime overhead、真实 malware coverage 和 detector accuracy。

实现解释：

- `streaming_dma_target_summary.json` 是 target baseline，不是 completed streaming transport。
- `resource_timing_summary.json` 有 FPGA utilization/timing，但 runtime overhead 是 non-claim。

### Slide 38. Alternative explanations

讲稿：

> 这页回应潜在质疑。第一，qemu/strace 有没有污染最终结论？我们用 provenance 把它们标成 oracle-only。第二，accepted-window gate 会不会选择性汇报？我们保留 14 个失败尝试。第三，controlled workload 能不能代表真实 malware？不能，所以真实 malware generalization 是 non-claim。第四，资源和 timing delta 是不是 runtime slowdown？不是，当前只有静态 FPGA resource/timing 和 board execution smoke，不 claim cycle-level slowdown。

实现解释：

- 每个 alternative explanation 都有对应 artifact 或 non-claim。
- 讲这里时语气要稳：我们不是回避限制，而是把限制工程化记录下来。

### Slide 39. Resource cost：静态 FPGA cost，不是 runtime overhead

讲稿：

> 资源结果来自 Vivado routed report。Baseline LUT 是 84,923，trace-enabled 是 106,428，增加 21,505，也就是 +25.32%。FF 从 56,491 到 65,634，+16.18%。BRAM18 等价从 108 到 114，+5.56%。DSP 不变，27 到 27。Timing status 仍然 MET，slack 是 0.177 ns。这个结果说明 trace-enabled bitstream 有静态资源成本，但它不是 cycle-level runtime overhead。

实现解释：

- source：`docs/07-evaluation-evidence/reports/resource_report.md`。
- 不要说“运行时开销很低”，除非有 cycle-level overhead evidence。
- 可以说“静态资源增量已量化，生产级 runtime overhead 尚未 claim”。

### Slide 40. Evidence matrix：哪些证据能报告

讲稿：

> 这个 matrix 是全 deck 的总结表。蓝色是 reportable hard evidence，比如 hardware trace、exact ELF、runtime map、accepted marker window。绿色或灰色是 validation aid，比如 qemu/strace expected order、host/control companion strings。红色是 open boundary，比如 production streaming、runtime overhead、real malware detection。报告时每个字段都要能回到 artifact 和 provenance label。

实现解释：

- 用这页防止答问时过度扩展 claim。
- 如果老师追问某一字段来源，就按 provenance label 回答。

### Slide 41. Recommendation：下一步建议

讲稿：

> 下一步建议是按 scoped claim 提交 artifact，而不是扩大成 detector claim。可以请 1 到 2 位 reviewer 按 artifact package 复查 current evidence root 和 checker；同时把 deployment overhead、streaming/DMA、real malware generalization 留作下一阶段。短期要完成的是 figures、source citations、scoped disclosures 和 reproducibility path。

实现解释：

- 这页不是技术细节，而是论文/汇报策略。
- 讲法要强调“先把当前可证的证据链写扎实”。

### Slide 42. Final summary：三句话收尾

讲稿：

> 总结一下。第一，板级 evidence 上，我们有 128/142 accepted marker-window attempts，失败 14 个保留，accepted 窗口 drop/wrap/gap 为 0。第二，语义 evidence 上，12/12 workloads 都有 semantic artifacts，并且 expected syscall label validation 是 50/50。第三，边界上，oracle-only 字段、主线 pointer-prefix 与 full-string closure 的范围、production streaming/DMA、runtime overhead、real malware detection 都被明确分开。

实现解释：

- 这是主汇报的正式收尾。
- 如果后面还有 backup，就说“下面几页是如果需要查证时可以展开的 backup”。

### Slide 43. Before/after summary

讲稿：

> 这页用 before/after 回答“本次工作的增量是什么”。Before 是软件 observer visibility、硬件 trace 低语义、字段来源容易混、没有 deployment overhead 证据。After 是硬件路径和 oracle 路径分离，context binding 把 PC 绑定到 ELF/runtime process，provenance 标签把字段来源固定下来，offline marker-window quality gate 把可用窗口筛出来。当前 contribution 是 scoped、trace-backed、provenance-aware reconstruction。

实现解释：

- 这里可以承认 streaming/DMA/runtime overhead 是 future work。
- 不要把 before/after 讲成“已经解决所有部署问题”。

### Slide 44. Reproducibility / checker commands

讲稿：

> 如果要复查，核心命令是 `uv run python tools/run_check_suite.py --suite genesys2-current`。这个 suite 会串起当前 Genesys2/CVA6 evidence root 的关键检查，包括 trace summary、drop accounting、semantic provenance、fd/path graph、source-line attribution、process/ELF ownership、artifact package 等。它不是重新采集板上 trace，而是验证当前 artifact package 的内部一致性。

实现解释：

- 如果 reviewer 是 fresh clone，还需要 raw board artifact 按 manifest 放回 repo root。
- checker command 是复查入口，不是新的 experimental result。

### Slide 45. Streaming/DMA appendix

讲稿：

> 这一页说明 streaming/DMA 还没作为 production claim 完成。当前 `streaming_dma_target_summary.json` 给的是 future transport target baseline：根据 accepted marker windows 估算 event bytes per cycle，p99 是 0.0215755 event bytes/cycle；未来外部 streaming transport 需要超过 1.5 倍，也就是 0.0323633 event bytes/cycle，再乘以实际 trace clock 得到 bytes/s。当前 sustained streaming evidence 没有闭合，所以不能 claim production throughput。

实现解释：

- 如果 slide 中提到 sustained 0 B/s 或 noninterference false，要讲成“当前 streaming/DMA closure 未完成”。
- BRAM/JTAG readout 不能替代 production streaming/DMA。

### Slide 46. Workload roster appendix

讲稿：

> 这页列出 workload 名单。P0 safe 是四个最小闭环样本；safe surrogate 是八个安全的 malware-like 行为样本；benign control 是五个非网络良性样本。这里的设计原则是 controlled、安全、source-controlled，不引入未知来源真实恶意样本。这样当前 claim 可以聚焦在 evidence chain 和 behavior reconstruction，而不是 malware family coverage。

实现解释：

- P0：`hello_write`、`file_open_read_write`、`fork_exec`、`illegal_instruction`。
- Surrogate：`file_scan`、`batch_open_read_write`、`self_copy_sim`、`abnormal_syscall_sequence`、`illegal_trap`、`process_chain`、`dynamic_executable_memory`、`anti_debug_like`。
- Benign：`hello`、`cat`、`clock_status`、`getdents_only`、`mmap_rw`。

### Slide 47. Resource detail appendix

讲稿：

> 最后一页是 resource detail。Baseline 与 trace-enabled 的具体数字是：LUT 84,923 到 106,428，FF 56,491 到 65,634，BRAM18 108 到 114，DSP 27 不变。Delta 分别是 +25.32%、+16.18%、+5.56%、+0%。Timing 仍然 MET，slack 没有恶化。这个 appendix 只支撑静态 FPGA 资源和 timing closure，不支撑 runtime overhead 或 throughput claim。

实现解释：

- 这页适合在老师问“硬件代价多大”时跳过去。
- 回答时保持边界：resource cost quantified，runtime overhead open。

### Slide 48. Backup: From NCScope to RV-MalTrace

建议作为 Google Slides 里的新增 backup / related-work 页，不建议插入主线前半段。

Slide 标题：

```text
Lineage: From NCScope to RV-MalTrace
```

Slide 正文建议：

```text
NCScope reference
Arm ETM + Android memory/context data for native-code self-protection and anti-analysis behavior.

RV-MalTrace adaptation
RISC-V Linux/CVA6 hardware trace with marker-window gate, ELF/runtime binding, and semantic recovery.

Claim boundary
NCScope is a motivation lineage / external reference, not a directly runnable RV-MalTrace sample set or current evidence source.
```

讲稿：

> 这页解释 RV-MalTrace 和 NCScope 的关系。NCScope 是我们早期参考的问题原型：它说明硬件执行 trace 结合 memory map 和运行时数据，可以帮助分析 Android native code 的自保护和反分析行为。RV-MalTrace 做的是把这个方向迁移到 RISC-V Linux/CVA6 板级原型，并把贡献收紧到 marker-window gated、context-bound、provenance-aware reconstruction。这里不能把 NCScope 说成我们的直接 baseline，也不能把它的 Android malicious APK dataset 说成当前 RV-MalTrace 的 real-malware evidence。

实现解释：

- NCScope 的 trace 路径是 Arm ETM / DS-5 / DSTREAM；RV-MalTrace 的 trace 路径是 CVA6 RVFI adapter / BRAM ring / board readout。
- NCScope 用 Android memory map 和 eBPF memory data 辅助分析；RV-MalTrace 用 exact ELF、runtime process map 和 field provenance 控制 claim。
- 当前仓库中的 NCScope vendor artifact 应分类为 `external_reference` 或 `vulnerability_test_trace`，不是 `real_malware` evidence。
- 对应依据：`docs/04-runtime-linux/linux_real_malware_validation.md` 的 `NCScope Vendor Reference`，以及 `vendor/ISSTA-22-NCScope/ISSTA-22-NCScope/README.txt`。

## 5. 可能被问到的问题和回答

### Q1. 你们到底捕获了什么数据？

答：

> 硬件捕获的是 committed-event trace，不是完整内存或完整 OS 行为。具体包括 marker、trap、privilege change、syscall entry/return、CSR/SATP、branch/jump/retire 相关字段，以及 selected syscall user pointer 的 bounded ARG_MEM bytes。每条 BRAM record 还有 sequence、cycle、PC、primary/aux 和 drop/wrap/captured counters。

### Q2. 怎么判断一个窗口能不能用？

答：

> 用 marker-window gate。必须有 begin/end marker，sequence 连续，wrap_count 为 0，unaccounted_drop 为 0，必要 syscall entry/return 可配对。失败窗口保留但不算 PASS。

### Q3. 路径字符串是硬件恢复的吗？

答：

> 主线汇报里不能这么说。主线硬件证据支持的是 selected syscall pointer 的 bounded prefix bytes 和 fragments；完整路径字符串如果来自 qemu/strace 或 host/control companion，就必须标成 `validation_oracle`。如果引用单独的 external full-string closure，要说明它有独立 artifact、redaction、mem_last/terminator、kernel-space filter 和 companion-substitution audit，不能泛化为 full memory dump。

### Q4. 为什么还需要 qemu/strace？

答：

> qemu/strace 用作 validation oracle，帮助确认 expected syscall order 和 companion fields。它们不进入 hardware-only claim。provenance checker 会检查 oracle-valued fields 不能被标为 hardware-only。

### Q5. 这个是不是 malware detector？

答：

> 不是。当前系统支持 controlled behavior reconstruction。它没有 claim real malware detection accuracy、malware family coverage、production false-positive rate。

### Q6. 资源和开销怎么说？

答：

> 静态 FPGA resource 已量化：LUT +25.32%，FF +16.18%，BRAM18 +5.56%，DSP 不变；timing MET，slack 0.177 ns。cycle-level runtime overhead 和 production streaming throughput 没有 claim。

## 6. 一分钟版总结

> RV-MalTrace 当前闭合的是一条受控板级行为重建证据链。硬件侧在 CVA6/RVFI 提交路径捕获 marker、trap、privilege、syscall 和 bounded ARG_MEM 事件，BRAM ring 记录 sequence 和 drop/wrap counters。主机侧先用 marker-window gate 接受 128/142 次 board attempts 中的完整窗口，并保留 14 个失败尝试；再用 exact ELF 和 runtime process map 把 PC 绑定到具体 binary/process；然后恢复 syscall sequence、fd/path graph 和 behavior graph；最后用 field provenance 区分 hardware、exact_elf、runtime_os_map 和 validation_oracle。当前结果支持 controlled trace-backed semantic reconstruction；不支持 malware detector、production streaming/DMA 或 cycle-level overhead claim。pointer string 相关内容要按主线 bounded-prefix 和单独 external closure 分开讲。
