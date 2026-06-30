# Presentation Outline

## Page 1 [cover]
- **Title**: RV-MalTrace: RISC-V 硬件辅助恶意软件行为追踪
- **Content**: 博士课题进展汇报 | 与导师第一次会议 | 2025年7月

## Page 2 [table_of_contents]
- **Title**: 汇报提纲
- **Content**:
  1. 研究背景与问题
  2. 难点与挑战
  3. 解决方案
  4. 技术细节与评估

## Page 3 [chapter]
- **Title**: 01 研究背景与问题
- **Content**: 为什么需要硬件层的行为追踪？

## Page 4 [content]
- **Title**: 当前研究的问题
- **Content**:
  - 核心问题：硬件 trace 是低层事件，而恶意软件行为声称是高层语义。如何在不把软件参考日志误报成硬件恢复结果的前提下，将低层硬件事件连接到进程、可执行文件和行为标签？
  - 现有软件 tracing（strace、eBPF）是测量系统的一部分，存在可检测性和可绕过性问题
  - 硬件 trace 提供独立观察点，但缺少归因（attribution）和边界（boundary）机制
  - 问题本质：需要构建一条从 RTL 级提交事件 → 代码映射 → 运行时映射 → 语义行为重建 的可验证证据链

## Page 5 [content]
- **Title**: 研究动机与价值
- **Content**:
  - 软件 tracing 不是没用，而是不适合单独承担对抗性 workload 的全部证据链
  - 对抗性场景（anti-debug、timing check、direct-syscall、packed code）中，软件 tracer 本身可被目标程序检测并绕过
  - 硬件 trace 提供 CPU 外部的独立观察点，目标程序无法感知或篡改
  - 但硬件事件本身不足以支撑 malware behavior 声称，必须补上：ELF/process 归因、语义重建、以及明确的证据边界
  - 本研究的核心价值：建立硬件 rooted 的 RISC-V 行为追踪与语义重建系统，作为对抗性场景下的独立证据来源

## Page 6 [chapter]
- **Title**: 02 难点与挑战
- **Content**: 从硬件事件到行为声称的鸿沟

## Page 7 [content]
- **Title**: 解决该问题的技术难点
- **Content**:
  - 语义鸿沟：硬件只记录 committed instruction / register / CSR，而行为分析需要 syscall 参数、文件路径、进程树等高层语义
  - 归因难题：同一物理 trace 可能来自多个进程（fork/exec）；PIE/ASLR 使静态 ELF 分析不足以定位代码；动态库加载改变地址空间
  - 证据混淆风险：软件参考日志（strace）容易与硬件 trace 混淆，导致“看似正确”实则错误的声称
  - 指针语义恢复：syscall 参数中的指针（如 openat 的路径字符串）需要额外的内存快照机制，但不能对 core 产生 backpressure
  - 反分析对抗：anti-debug、timing check、direct-syscall 等样本专门检测并绕过软件 tracer

## Page 8 [content]
- **Title**: 实现该方案的挑战
- **Content**:
  - CVA6 信号定位：CVA6 是多端口 commit 的超标量核心，需要准确定位 commit_valid、commit_pc、commit_instr、writeback、trap、CSR 等信号
  - Syscall entry/return 关联：ECALL 走 exception path，不是正常 retire；SRET 返回 U-mode 才算 syscall return——需要精确的 privilege transition 判定
  - 无侵入设计：trace tap 必须是 sideband-only，不能增加 CVA6 的寄存器读端口、不能 backpressure commit、不能改变时序
  - FPGA 资源约束：Genesys2 (Kintex-7) 上 CVA6 已占大量 LUT/FF，trace logic 必须在时序闭合的前提下增加最小资源开销
  - Trace 导出瓶颈：BRAM 容量有限（marker window 级别），UART 带宽低，AXI DMA 集成复杂——需要分阶段证明 trace shape 正确性
  - Linux 工作负载验证：从 bare-metal 到 Linux 用户态，需要完整的 boot、ELF 加载、代码映射、运行时映射链条

## Page 9 [chapter]
- **Title**: 03 解决方案
- **Content**: RV-MalTrace 系统架构

## Page 10 [content]
- **Title**: 提出的解决方案：RV-MalTrace
- **Content**:
  - 核心设计：在 CVA6 RTL 中植入轻量级 sideband trace tap，捕获 committed behavior 事件（syscall、branch、trap、CSR、privilege change）
  - 事件驱动：仅记录真正影响 architectural state 的 committed 事件，不记录 speculative、被 flush/kill 的指令
  - 语义重建流水线：hardware trace → Python parser → code map (ELF + symbol) → runtime map (process tree + fd graph) → behavior graph
  - 明确的证据来源标记：每个重建字段标注其来源——hardware trace、ELF map、runtime map、reference log——避免混淆
  - 分阶段验证：Vivado simulation → bare-metal board → Linux workload → controlled malware-like surrogate

## Page 11 [content]
- **Title**: 应对挑战的方法与策略
- **Content**:
  - 信号定位：基于 CVA6 RVFI (RISC-V Formal Interface) 输出，建立 signal_map.md，明确每个 commit port 的 valid/pc/instr/trap/cause 等信号
  - 无侵入设计：通过 arg_shadow 模块监听 writeback 端口，用 shadow register 跟踪 a0-a7，不增加寄存器堆读端口
  - Sideband-only + Drop mode：trace FIFO 溢出时 emit EVT_DROP 并计数，绝不 backpressure CVA6 commit logic
  - 分阶段导出：Phase 1 BRAM ring buffer + ILA/JTAG（证明 packet shape 正确）；Phase 2 评估 UART streaming；Phase 3 评估 AXI DMA
  - 受控验证矩阵：先跑 bare-metal smoke（branch、jump、ecall、trap、CSR），再上 board 验证，最后 Linux 工作负载
  - 合成/实现策略：trace logic 与 CVA6 一起综合，对比 baseline bitstream 和 trace-enabled bitstream 的资源增量，确保时序闭合

## Page 12 [chapter]
- **Title**: 04 技术细节与评估
- **Content**: 架构、背景与证据

## Page 13 [content]
- **Title**: 必要的技术背景知识
- **Content**:
  - RISC-V 特权架构：U-mode (User) / S-mode (Supervisor) / M-mode (Machine)；ECALL 从 U-mode 陷入 S-mode，SRET 返回 U-mode
  - CVA6 RVFI：RISC-V Formal Interface，每周期输出最多 2 个 commit port 的 valid、pc、insn、trap、cause、mode、rd_addr、rd_wdata 等信号
  - Syscall ABI：RISC-V Linux 中 a7 为 syscall number，a0-a5 为参数，a0 为返回值；openat/write/execve 等 syscall 携带指针参数
  - 硬件 vs 软件 tracing 范式：软件 tracer 通过 ptrace/eBPF/动态插桩获取信息，可被检测；硬件 tracer 通过 sideband 观察 committed state，目标不可感知
  - 行为图模型：节点为 process / file / socket / memory region，边为 syscall 关系（open/read/write/exec/clone 等），用于 malware behavior audit

## Page 14 [content]
- **Title**: 具体方案细节 — 硬件架构
- **Content**:
  - trace_pkg.sv：定义 13 种事件类型（EVT_RETIRE, BRANCH, JUMP, SYSCALL_ENTRY, SYSCALL_RET, TRAP, CSR, SATP, PRIV, ARG_MEM, DROP, MARKER）和统一的 trace_packet_t 结构体
  - 独立 tap 模块：retire_tap、branch_tap、syscall_tap、trap_tap、context_tap、arg_mem_tap，每个负责一类事件的检测和打包
  - trace_top.sv：仲裁逻辑，优先级 TRAP > SYSCALL > ARG_MEM > CONTEXT > BRANCH > RETIRE；同周期多事件通过 FIFO queue 排队，queue 满则 DROP
  - trace_filter.sv：可配置的事件过滤，支持 enable/disable 各事件类型、PC range filter、privilege mask filter
  - 输入流水线：PIPELINE_INPUTS 参数控制是否对 CVA6 输入打拍，平衡时序和延迟
  - 信号连接：commit_valid → retire/branch；trap_valid → trap；wb_valid + rd_addr → arg_shadow；csr_we + watched CSR → context；privilege change → PRIV

## Page 15 [content]
- **Title**: 具体方案细节 — 语义重建流水线
- **Content**:
  - Stage 1 硬件解析：trace.jsonl → 按事件类型分类，提取 cycle、pc、instr、syscall_id、a0-a7、cause 等字段
  - Stage 2 代码归因：join ELF 的 .symtab + .debug_line（如果可用）+ 反汇编，将 pc 映射到函数名和源代码行；处理 PIE/ASLR 通过基址重定位
  - Stage 3 运行时映射：识别进程边界（fork/exec/clone）、fd-to-path 关系、内存映射（mmap/mprotect）；构建 fd graph 和 process tree
  - Stage 4 行为重建：将 syscall 序列映射到行为规则（anti_debug、file_scan、dynamic_executable_memory、illegal_trap 等），输出 behavior_graph.json
  - Stage 5 证据标记：每个输出字段标注来源——hardware_derived（来自 trace）、elf_mapped（来自 ELF）、runtime_inferred（来自运行时映射）、reference_oracle（仅用于对比）
  - 输出产物：semantic_events.json、behavior_graph.json、recovery_report.md、timeline.html、scorecard.md

## Page 16 [content]
- **Title**: 评估框架与证据
- **Content**:
  - 6 个研究问题 (RQ1-RQ6)：正确性、语义重建、低扰动、抗绕过性、硬件开销、行为有用性
  - 基线对比：strace/ptrace、QEMU plugin、RV-MalTrace event-only、RV-MalTrace + pointer snapshot、software instrumentation sidecar
  - 数据集分类：Class A (microbenchmark)、Class B (benign Linux)、Class C (controlled malware-like surrogate)
  - 关键指标：syscall precision/recall、argument reconstruction accuracy、path string accuracy、fd graph accuracy、runtime overhead、trace drop rate、LUT/FF/BRAM/Fmax
  - 当前证据状态：simulation PASS、Genesys2 board baseline PASS、BRAM marker window trace PASS (122 accepted windows, 0 drops/wraps/gaps)、semantic reconstruction PASS (bounded)

## Page 17 [content]
- **Title**: 当前进展与边界
- **Content**:
  - 已完成的：CVA6 Vivado simulation MVP、trace architecture 实现、Genesys2 board bring-up、first-board trace validation、behavior demo 语义重建、controlled safe surrogate 评估
  - 明确的边界（非声称）：不声称真实 malware detection accuracy、不声称 production streaming/DMA throughput、不声称完整硬件指针字符串（当前为 bounded prefix）、不声称 cycle-level overhead（当前为 smoke-level）
  - 待关闭的外部项：board-native DWARF source lines、full hardware pointer strings、production streaming DMA、Genesys2 board benign control
  - 下一步决策：主 claim 是否足够支撑论文方向？是否补充 board-native 证据？哪些 non-claims 放入 limitations？

## Page 18 [final]
- **Title**: 总结与讨论
- **Content**:
  - 核心结论：在受控 RISC-V Linux workload 下，可以从 CVA6/Genesys2 硬件 trace 重建 source-labeled behavior；当前证据支持 controlled behavior reconstruction，不支持 real malware detection accuracy
  - 关键创新：RTL-level committed behavior trace + 明确的证据来源标记 + 分阶段 artifact-backed validation
  - 需要导师帮助判断的问题：
    1. 当前主 claim 的 scope 和边界是否适合论文方向？
    2. 是否需要优先补齐 board-native benign control 或 full pointer string 证据？
    3. 论文投稿目标应定位 CCF-A 会议还是更务实的 workshop？
  - 谢谢！欢迎提问
