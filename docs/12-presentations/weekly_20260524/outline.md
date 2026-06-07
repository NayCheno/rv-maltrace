# RV-MalTrace 论文进展汇报大纲

日期：2026-05-29

## 汇报目标

本次报告聚焦三个问题：

1. 当前仓库已经闭环到什么程度。
2. 哪些结论可以进入论文叙述，哪些仍必须保留边界。
3. 下一阶段如何从 35T 原型证据链推进到论文级贡献。

## 页级结构

| 页码 | 版式 | 标题 | 内容要点 |
|---:|---|---|---|
| P1 | cover | RV-MalTrace 当前进展与论文推进计划 | 论文进展汇报、日期、研究主题 |
| P2 | toc | 汇报提纲 | 研究定位、实验数据与结果、证据边界、下一阶段 |
| P3 | outline | Outline | 当前章节：研究定位 |
| P4 | text + keybox | 这不是一个单纯的 RTL demo | 从 trace tap 到行为证据链 |
| P5 | full diagram | 当前技术链路 | RISC-V/LiteX/VexRiscv/CVA6 相关链路与离线分析 |
| P6 | outline | Outline | 当前章节：实验数据与结果 |
| P7 | table | 仓库已经形成的四层能力（表 1） | RTL/仿真、35T 实验、语义恢复、证据包 |
| P8 | table | 阶段实验数据总览（表 2） | trace、35T、语义、baseline、真实派生、资源 |
| P9 | text + mini table | Trace 事件模型已经稳定 | 事件类型与 syscall/trap/context/drop 语义 |
| P10 | example table | Trace JSONL 的具体格式（示例 1） | `hello` trace.jsonl 前三行字段化展示 |
| P11 | example table | 16-word raw record 到 JSONL 的映射（示例 2） | raw_words 到 evt/cycle/pc/syscall 参数的映射 |
| P12 | table | Vivado 与 CVA6 仿真门禁（表 3） | trace unit、RVFI adapter、direct-core、full SoC、RV64GC |
| P13 | table | 仿真流程实验数据（表 4） | 30 个 PASS 行、220 events、pointer/backpressure 数据 |
| P14 | table | 35T 主矩阵已经闭环（表 5） | 512 records、13/13 PASS、DROP/marker/runtime attribution |
| P15 | table | 35T 样例矩阵实验数据（表 6） | benign/synthetic 分组、entry/ret/trap/drop 数据 |
| P16 | example table | `illegal_trap` 的板级结果样例（示例 3） | trace 片段、trap、marker、trace-code join 与 PASS 判定 |
| P17 | table | 真实恶意代码派生行为有六行证据（表 7） | DarthRa/Mirai-derived, 6/6 PASS, safety boundary |
| P18 | table | 真实恶意派生流程的时序与 trace 数据（表 8） | Host/QEMU/Board ms、events、DROP |
| P19 | columns | 解释接口让结果可复述 | `rvmt explain:35t`、fd/path、process tree、code map |
| P20 | table | 语义恢复流程的实验结果（表 9） | fd/path、process tree、function/source-line attribution |
| P21 | example table | `file_scan` 的 fd/path 输出样例（示例 4） | openat/path/fd/getdents64/close 的闭合 flow |
| P22 | example table | `process_chain` 的 process-tree 输出样例（示例 5） | clone return、wait PID、exec path、strong edge |
| P23 | table | 对比实验流程当前数据（表 10） | host/QEMU/eBPF/QEMU-plugin/software/RVMT ablation |
| P24 | outline | Outline | 当前章节：证据边界 |
| P25 | table | 现在可以稳妥陈述的结论（表 11） | 允许 claim 与证据来源 |
| P26 | table | 仍然不能越界的说法（表 12） | CVA6、真实恶意检测、完整语义、成熟检测器 |
| P27 | table + keybox | 资源与非干扰证据的边界（表 13） | LUT/FF/BRAM/DSP/slack，非性能提升 claim |
| P28 | outline | Outline | 当前章节：下一阶段 |
| P29 | text + keybox | 论文主线要从 prototype 走向 paper contribution | syscall semantic tracing + pointer reconstruction |
| P30 | formula/table | 下一步一：把 pointer 语义做成核心创新 | ARG_MEM、openat/execve/connect 语义 |
| P31 | table | 下一步二：把对比实验补齐（表 14） | strace/eBPF/QEMU/software instrumentation |
| P32 | table | 未来两周优先级（表 15） | source line、Linux gate、baseline、paper table |
| P33 | table | 未闭合流程的实验状态（表 16） | source-line、pointer snapshot、helper、side-channel、fuzz |
| P34 | list | 需要讨论的三个决策 | 题目定位、硬件-only/helper、目标会议强度 |
| P35 | thanks | 请老师批评指正 | 简洁结束页 |

## 术语

| English / ID | 中文表达 |
|---|---|
| RV-MalTrace | RISC-V 硬件辅助行为追踪原型 |
| committed event trace | 已提交事件追踪 |
| trace gate | trace 证据门禁 |
| semantic closure | 语义闭环 |
| real-malware-derived | 真实恶意代码派生行为 |
| pointer snapshot | 指针参数内存快照 |
| claim boundary | 结论边界 |
