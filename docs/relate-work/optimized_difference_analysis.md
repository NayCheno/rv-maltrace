# RV-MalTrace 与导师推荐 A 会论文的优化差异分析

> 生成日期：2026-06-29  
> 对比范围：`docs/relate-work/` 下五篇论文（USENIX SEC'17、TIFS'19、ESORICS'20、RAID'23、ICSE'22）
> 对比基准：RV-MalTrace 当前状态（NDSS'26 投稿目标）

---

## 0. 当前 RV-MalTrace 基线

为避免比较对象漂移，将"我们目前的工作"按仓库当前状态理解为：

- **主线**：Genesys2 / CVA6 / RISC-V 硬件辅助行为追踪证据链。核心是从 CVA6 committed-event trace RTL 采集 syscall、trap、privilege、CSR/context、drop、marker 等事件，结合 ELF、runtime process map、动态库、fork/exec ownership、fd/path、pointer string 等语义信息进行离线重建和证据链校验。
- **补充路线**：Artix-7 35T / LiteX / VexRiscv bounded prototype。核心为 512-record small-capacity trace policy、controlled benign + synthetic malware-like 矩阵，以及 35T 上 real-malware-derived behavior rows 的安全受控行为验证。
- **当前不可扩张的主张**：不能声称真实恶意软件检测准确率、成熟检测器、完整语义重建、生产级 streaming/DMA throughput、完整 cycle overhead、kernel rootkit resistance，或 uncontrolled/network-enabled malware execution。

因此，本报告里的"差异"围绕以下维度展开：

1. **平台**：ARM TrustZone/CoreSight/ETM、ARM MCU、RISC-V Rocket、RISC-V CVA6/FPGA。
2. **目标**：透明调试、内核模块保护、DIFT 运行时防护、固件 fuzzing、行为语义证据链。
3. **观测抽象**：原始指令/控制流 trace、ETM packet、DIFT tag、coverage bitmap、committed behavior event。
4. **语义路线**：在线调试、在线 enforcement、coverage feedback、离线 syscall/process/file/provenance 重建。
5. **评测证据**：overhead、漏洞发现、真实恶意样本、safe surrogate、artifact gate、board evidence。

---

## 1. 总览对比

| 文件 | 论文 | 主要方向 | 与我们最核心的关系 |
|------|------|----------|-----------------|
| `sec17-ning.pdf` | **Ninja**: Towards Transparent Tracing and Debugging on ARM, USENIX Security 2017 | ARM TrustZone + PMU + ETM 透明 tracing/debugging | **相邻工作**。证明硬件 debug/trace 可用于透明 malware analysis，但核心是 ARM 透明调试，不是 RISC-V 语义证据链。 |
| `ninja-tifs19.pdf` | **Ninja (TIFS)**：Hardware-Assisted Transparent Tracing and Debugging on ARM, TIFS 2019 | Ninja 扩展版，加连续 malware analysis 的快速系统恢复 | **相邻工作**。比 USENIX 版多了 restoration，我们目前没有同类系统恢复贡献。 |
| `hart-esorics20.pdf` | **HART**: Hardware-assisted Kernel Module Tracing on Arm, ESORICS 2020 | ARM ETM 跟踪二进制内核模块，并构建 HASAN | **相邻偏近**。关注 kernel module vulnerability protection，我们关注用户态/系统行为 trace 和语义重建。 |
| `3607199.3607246.pdf` | **Raft**: Hardware-assisted Dynamic Information Flow Tracking for Runtime Protection on RISC-V, RAID 2023 | RISC-V Rocket coprocessor DIFT runtime protection | **最接近的 RISC-V 硬件安全相关工作**，但目标是 taint/tag enforcement，不是 trace/provenance/audit。 |
| `3510003.3510208.pdf` | **μAFL**: Non-Intrusive Feedback-driven Fuzzing for Microcontroller Firmware, ICSE 2022 | ARM MCU ETM/DWT 硬件在环 fuzzing | **相邻工作**。用硬件 trace 产生 coverage feedback 找固件 bug，我们用硬件 trace 解释行为。 |

**一句话定位**：

> 这些论文共同说明"硬件辅助低侵入观测"是成熟方向；我们的差异不在于也用了硬件 trace，而在于面向 **RISC-V/Linux committed behavior event 的语义重建、证据链和 bounded malware-like behavior audit**。

---

## 2. 逐篇详细差异分析

### 2.1 Ninja（USENIX Security 2017）

#### 论文核心

Ninja 提出一个 ARM 平台上的透明 malware tracing/debugging 框架。出发点是：传统 emulator、VM、ptrace、strace、Android runtime instrumentation 或内核修改都会留下可检测指纹，evasive malware 可以据此隐藏恶意行为。因此 Ninja 把分析环境放到目标软件难以观察和篡改的位置。

**具体贡献**：

1. ARM TrustZone 隔离环境中的透明分析框架。Ninja 把 analyzer 放在 secure world，通过 TrustZone 隔离普通世界中的 Android/Linux 和目标应用。不依赖 QEMU、VM、ptrace/strace，也不修改 Android framework 或 Linux kernel。
2. 基于 PMU 和 ETM 的 tracing subsystem。利用 ARM PMU 事件和 ETM trace 支持 instruction tracing、system call tracing 和 Android API tracing。system call tracing 通过配置 ETM 跟踪 PMU 的 `EXC_SVC` 事件实现。
3. GDB-like debugging subsystem。支持远程调试命令，通过 secure serial port 和 secure monitor 交互，允许读写寄存器、内存、设置断点、单步等。
4. 透明性增强机制。由于 PMU/ETM 寄存器和 memory-mapped interface 可能被目标代码探测，Ninja 设计了系统寄存器访问 trap、memory mapping interception、人工 register view、timer adjustment 等机制。
5. 实验评测。在 ARM Juno 和 i.MX53 QSB 上验证。案例包括 DroidBench 信息泄露样本和 Suterusu rootkit 内核 text section 修改。开销方面，instruction/syscall tracing 小于 1% 或可忽略；Android API tracing 因频繁 domain switch 可达 4x–154x。

#### 与 RV-MalTrace 的差异

| 维度 | Ninja | RV-MalTrace |
|------|-------|-------------|
| **目标问题** | ARM 透明 malware analysis 和 interactive debugging | RISC-V/Linux 行为语义证据链和审计解释 |
| **平台** | ARMv8 TrustZone + PMU + ETM | RISC-V CVA6/FPGA 自定义 RTL trace tap |
| **隔离机制** | **TrustZone 安全域**（EL3 vs normal world） | **无安全域**；透明性来自 RTL 旁路捕获，不修改任何可见状态 |
| **Trace 源** | ARM 标准 ETM packet（指令流） | 自定义 committed behavior event schema（syscall、trap、priv、CSR 等） |
| **系统修改** | 需定制 TrustZone 固件（ATF） | **零修改任何系统软件**（固件、内核、用户态） |
| **语义恢复** | 指令 trace + 系统调用 trace + Android API trace（Java 层） | syscall entry/ret + 参数 + fd/path + 进程树 + 行为规则 |
| **分析方式** | 在线 trace + 人工 debug（GDB-like） | 离线 trace 分析（JSONL）+ 自动化行为规则匹配 |
| **威胁模型** | 面向 evasive malware 和部分 privileged malware | trusted kernel、user-mode malware-like workload、kernel rootkit out of scope |
| **评测** | 透明性实验、调试功能、真实 malware/rootkit 案例、overhead | trace correctness、semantic provenance、artifact integrity、safe surrogate audit |

**关键差异解读**：Ninja 和 RV-MalTrace 是**最接近的对手工作**——都关注恶意软件分析，都强调低侵入/抗规避。但实现路径截然不同：

- **Ninja 依赖 TrustZone**：利用 ARM 安全扩展实现隔离，分析器在 EL3 运行。这要求平台支持 TrustZone，且需定制固件。**RV-MalTrace 不依赖 TrustZone**，其透明性来自 trace tap 在 RTL 层的物理旁路——程序无法检测一个不修改任何可见状态的硬件单元。
- **Ninja 使用标准调试 IP**（ETM + PMU），RV-MalTrace 使用**自定义 RTL 设计**。这意味着在 RISC-V 生态中，RV-MalTrace 不依赖特定厂商调试 IP，可移植性理论上更高（只要 core 支持 RVFI 或等效 commit 接口）。
- **Ninja 是分析工具**（trace + debug 供人工分析），RV-MalTrace 是**证据生成器**（自动化行为规则匹配 + 审计证据链）。

#### 写作启示

**推荐写法**：

> Ninja shows that ARM TrustZone, PMU, and ETM can support low-artifact tracing and debugging for evasive malware analysis. RV-MalTrace differs by instrumenting a RISC-V core to export committed behavior events and by focusing on Linux semantic provenance and artifact-backed behavior reconstruction rather than interactive transparent debugging.

**需要避免**：

> RV-MalTrace is transparent like Ninja.  
> RV-MalTrace can analyze privileged malware like Ninja.  
> RV-MalTrace achieves Ninja-level overhead.

---

### 2.2 Ninja（TIFS 2019）

#### 论文核心

TIFS 版是 Ninja 工作的扩展版本。保留 USENIX 版 ARM TrustZone + PMU + ETM 透明 tracing/debugging 设计，同时加入面向连续 malware analysis 的快速系统恢复机制。

**主要新增贡献**：

1. 扩展透明 tracing/debugging 框架。继续强调不依赖 emulator、VM 或系统软件修改。
2. 引入 **data address tracing**。相比 USENIX 版主要强调 instruction/system call/API trace，TIFS 版进一步使用 ETM data address trace 分析内存写入位置，为 selective memory restoration 提供依据。
3. **快速系统恢复机制**。连续分析多个样本时，前一个样本可能污染内存、文件系统或寄存器状态。TIFS 版设计了三部分恢复：
   - selective memory restoration：只恢复被样本修改过的内存区域；
   - file system switching：利用类似 `pivot_root` 的机制快速切换文件系统；
   - register/context restoration：恢复可能影响后续分析的寄存器状态。
4. 性能与恢复评测。ETM-based instruction/system call/data address tracing 开销可忽略或低于 0.1%；Android API tracing 仍然较重。系统恢复耗时从约 0.029s 到 2.160s，selective restoration 明显快于 full memory restoration。

#### 与 RV-MalTrace 的差异

TIFS 版最突出的新增贡献是连续 malware analysis 的系统恢复。**我们目前没有对应能力**：

- 没有 sample execution 后自动恢复板上 Linux/内存/文件系统到 clean snapshot 的系统机制；
- 没有把 trace 用于 changed-memory restoration；
- 没有把多样本连续恶意软件分析作为主贡献。

**Memory trace 使用边界差异**：TIFS Ninja 使用 data address trace 支持恢复和 rootkit 修改分析。我们的 memory 语义路线更保守：

- 默认不启用 full memory trace；
- `ARG_MEM` 是 syscall-scoped、bounded、gated 的 pointer snapshot；
- full hardware pointer strings 仅限 accepted scoped evidence，不等于完整内存 dump 或 kernel memory capture。

**评测成熟度差异**：TIFS Ninja 对 tracing overhead 和 restoration latency 有清晰实验。我们当前主线对 trace correctness、semantic provenance、artifact integrity 更强，但 cycle overhead 和 production streaming/DMA 仍未闭环。

#### 写作启示

**推荐写法**：

> The extended Ninja work further uses ETM data-address tracing for selective system restoration across malware-analysis sessions. RV-MalTrace does not target continuous sandbox restoration; instead, it keeps memory capture disabled by default and uses bounded pointer snapshots only when supported by timing, provenance, and artifact gates.

**需要避免**：

> 和 TIFS Ninja 拼 transparent restoration；  
> 把当前 pointer snapshot 写成全局 data trace。

---

### 2.3 HART（ESORICS 2020）

#### 论文核心

HART 提出一个 ARM 平台上的硬件辅助 kernel module tracing 框架。关注的问题是第三方 Linux kernel modules 权限高、源码常不可得、已有内核保护方案需要源码或内核大改且开销高。

**主要贡献**：

1. 面向二进制 kernel modules 的 ETM-assisted tracing。利用 ARM ETM 跟踪目标 loadable kernel module 的 control flow 和 data access，不需要模块源码，也不要求修改主内核。通过 kernel driver 管理 ETM/ETB/PMU，并对目标模块的入口、出口和外部函数调用进行 hook。
2. 支持小 ETB 的连续 trace。特别处理低端 SoC 上 ETB 很小的问题（如 i.MX53 QSB 只有 4KB ETB）。使用 PMU instruction counter 在 ETB 填满前触发中断，将 ETB 中 trace 及时备份，避免被覆盖。
3. Selective module tracing。由于 PMU 默认统计整颗 CPU 的指令，通过模块入口/出口 wrapper 控制 PMU，只在目标模块执行时计数和触发 trace 管理。
4. Elastic decoding。设计 trace backup 与 decoding 的并行机制，并根据 trace 生成速度调整 decoding thread 调度，避免 decoder 忙等。
5. HASAN。在 HART 之上构建 modular AddressSanitizer，面向目标 kernel module 的 heap memory corruption 检测。
6. 实验评测。在 i.MX53 QSB 上评测 6 个常用 kernel modules，平均 overhead 约 5%（HART）/ 6%（HASAN）；最坏 HFS+ case 约 12%/13%。HASAN 检测 6 个 heap 相关 CVE case。

#### 与 RV-MalTrace 的差异

| 维度 | HART | RV-MalTrace |
|------|------|-------------|
| **目标对象** | Linux kernel modules（binary-only） | 用户态 Linux workload（malware-like behavior） |
| **OS 层级** | **内核空间** | **用户空间** |
| **硬件平台** | ARM Cortex-A8（i.MX53） | RISC-V CVA6 / VexRiscv |
| **Trace 源** | ARM ETM + ETB + PMU | 自定义 RTL trace tap |
| **系统修改** | 需加载内核模块（wrapper 注入） | **零内核修改** |
| **语义恢复** | 指令 trace + 内存访问追踪 | syscall 语义 + 参数 + 进程/文件行为图 |
| **用途** | 在线 kernel module protection（HASAN） | 离线行为审计和证据链 |
| **评测** | 性能开销 + 漏洞检测（CVE） | 合成恶意软件行为 + 抗规避 + 真实恶意软件派生行为 |

**关键差异解读**：HART 和 RV-MalTrace 都利用**硬件 trace 实现非侵入式（相对）监控**，但 HART 监控的是**内核模块**（kernel space），RV-MalTrace 监控的是**用户空间程序**（user space）。HART 必须修改内核模块加载过程（wrapper 注入），而 RV-MalTrace 的 threat model 明确将**恶意内核模块和内核 rootkit 排除在外**。HART 的 ETM 是 ARM 标准调试特性，RV-MalTrace 的 trace tap 是**自主 RTL 设计**（非标准调试 IP）。HART 的评估是**性能开销 + 漏洞检测能力**，RV-MalTrace 的评估是**行为重建正确性 + 抗规避能力**。

> **值得学习的点**：HART 的 PMU 周期采样 + ETB 备份机制，对 RV-MalTrace 未来解决**连续 trace 流导出**（streaming/DMA）有启发；HART 的"最小配置即可工作"务实路线与 RV-MalTrace 的 35T 小容量 BRAM 策略类似。

#### 写作启示

**推荐写法**：

> HART demonstrates that hardware trace can reduce kernel-module protection overhead. RV-MalTrace instead designs RISC-V committed behavior events and semantic provenance checks for audit-oriented malware-like behavior reconstruction.

**需要避免**：

> 把我们的系统写成 kernel module protection；  
> 声称我们能检测 kernel CVE；  
> 声称我们能抵抗 malicious kernel module；  
> 把 HART 的 ETM data access trace 等同于我们的 bounded pointer snapshot。

---

### 2.4 Raft（RAID 2023）

#### 论文核心

Raft 提出一个 RISC-V 上的硬件辅助 Dynamic Information Flow Tracking（DIFT）框架。是五篇中**平台最接近**的一篇，因为同属 RISC-V hardware-assisted security。

**主要贡献**：

1. RISC-V Rocket Core coprocessor-based DIFT。作为 Rocket Core 的 coprocessor，通过提交日志和 RoCC-like interface 获取与 DIFT 相关的指令信息，在 coprocessor 中执行 tag propagation 和 tag checking。
2. 过滤 DIFT-unrelated instructions。在硬件侧过滤不影响 tag propagation 的指令，减少 coprocessor 处理量。
3. Hybrid byte/variable granularity tag storage。传统 shadow memory 需要主核访问内存获取 tag，通信开销大。Raft 将 tag storage 保留在 coprocessor 中：stack/data 等区域使用 byte-level tag；heap 使用 variable-level tag；register tag 存在 shadow register file。
4. Runtime protection policy interface。支持程序员配置 source、sink 和安全策略，对 untrusted data flow 进行运行时检查。
5. 实验评测。在 Rocket emulator 和 FPGA development board 上部署。NBench/CoreMark 上 overhead 从 20%+ 降到 <0.1%；SPEC CINT 2006 上约 0.13%。硬件成本报告 LUT/FF/power。
6. 局限性讨论。不处理 implicit flows；当前聚焦 single processor without multithreading；多线程、多核和 rich OS 场景需额外机制。

#### 与 RV-MalTrace 的差异

| 维度 | Raft | RV-MalTrace |
|------|------|-------------|
| **核心目标** | 运行时数据流防护（DIFT） | 行为流审计（Behavioral Trace） |
| **ISA/平台** | RISC-V Rocket Core | RISC-V CVA6 / VexRiscv |
| **硬件架构** | **协处理器**（RoCC 接口），主核可停顿 | **片上 trace tap**（旁路捕获，非主核停顿） |
| **追踪对象** | 数据流（taint propagation）：load/store/ALU tag | 控制流 + OS 语义事件（syscall、trap、priv） |
| **粒度** | 字节/变量级数据标记 | 事件级（syscall entry/ret、trap、branch） |
| **系统修改** | 自定义指令 + 编译器插桩 + Linux 内核修改 | **无需编译器插桩，无需内核修改**（MVP 无 eBPF） |
| **对程序透明** | 不透明（需插桩、自定义指令） | **对程序透明**（无插桩、无内核修改、无 OS 依赖） |
| **语义恢复** | 无 syscall 语义；关注数据污染到 sink 的流 | syscall 序列、参数、fd、path、进程树恢复 |
| **用途** | 在线 enforcement（实时阻止违规） | 离线审计（行为解释和证据链） |
| **开销控制** | 协处理器并行，主核几乎零停顿 | BRAM 容量限制，当前 cycle 开销未闭合 |
| **Rich OS 支持** | 自述 multithreading、rich OS 扩展有复杂性 | 已将 Linux 层 provenance（PIE/ASLR、fork/exec、动态库）纳入 artifact gates |

**关键差异解读**：Raft 和 RV-MalTrace 都基于 RISC-V，是**最直接的同平台对比**。但两者是**正交技术**：Raft 是**数据流安全**（DIFT，防止恶意输入到达安全敏感操作），RV-MalTrace 是**行为流审计**（观察程序做了什么 syscall、如何创建进程、如何操作文件）。Raft 需要**编译器插桩和自定义指令**（程序必须配合），RV-MalTrace 强调**零插桩、零内核修改**（对程序完全透明）。Raft 对主核是**侵入式**的（协处理器中断可停顿主核），RV-MalTrace 是**旁路式**的（trace tap 不介入执行）。

> **值得学习的点**：Raft 在 RISC-V 上的协处理器集成经验、低开销设计思路、以及 RoCC 接口的利用方式，可为 RV-MalTrace 未来可能的片上分析模块（如硬件规则匹配）提供参考。

#### 写作启示

**推荐写法**：

> Raft demonstrates low-overhead hardware-assisted DIFT on a RISC-V Rocket core by moving hybrid-granularity tag storage into a coprocessor. RV-MalTrace targets a different abstraction: it exports committed syscall, trap, privilege, marker, drop, and bounded pointer events from a RISC-V/CVA6 trace path, then reconstructs Linux behavior provenance offline rather than enforcing taint policies online.

**需要避免**：

> Raft is similar to our malware trace system.  
> RV-MalTrace provides runtime protection like Raft.  
> RV-MalTrace is lower overhead than Raft.

---

### 2.5 μAFL（ICSE 2022）

#### 论文核心

μAFL 提出一个面向 ARM microcontroller firmware 的非侵入式 feedback-driven fuzzing 框架。关注 MCU firmware fuzzing 中 rehosting/peripheral modeling 不准确、driver code 难以测试、hardware-in-the-loop 同步开销高的问题。

**主要贡献**：

1. Hardware-in-the-loop firmware fuzzing。将 fuzzing manager 保留在 PC 上，target firmware 直接运行在真实 MCU board 上，通过 debug dongle 连接。避免 QEMU rehosting 对 peripheral behavior 的不准确建模。
2. AFL-compatible 架构。将 execution engine 与 AFL 的 fuzzing manager 解耦，复用 AFL mutation、queue、crash handling 等机制。
3. 基于 ETM 的非侵入式 coverage collection。使用 ARM ETM 采集 instruction trace，避免给 firmware 插桩。ETM trace 通过 debug dongle streaming 到 PC。
4. 使用 DWT 做在线过滤。使用 Data Watchpoint and Trace 单元控制 ETM on/off，只收集 testcase main logic 范围内的 trace，降低 boot、scheduler、interrupt handler 等噪声。
5. 不完整解码 ETM 的 coverage 表示。完整恢复 instruction flow 需要 disassembly 和 ETM packet alignment，代价高。提出基于 raw ETM packet 的 LCSAJ_BB-like coverage 表示，保留 AFL 所需 path sensitivity，同时避免完整 disassembly。
6. 真实 firmware bug 发现。在 NXP 和 STMicroelectronics 真实评估板与 SDK 上评测。两天 fuzzing 发现 13 个 zero-day bugs，其中 8 个分配 CVE。案例集中在 USB driver descriptor parsing、length sanitization 等。

#### 与 RV-MalTrace 的差异

| 维度 | μAFL | RV-MalTrace |
|------|------|-------------|
| **目标问题** | 固件安全测试（fuzzing 漏洞发现） | Linux 工作负载恶意软件行为审计与证据链 |
| **ISA/平台** | ARM Cortex-M（MCU，裸机/RTOS） | RISC-V CVA6 / VexRiscv（应用处理器，Linux） |
| **Trace 源** | ARM ETM（指令流分支包） | 自定义 RTL trace tap（commit log / RVFI 适配） |
| **事件粒度** | 指令级基本块转移（branch taken/not taken） | **多事件语义**：syscall、trap、CSR、SATP、PRIV、ARG_MEM、DROP 等 |
| **语义恢复** | 仅覆盖率（bitmap），无 syscall/语义 | syscall 序列、参数、fd/path 图、进程树、行为规则匹配 |
| **系统修改** | 零修改（纯 debug 接口） | 需要 RTL 修改（trace 模块）、FPGA 综合、Linux 启动 |
| **透明性** | 对固件透明（非目标问题） | 低侵入性，强调抗规避（anti-debug、timing、direct-syscall 等验证） |
| **输出** | AFL 覆盖率 bitmap | JSONL trace 流 + 行为图 + 审计规则命中 |
| **评估** | 发现真实漏洞（CVE） | 合成恶意软件行为矩阵 + 真实恶意软件派生行为验证 |

**关键差异解读**：μAFL 是**安全测试工具**（找 bug），RV-MalTrace 是**行为审计证据链**（追行为）。两者虽然都用硬件 trace 避免插桩，但 μAFL 利用的是 ARM ETM 的**指令覆盖率**，而 RV-MalTrace 构建的是**操作系统语义事件**。μAFL 不需要理解操作系统语义（无 OS 或 RTOS 无关），RV-MalTrace 的核心挑战恰恰是**从裸指令流恢复 Linux syscall 语义**。此外，μAFL 的 ETM 是 ARM 厂商标准 IP，RV-MalTrace 的 trace tap 是**自定义 RTL 设计**，在 RISC-V 开源生态中自主可控。

#### 写作启示

**推荐写法**：

> microAFL uses ARM ETM and DWT as non-intrusive feedback for MCU firmware fuzzing, converting raw trace packets into path-sensitive coverage. RV-MalTrace uses a different trace abstraction and objective: committed RISC-V behavior events are retained and joined with OS/runtime metadata to explain malware-like behaviors rather than to guide testcase generation.

**需要避免**：

> 拿我们 35T/Genesys2 的 safe surrogate audit 去类比 CVE discovery；  
> 声称我们的 trace 也用于 fuzzing 或漏洞发现。

---

## 3. 横向综合差异矩阵

| 维度 | Ninja (SEC'17) | Ninja (TIFS'19) | HART (ESORICS'20) | Raft (RAID'23) | μAFL (ICSE'22) | **RV-MalTrace** |
|------|---------------|-----------------|-------------------|----------------|----------------|-----------------|
| **核心目标** | 透明 malware 分析/调试 | 透明分析 + 系统恢复 | 内核模块追踪/保护 | 运行时 DIFT 防护 | 固件 fuzzing | **行为审计证据链** |
| **ISA/平台** | ARMv8 Juno | ARMv8 Juno | ARM Cortex-A8 | RISC-V Rocket | ARM Cortex-M | **RISC-V CVA6/35T** |
| **OS 环境** | Android/Linux | Android/Linux | Linux 内核 | Linux/嵌入式 | 裸机/RTOS | **Linux 用户态** |
| **硬件机制** | TrustZone + PMU + ETM | TrustZone + PMU + ETM + data addr | ETM + ETB + PMU | RoCC 协处理器 + tag storage | ETM + DWT + debug dongle | **自定义 RTL trace tap** |
| **系统修改** | 定制 TrustZone 固件 | 定制 TrustZone 固件 | 内核模块 wrapper | 编译器+内核+自定义指令 | 零修改 | **零修改（MVP）** |
| **对程序透明** | 是（TrustZone 隔离） | 是（TrustZone 隔离） | 部分（内核 wrapper） | 否（需插桩） | 是（裸机无 OS） | **是（RTL 旁路）** |
| **事件粒度** | 指令级 + syscall + API | 指令级 + syscall + API + memory | 指令级 + 内存访问 | 数据流操作 | 指令级分支 | **OS 语义事件** |
| **语义恢复** | 指令/syscall/API | 指令/syscall/API/memory | 指令 + 内存 | 无（仅 taint tag） | 无（仅覆盖率） | **syscall+参数+fd/path+进程** |
| **在线/离线** | 在线 trace/debug + 部分离线 | 在线 + 恢复 | 在线 trace + decoder + HASAN | 在线 tag enforcement | 在线运行 + 离线 coverage | **硬件采集 + 离线语义重建** |
| **抗规避** | **核心目标** | **核心目标** | 非目标 | 非目标 | 非目标 | **核心目标（验证通过）** |
| **评测重点** | 透明度 + overhead + malware | 透明度 + 恢复 latency + overhead | overhead + CVE 检测 | overhead + 硬件成本 | 漏洞发现数量 | **行为正确性 + 抗规避 + artifact gates** |
| **输出形式** | trace 流 + debug 接口 | trace 流 + 恢复机制 | 解码后指令 trace | 安全违规中断 | AFL bitmap | **JSONL + 行为图 + 审计报告** |

---

## 4. RV-MalTrace 的相对优势与差距

### 4.1 相对优势（与五篇论文相比）

1. **自主 RTL 设计，不依赖厂商调试 IP**
   - μAFL、HART、Ninja 均依赖 ARM ETM/ETB/PMU 等标准调试 IP，平台可移植性受 ARM 生态限制。
   - RV-MalTrace 的 trace tap 是**自定义 RTL**，可适配任何支持 RVFI 或 commit log 的 RISC-V core，在开源硬件生态中可控性更强。

2. **零系统软件修改**
   - HART 需内核模块 wrapper，Ninja 需 TrustZone 固件，Raft 需编译器插桩和内核修改。
   - RV-MalTrace 的 MVP 明确**无 eBPF、无 kernel helper、无编译器插桩**，对内核、固件、用户态程序均零修改。

3. **OS 语义事件原生捕获**
   - μAFL 只有指令覆盖率；Raft 只有数据流；HART 只有指令 trace；Ninja 有 syscall trace 但需 ETM 解码。
   - RV-MalTrace 在 RTL 层直接发出 **SYSCALL_ENTRY、SYSCALL_RET、TRAP、PRIV、SATP** 等语义事件，无需从指令流解码即可恢复系统调用序列。

4. **自动化行为审计**
   - Ninja 是人工分析工具（trace + debug 接口）。
   - RV-MalTrace 有**自动化行为规则匹配**（`illegal_instruction_trap`、`process_creation_chain`、`dynamic_executable_memory` 等），面向可审计的证据链。

5. **RISC-V 生态差异化定位**
   - 五篇论文中有四篇基于 ARM，一篇基于 RISC-V（Raft）但做 DIFT 而非行为追踪。
   - RV-MalTrace 是**RISC-V 上首个面向恶意软件行为审计的硬件 trace 框架**，填补该生态空白。

6. **Linux 层 provenance 已纳入证据**
   - Raft 自述 multithreading、rich OS 扩展仍有复杂性。
   - RV-MalTrace 当前主线已将 PIE/ASLR load bias、runtime process maps、动态库、fork/exec ownership、stripped ELF 降级等纳入 artifact gates。

### 4.2 当前差距（需补强的方向）

1. **Trace 导出能力**
   - μAFL、HART、Ninja 均有成熟的 trace 流导出机制（ETM 通过 SWD/JTAG 实时流式）。
   - RV-MalTrace 当前使用 **BRAM 环形缓冲 + ILA/JTAG dump**，容量严重受限（512 条记录），且无生产级 streaming/DMA 路径。

2. **性能开销闭合**
   - Raft 给出精确 benchmark 开销（<0.1%）；HART 给出 5-6% 开销；Ninja 也评估了性能影响。
   - RV-MalTrace 的 **cycle-level 开销尚未闭合**（`BLOCKED_SD_CARD_LINUX_SOURCE_MISSING`），目前仅有 UART runtime smoke 测试，缺少精确硬件计数器测量。

3. **真实恶意软件验证**
   - μAFL 发现真实 CVE；Ninja 分析真实 Android 恶意软件。
   - RV-MalTrace 当前仅验证**合成恶意软件行为**和**真实恶意软件派生行为**（DarthRa/Mirai 的行为子集），尚未执行完整真实恶意软件 payload。

4. **Source-level 归因**
   - HART 和 Ninja 的指令 trace 可精确到指令地址；RV-MalTrace 当前有 ELF 符号级归因，但**源行级归因（DWARF）** 仅在 board-native 外部摘要中接受，尚未成为核心能力。

5. **平台成熟度**
   - Ninja 在 ARM Juno 开发板上运行；μAFL 在 NXP/STM32 评估板上运行；HART 在 i.MX53 上运行；Raft 在 FPGA 和仿真器上运行。
   - RV-MalTrace 的 **CVA6/Genesys2 板级验证**仍有多个外部闭合项（board cycle overhead、JTAG RAM boot、production streaming/DMA）。

---

## 5. 推荐相关工作组织方式

建议在论文 Related Work 中分**四组**组织，而非按年份罗列：

### 5.1 Hardware-assisted Transparent Malware Analysis

放 Ninja USENIX 2017 和 TIFS 2019。重点承认它们在 ARM TrustZone/CoreSight 透明分析方面的贡献，然后说明我们不追求 secure-world interactive debugging 或 continuous restoration，而是 RISC-V/Linux committed-event semantic provenance。

### 5.2 Hardware Trace for Kernel Protection

放 HART。重点说明 HART 面向 kernel module 和 memory safety protection，而我们面向用户态/系统行为审计和证据重建。

### 5.3 RISC-V Hardware-Assisted Runtime Security

放 Raft。重点说明同为 RISC-V hardware-assisted security，但 Raft 是 DIFT enforcement，我们是 trace/provenance/audit。这是审稿人最可能直接对比的段落，需**单独成段**并写得最清晰。

### 5.4 Hardware-in-the-Loop Firmware Analysis/Fuzzing

放 μAFL。重点说明它把 ETM trace 转为 fuzzing coverage，我们把硬件 trace 保留为行为证据。

---

## 6. 我们当前最需要补强的对比点

这些相关工作也暴露出我们当前容易被问到的问题：

1. **Overhead 证据**。Ninja、HART、Raft 都有较清楚的 overhead 数字。我们当前 cycle-level overhead 和 production streaming/DMA 仍 open/blocker。若目标是 A 会投稿，这会是**高优先级补强项**。

2. **Trace capacity / loss 处理**。HART 对小 ETB 和 continuous trace 处理很具体。我们需要把 `EVT_DROP`、BRAM ring、marker window、streaming/DMA plan 写清楚，尤其要区分当前 PASS 和未来 target。

3. **透明性边界**。Ninja 系列很强，审稿人可能问 malware 是否能发现 RV-MalTrace。我们应主动声明当前不是 Ninja-style transparent debugging，不对 malicious kernel/rootkit 做强主张。

4. **真实样本/真实漏洞结果**。μAFL 有 CVE，HART 有 CVE cases，Ninja 有 malware/rootkit case。我们当前只能做 safe surrogate / real-malware-derived behavior rows，不应扩张为 real malware detection accuracy。若后续要走安全顶会，真实样本伦理/containment 和独立验证需要更强。

5. **RISC-V 直接相关工作**。Raft 是最直接的 RISC-V 对比。我们需要在 introduction 和 related work 中清楚说出"不是 DIFT，不做 runtime enforcement"，并强调我们的 OS-level semantic provenance 是不同贡献。

---

## 7. 可直接使用的差异表述

### 7.1 推荐使用的句子

```text
Prior ARM systems such as Ninja and HART reuse CoreSight/ETM facilities for transparent malware analysis or kernel-module protection. RV-MalTrace instead instruments a RISC-V core to emit committed behavior events and reconstructs Linux-level semantic provenance from those events.
```

```text
Raft demonstrates low-overhead RISC-V DIFT by propagating tags in a coprocessor. RV-MalTrace targets a different abstraction: syscall, trap, privilege, marker, drop, and bounded pointer events are used to explain observed behaviors rather than to enforce taint policies online.
```

```text
microAFL consumes ETM traces as path-sensitive coverage feedback for MCU firmware fuzzing. RV-MalTrace preserves trace records as audit evidence and joins them with runtime process, ELF, fd/path, and provenance metadata.
```

```text
Our current claims are bounded: safe malware-like and real-malware-derived behavior evidence do not imply real malware family accuracy, IOC coverage, TTP coverage, or a mature detector.
```

### 7.2 绝对避免的说法

```text
RV-MalTrace is transparent like Ninja.
RV-MalTrace detects real malware.
RV-MalTrace provides runtime protection like Raft.
RV-MalTrace finds vulnerabilities like microAFL.
RV-MalTrace protects kernel modules like HART.
```

---

## 8. 结论

这五篇论文和我们都处在"硬件辅助低侵入观测/安全分析"的大方向下，但它们分别解决的是不同问题：

- **Ninja 系列**解决 ARM 透明 tracing/debugging 和连续 malware analysis 恢复。
- **HART**解决 ARM 二进制 kernel module 的低开销追踪和 heap memory protection。
- **Raft**解决 RISC-V DIFT runtime protection 的 tag storage 和 overhead 问题。
- **μAFL**解决 ARM MCU firmware fuzzing 的高保真 coverage feedback 问题。
- **RV-MalTrace**当前应定位为 **RISC-V/Linux committed behavior tracing + semantic provenance + artifact-backed behavior evidence chain**。

**最重要的写作策略**是：承认这些工作在透明性、overhead、CVE/漏洞发现、runtime protection 上更强；同时把我们的贡献收紧到 **RISC-V committed-event 语义证据链**，并诚实标出当前未闭环的 cycle overhead、production streaming/DMA 和 real malware validation 边界。

> **一句话总结**：别人用硬件 trace 做"防护"（DIFT、kernel sanitizer）或"分析"（透明调试、模糊测试）；我们用硬件 trace 做"行为证据"——从 RISC-V 指令流水线直接提取操作系统语义事件，形成可审计、可校验、可解释的恶意软件行为证据链。
