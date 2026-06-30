# RV-MalTrace Related Work Comparison Report

生成日期：2026-06-29

适用范围：`docs/relate-work/` 下导师给出的五篇相关论文。

## 0. 当前 RV-MalTrace 基线

为了避免比较对象漂移，本报告把“我们目前的工作”按仓库当前状态理解为：

- 当前主线：Genesys2 / CVA6 / RISC-V 硬件辅助行为追踪证据包。
  核心是从 CVA6 committed-event trace RTL 采集 syscall、trap、privilege、CSR/context、drop、marker 等事件，再结合 ELF、runtime process map、动态库、fork/exec ownership、fd/path、pointer string 等语义信息进行离线重建和证据链校验。
- 补充路线：Artix-7 35T / LiteX / VexRiscv bounded prototype。
  核心是 512-record small-capacity trace policy、controlled benign + synthetic malware-like matrix，以及 35T 上 real-malware-derived behavior rows 的安全受控行为验证。
- 当前不能扩张的主张：不能声称真实恶意软件检测准确率、成熟检测器、完整语义重建、生产级 streaming/DMA throughput、完整 cycle overhead、kernel rootkit resistance，或 uncontrolled/network-enabled malware execution。

因此，本报告里的“差异”主要围绕以下维度展开：

1. 平台：ARM TrustZone/CoreSight/ETM、ARM MCU、RISC-V Rocket、RISC-V CVA6/FPGA。
2. 目标：透明调试、内核模块保护、DIFT 运行时防护、firmware fuzzing、行为语义证据链。
3. 观测抽象：原始指令/控制流 trace、ETM packet、DIFT tag、coverage bitmap、committed behavior event。
4. 语义路线：在线调试、在线 enforcement、coverage feedback、离线 syscall/process/file/provenance 重建。
5. 评测证据：overhead、漏洞发现、真实恶意样本、safe surrogate、artifact gate、board evidence。

## 1. 总览对比

| 文件 | 论文 | 主要方向 | 与我们最核心的关系 |
| --- | --- | --- | --- |
| `sec17-ning.pdf` | Ninja: Towards Transparent Tracing and Debugging on ARM, USENIX Security 2017 | ARM TrustZone + PMU + ETM 透明 tracing/debugging | 相邻工作。它证明硬件 debug/trace 可用于透明 malware analysis，但其核心是 ARM 透明调试，不是 RISC-V 语义证据链。 |
| `ninja-tifs19.pdf` | Hardware-Assisted Transparent Tracing and Debugging on ARM, TIFS 2019 | Ninja 扩展版，加连续 malware analysis 的快速系统恢复 | 相邻工作。它比 USENIX 版多了 restoration，我们目前没有同类系统恢复贡献。 |
| `hart-esorics20.pdf` | HART: Hardware-assisted Kernel Module Tracing on Arm, ESORICS 2020 | ARM ETM 跟踪二进制内核模块，并构建 HASAN | 相邻偏近。它关注 kernel module vulnerability protection，我们关注用户态/系统行为 trace 和语义重建。 |
| `3607199.3607246.pdf` | Raft: Hardware-assisted Dynamic Information Flow Tracking for Runtime Protection on RISC-V, RAID 2023 | RISC-V Rocket coprocessor DIFT runtime protection | 最接近的 RISC-V 硬件安全相关工作，但目标是 taint/tag enforcement，不是 trace/provenance/audit。 |
| `3510003.3510208.pdf` | microAFL: Non-Intrusive Feedback-driven Fuzzing for Microcontroller Firmware, ICSE 2022 | ARM MCU ETM/DWT 硬件在环 fuzzing | 相邻工作。它用硬件 trace 产生 coverage feedback 找 firmware bug，我们用硬件 trace 解释行为。 |

一句话定位：

```text
这些论文共同说明“硬件辅助低侵入观测”是成熟方向；我们的差异不在于也用了硬件 trace，而在于面向 RISC-V/Linux committed behavior event 的语义重建、证据链和 bounded malware-like behavior audit。
```

## 2. Ninja USENIX Security 2017

### 2.1 论文主要贡献

`sec17-ning.pdf` 的核心贡献是提出 Ninja，一个 ARM 平台上的透明 malware tracing/debugging 框架。它的出发点是：传统 emulator、VM、ptrace、strace、Android runtime instrumentation 或内核修改都会留下可检测指纹，evasive malware 可以据此隐藏恶意行为。因此 Ninja 试图把分析环境放到目标软件难以观察和篡改的位置。

具体贡献包括：

1. ARM TrustZone 隔离环境中的透明分析框架。
   Ninja 把 analyzer 放在 secure world，通过 TrustZone 隔离普通世界中的 Android/Linux 和目标应用。它不依赖 QEMU、虚拟机、ptrace/strace，也不修改 Android framework 或 Linux kernel，因此相比软件分析工具更难被普通世界代码直接观察。

2. 基于 PMU 和 ETM 的 tracing subsystem。
   Ninja 利用 ARM PMU 事件和 ETM trace 能力支持多种粒度的观测，包括 instruction tracing、system call tracing 和 Android API tracing。system call tracing 通过配置 ETM 跟踪 PMU 的 `EXC_SVC` 事件实现，Android API tracing 则依赖 PMU 事件和 domain switch。

3. GDB-like debugging subsystem。
   Ninja 支持远程调试命令，通过 secure serial port 和 secure monitor 交互，允许分析者读写寄存器、内存、设置断点、单步等。它的调试不通过普通世界调试接口暴露给目标软件。

4. 透明性增强机制。
   由于 PMU/ETM 寄存器和 memory-mapped interface 可能被目标代码探测，Ninja 设计了系统寄存器访问 trap、memory mapping interception、人工 PMU/ETM register view、timer adjustment 等机制，减少分析器痕迹。

5. 实验评测。
   论文在 ARM Juno 和 i.MX53 QSB 等平台上验证框架。案例包括 DroidBench 中的信息泄露样本，以及 Suterusu rootkit 的内核 text section 修改行为。性能方面，instruction tracing 和 system call tracing 的开销很小，论文报告为小于 1% 或可忽略；Android API tracing 由于频繁 domain switch 和 semantic gap bridging，开销较大，可达到 4x 到 154x。

### 2.2 Ninja 和我们的差异

#### 目标差异

Ninja 的目标是透明 malware analysis 和 interactive debugging。它主要回答的问题是：

```text
能否在 ARM 设备上低痕迹地观察和调试 evasive malware？
```

我们当前主线回答的问题不同：

```text
能否在 RISC-V/CVA6 上从 committed hardware events 出发，重建 Linux syscall/process/file/path/provenance 行为证据，并形成可校验 artifact chain？
```

因此，Ninja 是透明调试器/分析框架，我们是行为证据链系统。我们不应把自己写成 Ninja 的 RISC-V 复刻版。

#### 平台差异

Ninja 依赖 ARM TrustZone、PMU、ETM、secure monitor，以及 ARM CoreSight debug/trace 生态。我们依赖自定义 FPGA RTL trace tap、CVA6/RVFI/committed event adapter、BRAM/ILA 或后续 streaming sink。我们的 trace 来源是可综合 RTL 和 RISC-V committed pipeline/context，而不是 ARM 已有 ETM packet。

这带来两个后果：

- Ninja 的优势是使用 off-the-shelf ARM 硬件特性，透明性论述更强。
- 我们的优势是 trace event schema 可以围绕 RISC-V syscall/trap/context/provenance 设计，事件语义更贴近论文主张。

#### 观测抽象差异

Ninja 直接利用 ETM instruction/control-flow trace 和 PMU events，再由 analyzer 跨 semantic gap。我们的 trace format 是结构化 committed behavior event，包括 `SYSCALL_ENTRY`、`SYSCALL_RET`、`TRAP`、`CSR`、`SATP`、`PRIV`、`ARG_MEM`、`DROP`、`MARKER` 等。

换句话说，Ninja 更接近“硬件 debug trace + secure analyzer”，我们更接近“硬件事件语义接口 + 离线 provenance reconstruction”。

#### 威胁模型差异

Ninja 明确面向 evasive malware 和部分 privileged malware 场景，强调减少 PMU/ETM 可见痕迹。我们当前 threat model 更保守：trusted kernel、user-mode malware-like workload、kernel rootkit out of scope。我们不能声称对 privileged malware、malicious kernel 或 kernel module tampering 具有 Ninja 式透明性。

#### 评测差异

Ninja 的评测重点是透明性实验、调试/trace 功能、真实或代表性 malware/rootkit 案例和 overhead。我们当前评测重点是 trace correctness directed fixtures、semantic provenance、local code analysis、board evidence、artifact integrity、safe surrogate audit、bounded pointer strings 等。

Ninja 对 overhead 的闭环比我们当前主线更成熟。我们当前 cycle-level overhead、production streaming/DMA throughput 仍是 blocked/open。因此，相关工作中不能写成“我们也达到低开销透明分析”，只能写成“我们提供了 RISC-V/Linux 语义证据链，性能/production transport 是当前边界或后续项”。

### 2.3 对我们写作的启示

Ninja 应放在“transparent hardware-assisted malware analysis on ARM”段落。推荐写法：

```text
Ninja shows that ARM TrustZone, PMU, and ETM can support low-artifact tracing and debugging for evasive malware analysis. RV-MalTrace differs by instrumenting a RISC-V core to export committed behavior events and by focusing on Linux semantic provenance and artifact-backed behavior reconstruction rather than interactive transparent debugging.
```

需要避免的写法：

```text
RV-MalTrace is transparent like Ninja.
RV-MalTrace can analyze privileged malware like Ninja.
RV-MalTrace achieves Ninja-level overhead.
```

## 3. Ninja TIFS 2019

### 3.1 论文主要贡献

`ninja-tifs19.pdf` 是 Ninja 工作的扩展版本。它保留 USENIX Security 2017 版的 ARM TrustZone + PMU + ETM 透明 tracing/debugging 设计，同时加入了面向连续 malware analysis 的快速系统恢复机制。

主要贡献包括：

1. 扩展透明 tracing/debugging 框架。
   论文继续强调不依赖 emulator、VM 或系统软件修改，通过 secure world 中的 tracing/debugging subsystem 观察 normal world 目标。

2. 引入 data address tracing。
   相比 USENIX 版主要强调 instruction/system call/API trace，TIFS 版进一步使用 ETM data address trace 分析内存写入位置，为 selective memory restoration 提供依据。

3. 快速系统恢复机制。
   连续分析多个 malware sample 时，前一个样本可能污染内存、文件系统或寄存器状态。TIFS 版设计了三部分恢复：
   - selective memory restoration：只恢复被样本修改过的内存区域；
   - file system switching：利用类似 `pivot_root` 的机制快速切换文件系统；
   - register/context restoration：恢复可能影响后续分析的寄存器状态。

4. 性能与恢复评测。
   论文报告 ETM-based instruction/system call/data address tracing 开销可忽略或低于 0.1%。Android API tracing 仍然较重。系统恢复方面，论文报告恢复耗时从约 0.029s 到 2.160s，且在小 changed-memory 场景下 selective restoration 明显快于 full memory restoration。

### 3.2 TIFS Ninja 和我们的差异

#### 新增贡献点差异

TIFS 版最突出的新增贡献是连续 malware analysis 的系统恢复。我们目前没有对应能力：

- 没有 sample execution 后自动恢复板上 Linux/内存/文件系统到 clean snapshot 的系统机制。
- 没有把 trace 用于 changed-memory restoration。
- 没有把多样本连续恶意软件分析作为主贡献。

因此，如果审稿人拿 TIFS Ninja 比较，我们应明确：我们不是 bare-metal malware sandbox，也不解决连续样本恢复；我们解决的是 RISC-V committed event 到 Linux behavior provenance 的可审计证据链。

#### Memory trace 使用边界差异

TIFS Ninja 使用 data address trace 支持恢复和 rootkit 修改分析。我们的 memory 语义路线更保守：

- 默认不启用 full memory trace。
- `ARG_MEM` 是 syscall-scoped、bounded、gated 的 pointer snapshot。
- full hardware pointer strings 仅限 accepted scoped evidence，不等于完整内存 dump 或 kernel memory capture。

这点是我们的重要边界。不能为了对标 TIFS Ninja 而把当前 pointer snapshot 写成全局 data trace。

#### 评测成熟度差异

TIFS Ninja 对 tracing overhead 和 restoration latency 有清晰实验。我们当前主线对 trace correctness、semantic provenance、artifact integrity 更强，但 cycle overhead 和 production streaming/DMA 仍未闭环。写作时应把比较维度错开：

- 不和 TIFS Ninja 拼 transparent restoration；
- 强调 RISC-V/Linux semantic event schema 和 evidence gates；
- 诚实列出 production overhead/transport 仍是 open/blocker。

### 3.3 对我们写作的启示

TIFS Ninja 和 USENIX Ninja 可以合并到一个 related-work 小节中，但需要说明 TIFS 版增加了 restoration。推荐写法：

```text
The extended Ninja work further uses ETM data-address tracing for selective system restoration across malware-analysis sessions. RV-MalTrace does not target continuous sandbox restoration; instead, it keeps memory capture disabled by default and uses bounded pointer snapshots only when supported by timing, provenance, and artifact gates.
```

## 4. HART ESORICS 2020

### 4.1 论文主要贡献

`hart-esorics20.pdf` 提出 HART，一个 ARM 平台上的硬件辅助 kernel module tracing 框架。论文关注的问题是第三方 Linux kernel modules 权限高、源码常不可得、已有内核保护方案需要源码或内核大改且开销高。

主要贡献包括：

1. 面向二进制 kernel modules 的 ETM-assisted tracing。
   HART 利用 ARM ETM 跟踪目标 loadable kernel module 的 control flow 和 data access，不需要模块源码，也不要求修改主内核。它通过 kernel driver 管理 ETM/ETB/PMU，并对目标模块的入口、出口和外部函数调用进行 hook。

2. 支持小 ETB 的连续 trace。
   论文特别处理低端 SoC 上 ETB 很小的问题，例如 i.MX53 QSB 只有 4KB ETB。HART 使用 PMU instruction counter 在 ETB 填满前触发中断，将 ETB 中 trace 及时备份，避免被覆盖。

3. Selective module tracing。
   由于 PMU 默认统计整颗 CPU 的指令，HART 通过模块入口/出口 wrapper 控制 PMU，只在目标模块执行时计数和触发 trace 管理，从而减少系统级干扰。

4. Elastic decoding。
   HART 设计 trace backup 与 decoding 的并行机制，并根据 trace 生成速度调整 decoding thread 的调度，避免 decoder 忙等造成额外 overhead。

5. HASAN。
   论文在 HART 之上构建 HASAN，一个 modular AddressSanitizer，面向目标 kernel module 的 heap memory corruption 检测。它不需要模块源码，在一定范围内可检测 buffer overflow、off-by-one、use-after-free、double-free 等。

6. 实验评测。
   HART 在 i.MX53 QSB 上评测 6 个常用 kernel modules，平均 overhead 约 5%；HASAN 平均 overhead 约 6%；在最坏 HFS+ case 中 HART/HASAN 约 12%/13%。HASAN 检测了 6 个 heap 相关 CVE case，覆盖 out-of-bound、use-after-free、double-free 等类别。

### 4.2 HART 和我们的差异

#### 目标对象差异

HART 的目标是 Linux kernel modules，尤其是 binary-only modules。它关心：

```text
如何在不改主内核、没有模块源码的情况下，跟踪并保护第三方内核模块？
```

我们当前主线关心：

```text
如何从 RISC-V/CVA6 committed events 出发，重建用户态 workload 在 Linux 上的 syscall/process/file/path 行为证据？
```

我们不是 kernel module sanitizer，也不检测 kernel heap memory corruption。HART 的内核保护主张不能平移到我们这里。

#### Trace 机制差异

HART 依赖 ARM ETM/ETB/PMU。ETM 产生压缩的 control/data trace，HART 在 kernel driver 中管理备份、解码和 module context。我们是自定义 RTL event trace，事件在硬件侧已经是 syscall/trap/context/drop 等行为事件。两者都面对 trace capacity/overflow 问题，但处理抽象不同：

- HART 的问题是 ETB 太小，trace packet 会被覆盖，需要 PMU 周期性中断备份。
- 我们的问题是 BRAM ring/trace sink 容量、DROP accounting、marker window、未来 streaming/DMA noninterference。

因此，HART 可以作为“小 buffer 下连续追踪和 overflow 管理”的相关工作，但我们的 `EVT_DROP` 和 artifact gate 是不同路线。

#### 语义与用途差异

HART 的 trace 被用于 kernel module protection，HASAN 在线检测 memory violations。我们的 trace 被用于离线语义恢复和审计解释。我们不会对运行中的程序进行 taint/tag enforcement 或 memory safety violation blocking。

这意味着 HART 的“检测 6 个 CVE”是漏洞保护效果，我们不能类比为“检测 malware”或“发现 CVE”。我们的强项应写成“行为可解释、证据可追溯、artifact 可复现”。

#### 评测差异

HART 有明确 runtime overhead 对比和漏洞检测对比，且直接与 KASAN 比较。我们当前主线对 artifact gate 很强，但 production runtime/cycle overhead 仍存在 open items。相关工作写作时，不宜和 HART 正面对比 overhead 成熟度，而应说：

```text
HART demonstrates that hardware trace can reduce kernel-module protection overhead. RV-MalTrace instead designs RISC-V committed behavior events and semantic provenance checks for audit-oriented malware-like behavior reconstruction.
```

### 4.3 对我们写作的启示

HART 很适合放在“hardware trace for kernel protection”段落。可借鉴的点有：

- 小 trace buffer 下的 trace loss/overflow 处理；
- selective tracing 降低噪声；
- binary-only target 的语义 gap；
- 与 sanitizer/软件方案的 overhead 比较方式。

但必须保持边界：

- 不把我们的系统写成 kernel module protection；
- 不声称我们能检测 kernel CVE；
- 不声称我们能抵抗 malicious kernel module；
- 不把 HART 的 ETM data access trace 等同于我们的 bounded pointer snapshot。

## 5. Raft RAID 2023

### 5.1 论文主要贡献

`3607199.3607246.pdf` 提出 Raft，一个 RISC-V 上的硬件辅助 Dynamic Information Flow Tracking 框架。它是五篇中和我们平台最接近的一篇，因为同属 RISC-V hardware-assisted security。

Raft 关注的问题是：软件 DIFT 依赖 dynamic binary instrumentation 或 simulator，overhead 很高；已有硬件 DIFT 虽降低 overhead，但 coprocessor 和 main core 之间通信、shadow memory tag access 仍会导致主核 stall，不适合 time-critical embedded applications。

主要贡献包括：

1. RISC-V Rocket Core coprocessor-based DIFT。
   Raft 作为 Rocket Core 的 coprocessor，通过提交日志和 RoCC-like interface 获取与 DIFT 相关的指令信息，在 coprocessor 中执行 tag propagation 和 tag checking。

2. 过滤 DIFT-unrelated instructions。
   Raft 在硬件侧过滤不影响 tag propagation 的指令，减少 coprocessor 处理量，提高 DIFT pipeline 效率。

3. Hybrid byte/variable granularity tag storage。
   传统 shadow memory 需要主核访问内存获取 tag，通信开销大。Raft 将 tag storage 保留在 coprocessor 中，并设计混合粒度：
   - stack/data 等区域使用 byte-level tag；
   - heap 使用 variable-level tag；
   - register tag 存在 shadow register file。

4. Runtime protection policy interface。
   Raft 支持程序员配置 source、sink 和安全策略，对 untrusted data flow 进行运行时检查。

5. 实验评测。
   论文在 Rocket emulator 和 FPGA development board 上部署。结果显示相比传统 shadow-memory DIFT，Raft 将 NBench/CoreMark 上 20% 以上 overhead 降到小于 0.1%；SPEC CINT 2006 上 overhead 约 0.13%。硬件成本方面，论文报告 LUT/FF/power 等开销。

6. 局限性讨论。
   Raft 不处理 implicit flows；当前聚焦 single processor without multithreading；多线程、多核和 rich OS 场景需要额外 thread ID、多个 tag storage、coherency protocols 等机制。

### 5.2 Raft 和我们的差异

#### 平台接近但问题不同

Raft 和我们都在 RISC-V/FPGA 语境下做硬件辅助安全，这是它最容易被审稿人拿来比较的原因。但两者的核心问题完全不同：

- Raft：如何在运行时低开销传播 taint tags 并阻止/报告策略违规。
- 我们：如何采集 committed behavior events 并离线恢复 syscall/process/file/path/provenance 行为证据。

Raft 属于 runtime enforcement / DIFT；我们属于 behavior tracing / semantic reconstruction / evidence chain。

#### 硬件接口差异

Raft 的硬件接口围绕 instruction commit log、tag propagation、tag checking、coprocessor storage 设计。我们的硬件接口围绕 committed event schema 设计，包括 syscall entry/return、trap、privilege/context、pointer snapshot、drop accounting、marker。

因此，Raft 的“正确性”是 tag propagation 和 security policy 是否正确；我们的“正确性”是事件 capture、syscall pairing、trap/privilege qualification、semantic provenance、trace-code join 是否正确。

#### 语义层次差异

Raft 主要追踪数据流，侧重 source/sink taint policy。它不试图恢复 Linux fd/path/process tree、ELF ownership、dynamic library attribution 或行为图。我们的语义层更贴近操作系统行为审计，但不进行实时 enforcement。

这给我们一个清晰的定位：

```text
Raft protects programs from unsafe data flows; RV-MalTrace explains what behavior occurred and where the evidence came from.
```

#### 评测强弱差异

Raft 的性能论证很强，尤其是 SPEC/NBench/CoreMark overhead 和硬件资源评估。我们当前不能在这个维度上对等声称。我们的强项是：

- directed trace correctness fixtures；
- semantic provenance tags；
- local code-analysis fixtures；
- board artifact integrity；
- safe workload/case-study evidence；
- bounded pointer string external summary。

我们的弱项或 open items 是：

- cycle-level overhead；
- production streaming/DMA throughput；
- real malware validation；
- full generality of pointer strings。

写作时应主动区分评测目标，避免被要求按 Raft 的 runtime-protection 标准交付 DIFT overhead。

#### Rich OS 支持差异

Raft 自述 multithreading、multicore、rich OS 扩展仍有复杂性。我们的当前主线已经把很多 Linux 层 provenance 问题纳入 artifact gates，例如 PIE/ASLR load bias、runtime process maps、dynamic libraries、fork/exec ownership、stripped ELF degradation。这个是我们相对 Raft 的一个可强调差异：

```text
Although Raft targets low-overhead data-flow enforcement, RV-MalTrace focuses on OS-level semantic attribution and evidence provenance for Linux workloads.
```

### 5.3 对我们写作的启示

Raft 应该单独一段，因为它是 RISC-V 硬件安全直接相关工作。推荐写法：

```text
Raft demonstrates low-overhead hardware-assisted DIFT on a RISC-V Rocket core by moving hybrid-granularity tag storage into a coprocessor. RV-MalTrace targets a different abstraction: it exports committed syscall, trap, privilege, marker, drop, and bounded pointer events from a RISC-V/CVA6 trace path, then reconstructs Linux behavior provenance offline rather than enforcing taint policies online.
```

需要避免的写法：

```text
Raft is similar to our malware trace system.
RV-MalTrace provides runtime protection like Raft.
RV-MalTrace is lower overhead than Raft.
```

## 6. microAFL ICSE 2022

### 6.1 论文主要贡献

`3510003.3510208.pdf` 提出 microAFL，一个面向 ARM microcontroller firmware 的非侵入式 feedback-driven fuzzing 框架。论文关注 MCU firmware fuzzing 中 rehosting/peripheral modeling 不准确、driver code 难以测试、hardware-in-the-loop 同步开销高的问题。

主要贡献包括：

1. Hardware-in-the-loop firmware fuzzing。
   microAFL 将 fuzzing manager 保留在 PC 上，将 target firmware 直接运行在真实 MCU board 上，通过 debug dongle 连接 PC 和 board。这样避免了 QEMU rehosting 对 peripheral behavior 的不准确建模。

2. AFL-compatible 架构。
   microAFL 将 execution engine 与 AFL 的 fuzzing manager 解耦，使已有 AFL mutation、queue、crash handling 等机制可以复用。

3. 基于 ETM 的非侵入式 coverage collection。
   microAFL 使用 ARM ETM 采集 instruction trace，避免给 firmware 插桩。ETM trace 通过 debug dongle streaming 到 PC。

4. 使用 DWT 做在线过滤。
   microAFL 使用 Data Watchpoint and Trace 单元控制 ETM on/off，只收集 testcase main logic 范围内的 trace，降低 boot、scheduler、interrupt handler 等噪声。

5. 不完整解码 ETM 的 coverage 表示。
   完整恢复 instruction flow 需要 disassembly 和 ETM packet alignment，代价高。microAFL 提出基于 raw ETM packet 的 LCSAJ_BB-like coverage 表示，保留 AFL 所需 path sensitivity，同时避免完整 disassembly。

6. 真实 firmware bug 发现。
   论文在 NXP 和 STMicroelectronics 的真实评估板与 SDK 上评测。两天 fuzzing campaign 发现 13 个此前未知 bug，其中 8 个分配 CVE。案例集中在 USB driver descriptor parsing、length sanitization、endpoint address、polling interval、hardware support checking 等。

### 6.2 microAFL 和我们的差异

#### 任务目标差异

microAFL 是 fuzzing 工具。它的输出是新的 inputs、coverage、crashes/hangs、bugs/CVEs。我们的输出是 trace、semantic events、behavior graph、case-study evidence、provenance summary、artifact gates。

因此它回答：

```text
如何在真实 MCU 上高保真 fuzz peripheral driver？
```

我们回答：

```text
如何在 RISC-V/Linux 上把硬件事件转化成可审计的 malware-like 行为证据？
```

#### 平台差异

microAFL 面向 ARM Cortex-M MCU 和 bare-metal/RTOS-style firmware，依赖 ETM/DWT/debug dongle。我们面向 RISC-V CVA6/Linux/FPGA，依赖自定义 RTL trace sink、board capture、Linux runtime semantics。

microAFL 的 ETM trace 是现成硬件 debug feature；我们的 trace 是研究系统自身设计的一部分。

#### Trace 用途差异

microAFL 用 trace 计算 coverage bitmap，目标是指导 AFL 生成更好的 testcase。它并不追求 syscall/fd/path/process/provenance 语义。我们用 trace 解释行为，目标是给人和审稿 artifact checker 看的证据链。

这一区别可以写得很清楚：

```text
microAFL consumes trace as fuzzing feedback; RV-MalTrace preserves trace as semantic evidence.
```

#### Harness 与 domain knowledge 差异

microAFL 自述 fuzzing peripheral driver 需要 case-by-case harness，需要找到 driver 与 hardware/peripheral 交互的输入点。我们的 workload 也需要样本设计和 ground truth，但不是 fuzz harness；我们更关注 marker scope、runtime process attribution、trace-code join、semantic recovery target。

#### 结果强弱差异

microAFL 的强结果是发现 13 个 zero-day bugs 和 8 个 CVE。我们当前没有漏洞发现或真实 malware detection accuracy 的结果。不能拿我们 35T/Genesys2 的 safe surrogate audit 去类比 CVE discovery。我们可对比的是：

- microAFL 展示硬件 trace 能帮助 firmware testing；
- 我们展示硬件 trace 能帮助 RISC-V/Linux 行为审计和证据重建。

### 6.3 对我们写作的启示

microAFL 适合放在“hardware trace for firmware analysis/fuzzing”段落。推荐写法：

```text
microAFL uses ARM ETM and DWT as non-intrusive feedback for MCU firmware fuzzing, converting raw trace packets into path-sensitive coverage. RV-MalTrace uses a different trace abstraction and objective: committed RISC-V behavior events are retained and joined with OS/runtime metadata to explain malware-like behaviors rather than to guide testcase generation.
```

## 7. 横向差异矩阵

| 维度 | Ninja | TIFS Ninja | HART | Raft | microAFL | RV-MalTrace 当前路线 |
| --- | --- | --- | --- | --- | --- | --- |
| ISA/平台 | ARMv8/Juno, i.MX53 | ARMv8/Juno, i.MX53 | ARM/i.MX53 | RISC-V Rocket | ARM Cortex-M MCU | RISC-V CVA6/Genesys2, 35T/VexRiscv |
| 硬件特性 | TrustZone, PMU, ETM | TrustZone, PMU, ETM, data address trace | ETM, ETB, PMU | RoCC-like coprocessor, tag storage | ETM, DWT, debug dongle | custom RTL trace, RVFI/CVA6, BRAM/ILA, future streaming |
| 目标 | 透明 tracing/debugging | 透明 tracing/debugging + restoration | kernel module tracing/protection | DIFT runtime protection | firmware fuzzing | behavior trace + semantic evidence chain |
| 在线/离线 | 在线 trace/debug +部分离线分析 | 在线 trace/debug +恢复 | 在线 trace + decoder + HASAN | 在线 tag propagation/enforcement | 在线运行 +离线 coverage analysis | 硬件采集 +离线语义重建/校验 |
| 主要语义 | instruction, syscall, Android API | instruction, syscall, API, memory writes | module control/data access | taint tags/source/sink | coverage/path feedback | syscall, ret, trap, priv, process, fd/path, ELF/provenance |
| 主要评测 | 透明性、rootkit/app case、overhead | 透明性、restoration latency、overhead | overhead、ETB continuity、CVE detection | overhead、hardware cost、DIFT functionality | executions/sec、bugs/CVEs | trace correctness、semantic provenance、artifact gates、safe surrogate |
| 我们不能借用的主张 | 透明调试 privileged malware | 快速恢复 clean system | kernel module CVE protection | runtime taint enforcement | zero-day bug finding | 不适用 |
| 我们可强调的差异 | RISC-V committed event + provenance | memory capture gated, not restoration | behavior audit not kernel sanitizer | OS-level behavior provenance not DIFT | trace-as-evidence not trace-as-coverage | 当前贡献边界 |

## 8. 推荐相关工作组织方式

建议在论文 related work 里分四组，而不是按年份列：

### 8.1 Hardware-assisted transparent malware analysis

放 Ninja USENIX 2017 和 TIFS 2019。重点承认它们在 ARM TrustZone/CoreSight 透明分析方面的贡献，然后说明我们不追求 secure-world interactive debugging 或 continuous restoration，而是 RISC-V/Linux committed-event semantic provenance。

### 8.2 Hardware trace for kernel protection

放 HART。重点说明 HART 面向 kernel module 和 memory safety protection，而我们面向用户态/系统行为审计和证据重建。

### 8.3 RISC-V hardware-assisted runtime security

放 Raft。重点说明同为 RISC-V hardware-assisted security，但 Raft 是 DIFT enforcement，我们是 trace/provenance/audit。

### 8.4 Hardware-in-the-loop firmware analysis/fuzzing

放 microAFL。重点说明它把 ETM trace 转为 fuzzing coverage，我们把硬件 trace 保留为行为证据。

## 9. 我们当前最需要补强的对比点

这些相关工作也暴露出我们当前容易被问到的问题：

1. Overhead 证据。
   Ninja、HART、Raft 都有较清楚的 overhead 数字。我们当前 cycle-level overhead 和 production streaming/DMA 仍 open/blocker。若目标是 A 会投稿，这会是高优先级补强项。

2. Trace capacity / loss 处理。
   HART 对小 ETB 和 continuous trace 处理很具体。我们需要把 `EVT_DROP`、BRAM ring、marker window、streaming/DMA plan 写清楚，尤其要区分当前 PASS 和 future target。

3. 透明性边界。
   Ninja 系列很强，审稿人可能问 malware 是否能发现 RV-MalTrace。我们应主动声明当前不是 Ninja-style transparent debugging，不对 malicious kernel/rootkit 做强主张。

4. 真实样本/真实漏洞结果。
   microAFL 有 CVE，HART 有 CVE cases，Ninja 有 malware/rootkit case。我们当前只能做 safe surrogate / real-malware-derived behavior rows，不应扩张为 real malware detection accuracy。若后续要走安全顶会，真实样本伦理/containment 和独立验证需要更强。

5. RISC-V 直接相关工作。
   Raft 是最直接的 RISC-V 对比。我们需要在 introduction 和 related work 中清楚说出“不是 DIFT，不做 runtime enforcement”，并强调我们的 OS-level semantic provenance 是不同贡献。

## 10. 可直接使用的差异表述

可以使用：

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

不建议使用：

```text
RV-MalTrace is transparent like Ninja.
RV-MalTrace detects real malware.
RV-MalTrace provides runtime protection like Raft.
RV-MalTrace finds vulnerabilities like microAFL.
RV-MalTrace protects kernel modules like HART.
```

## 11. 结论

这五篇论文和我们都处在“硬件辅助低侵入观测/安全分析”的大方向下，但它们分别解决的是不同问题：

- Ninja 系列解决 ARM 透明 tracing/debugging 和连续 malware analysis 恢复。
- HART 解决 ARM 二进制 kernel module 的低开销追踪和 heap memory protection。
- Raft 解决 RISC-V DIFT runtime protection 的 tag storage 和 overhead 问题。
- microAFL 解决 ARM MCU firmware fuzzing 的高保真 coverage feedback 问题。
- RV-MalTrace 当前应定位为 RISC-V/Linux committed behavior tracing + semantic provenance + artifact-backed behavior evidence chain。

最重要的写作策略是：承认这些工作在透明性、overhead、CVE/漏洞发现、runtime protection 上更强；同时把我们的贡献收紧到 RISC-V committed-event 语义证据链，并诚实标出当前未闭环的 cycle overhead、production streaming/DMA 和 real malware validation 边界。
