# RV-MalTrace 下一阶段计划

## 1. 总体研究定位

### 1.1 一句话目标

在 RISC-V/CVA6 上实现一个类似 NCScope 的硬件辅助行为追踪框架：

```text
RISC-V/CVA6 committed execution
    -> RTL trace tap
    -> syscall / control-flow / trap / context / argument-memory trace
    -> Vivado simulation first
    -> FPGA board validation
    -> offline semantic reconstruction
    -> malware behavior graph / anti-analysis detection / system-call semantic audit
```

它不是简单地“在 RISC-V 上复刻 NCScope”，而是把 NCScope 的核心思想迁移到 RISC-V：

| NCScope                             | RISC-V 方案                                                                                               |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------- |
| ARM ETM 提供硬件执行轨迹            | CVA6 RTL commit-stage trace tap                                                                           |
| BPF 补充 syscall/API 参数和内存语义 | 硬件捕获 syscall a0-a7 + syscall return + 可选 eBPF/kernel helper + 可选硬件 user-pointer memory snapshot |
| Android native code 分析            | RISC-V Linux 用户态程序 / malware-like native behavior 分析                                               |
| 函数/API 调用恢复                   | syscall sequence、trap/context、control-flow segment、fd/process/file/network 行为图恢复                  |

## 2. 仅做当前仓库中的 MVP 不够 CCF-A

`rv-maltrace` 现有计划里的 MVP 是合理的工程起点：只做 committed control-flow、syscall、trap、context，不做 full load/store，也不依赖 eBPF。这个路线非常适合 Vivado 可行性验证。

但如果目标是 CCF-A，只做到 “CVA6 commit-level trace tap + syscall event dump” 大概率不够。原因是：

- 这更像工程实现，不足以形成强研究贡献。
- 只拿到 syscall number 和 a0-a7，很多行为语义恢复不了，比如 `openat` 打开了哪个路径、`execve` 执行了哪个文件、`connect` 连接了哪个地址。
- 没有真实板上 Linux 行为实验，很难说服安全/系统方向审稿人。
- 没有和 `strace`、eBPF、QEMU 插件、DBI、`ptrace` 类方法比较，缺乏定位。
- 没有抗规避实验，无法体现硬件辅助的核心优势。

所以建议把项目拆成两层：

- 工程 MVP：committed syscall/control-flow/trap/context trace。
- 论文级贡献：low-perturbation RISC-V hardware-assisted semantic malware behavior tracing + syscall argument semantic reconstruction + evasion-resistance evaluation + board-level Linux validation。

## 3. 最终方案：RV-MalScope

### 3.1 核心创新点

建议把 CCF-A 论文贡献设计成四个点。

### 贡献 1：RISC-V commit-level 可信行为追踪

在 CVA6 RTL 的 commit / trap / CSR / writeback 路径上增加旁路 trace tap，只记录已经提交或已经造成 architectural effect 的事件：

```text
EVT_SYSCALL_ENTRY
EVT_SYSCALL_RET
EVT_BRANCH
EVT_JUMP
EVT_TRAP
EVT_PRIV
EVT_CSR
EVT_SATP
EVT_ARG_MEM
EVT_DROP
```

核心原则：

- 不追踪 speculative instruction。
- 不追踪被 flush / kill 的路径。
- 不通过 `ptrace` / debugger / DBI 插桩。
- 不让 trace sink 反压 core。

这比软件动态分析更低扰动，也比纯模拟器更接近真实执行。

### 贡献 2：RISC-V syscall semantic reconstruction

RISC-V Linux syscall 约定中，`a7` 是 syscall number，`a0-a5` 是主要参数，返回值通常在 `a0`。因此硬件可以在 syscall entry 捕获：

- `cycle`
- `hart_id`
- `privilege`
- `satp / ASID`
- user `pc`
- syscall number = `a7`
- arguments = `a0-a5`

在 syscall return 捕获：

- return value = `a0`
- duration cycles
- return-to-user `pc`
- context id

然后离线恢复：

- `openat(path) -> fd`
- `read(fd)`
- `write(fd)`
- `close(fd)`
- `execve(path)`
- `clone/fork`
- `connect(sockaddr)`
- `mmap/mprotect`

这一步是从“寄存器 trace”走向“行为 trace”的关键。

### 贡献 3：syscall pointer 参数语义补全

这是决定能不能冲 CCF-A 的关键。仅有 `a0-a7` 不够，因为很多参数是指针，例如：

- `openat(dirfd, pathname_ptr, flags, mode)`
- `execve(filename_ptr, argv_ptr, envp_ptr)`
- `connect(fd, sockaddr_ptr, len)`
- `write(fd, buf_ptr, len)`

建议采用双路径语义补全：

- Path A：硬件优先，OS-transparent user-pointer memory snapshot。
- Path B：工程兜底，trusted kernel helper / eBPF semantic companion。

#### Path A：硬件 user-pointer memory snapshot

思路：

1. 在 U-mode `ecall` 触发 syscall entry 时，硬件记录 pointer 参数。
2. 根据 syscall number 判断哪些参数可能是 user pointer。
3. 在后续 S-mode syscall handler 执行期间，监控 LSU load。
4. 如果 S-mode load 地址落在被 watch 的 user pointer 范围内，就捕获返回数据。
5. 离线重建字符串、`sockaddr`、`argv`、buffer 前缀。

示例：

```text
U-mode:
  a7 = SYS_openat
  a1 = 0x40012340   # pathname pointer

S-mode:
  kernel getname/copy_from_user loads bytes from 0x40012340

hardware:
  captures bytes: "/tmp/a.txt\0"

offline:
  openat(AT_FDCWD, "/tmp/a.txt", O_RDONLY)
```

这比 NCScope 的 eBPF 参数读取更适合 RISC-V 论文，因为它有独立的新意：不用 OS hook，也能从硬件侧恢复 syscall pointer 语义。

#### Path B：trusted kernel helper / eBPF semantic companion

如果 Path A 在真实 Linux 上复杂度过高，兜底方案是：

- 硬件 trace：syscall entry/return/control-flow/trap/context。
- kernel helper/eBPF：pid/tgid/comm、syscall pointer string、fd/path mapping、process context switch。

这与 NCScope 的 ETM + eBPF 思路更接近，但在 RISC-V 上仍有价值。注意：这一路线的威胁模型必须诚实写成 trusted-kernel, user-mode malware，不能声称能抵抗 rootkit。

### 贡献 4：抗规避与低扰动评估

论文实验要证明硬件方案的优势，而不是只证明“能 trace”。

需要比较：

- RV-MalScope
- `strace` / `ptrace`
- eBPF-only
- QEMU plugin
- software instrumentation

比较维度：

- runtime overhead
- trace completeness
- anti-debug detectability
- timing perturbation
- syscall semantic accuracy
- trace bandwidth
- FPGA resource overhead
- Fmax impact

malware-like 规避样例包括：

- `ptrace` anti-debug
- `/proc/self/status` `TracerPid` check
- timing check
- self-modifying code
- direct syscall
- packed / obfuscated syscall wrapper
- `mmap` + `mprotect` executable memory
- `fork/exec` process chain

## 4. 总体架构

```text
                    +-----------------------------+
                    |        RISC-V CVA6 Core      |
                    |                             |
                    | commit / wb / trap / csr     |
                    +--------------+--------------+
                                   |
                          non-intrusive taps
                                   |
       +---------------------------+---------------------------+
       |                           |                           |
+------+-----+            +--------+------+           +--------+------+
| syscall tap |            | control-flow |           | context tap   |
| ecall/sret  |            | branch/jump  |           | priv/satp/csr |
+------+-----+            +--------+------+           +--------+------+
       |                           |                           |
       +---------------+-----------+---------------+-----------+
                       |                           |
                +------+-----+             +-------+------+
                | arg shadow |             | user-pointer |
                | a0-a7      |             | mem snapshot |
                +------+-----+             +-------+------+
                       |                           |
                       +-----------+---------------+
                                   |
                           +-------+-------+
                           | trace packet  |
                           | formatter     |
                           +-------+-------+
                                   |
                           +-------+-------+
                           | FIFO / filter |
                           | compression   |
                           +-------+-------+
                                   |
              +--------------------+--------------------+
              |                    |                    |
       Vivado file sink       BRAM ring buffer      AXI DMA / UART
              |                    |                    |
              +--------------------+--------------------+
                                   |
                           +-------+-------+
                           | host decoder  |
                           +-------+-------+
                                   |
                           +-------+-------+
                           | behavior graph|
                           +---------------+
```

## 5. Trace event 设计

### 5.1 Packet 类型

建议最终不要只用一个超大定长 packet。Vivado MVP 可以用大 packet，方便调试；论文级系统要做 event-specific compact packet。

MVP packet：

```systemverilog
typedef enum logic [3:0] {
  EVT_NONE          = 4'd0,
  EVT_RETIRE        = 4'd1,
  EVT_BRANCH        = 4'd2,
  EVT_JUMP          = 4'd3,
  EVT_SYSCALL_ENTRY = 4'd4,
  EVT_SYSCALL_RET   = 4'd5,
  EVT_TRAP          = 4'd6,
  EVT_CSR           = 4'd7,
  EVT_SATP          = 4'd8,
  EVT_PRIV          = 4'd9,
  EVT_ARG_MEM       = 4'd10,
  EVT_DROP          = 4'd11
} trace_evt_e;
```

MVP 阶段 packet 可以是：

```systemverilog
typedef struct packed {
  logic        valid;
  trace_evt_e evt;
  logic [63:0] cycle;
  logic [63:0] pc;
  logic [31:0] instr;
  logic [63:0] next_pc;
  logic [63:0] target;
  logic        taken;
  logic [1:0]  priv;
  logic [63:0] satp;
  logic [63:0] cause;
  logic [63:0] tval;
  logic [63:0] a0;
  logic [63:0] a1;
  logic [63:0] a2;
  logic [63:0] a3;
  logic [63:0] a4;
  logic [63:0] a5;
  logic [63:0] a6;
  logic [63:0] a7;
} trace_packet_t;
```

论文级 compact packet 再改成：

```text
header:
  event_type
  hart_id
  delta_cycle
  context_id
  payload_len

payload:
  event-specific fields
```

## 6. Vivado 阶段完整方案

### 6.1 Phase V0：版本锁定与仓库修复

首先要把 `rv-maltrace` 变成可复现项目。当前能看到的文档计划已经有目录结构、Phase 0-7、trace module 规划，但主分支上 README 获取失败，说明仓库状态还不完整。

需要先补齐：

- `README.md`
- `docs/10-process/version_lock.md`
- `docs/02-trace-architecture/signal_map.md`
- `docs/02-trace-architecture/trace_format.md`
- `docs/10-process/risk_log.md`
- `docs/07-evaluation-evidence/evaluation_plan.md`
- `rtl/trace/`
- `sim/`
- `tools/`
- `fpga/`

`version_lock.md` 必须固定：

- CVA6 commit hash
- Vivado version
- `riscv64-unknown-elf-gcc` version
- `riscv64-linux-gnu-gcc` version
- Linux kernel version
- Buildroot version
- FPGA board part number
- Python decoder version

通过标准：

- `git clone` 后可以一键复现 baseline simulation。
- 所有第三方依赖有 commit hash。
- 所有测试程序有源码和 golden。

### 6.2 Phase V1：未修改 CVA6 baseline 仿真

目标：不加 trace tap，先证明 CVA6 在 Vivado xsim 中能跑。

测试：

- smoke bare-metal
- branch bare-metal
- ecall-to-machine-handler bare-metal
- illegal instruction trap
- CSR write/read

通过标准：

- Vivado `xvlog/xelab/xsim` 通过。
- reset 后 PC 正常变化。
- bare-metal 程序能写 `tohost` 结束。
- 没有关键 X propagation。
- 可以在 waveform 中定位 `commit_pc` / `commit_instr` / trap cause / CSR / wb 信号。

如果 Vivado xsim 编译 CVA6 失败，修复路径：

1. 优先：写 Vivado-compatible wrapper / filelist / macro config。
2. 其次：先用 Verilator/Questa 做 RTL 功能验证，Vivado 只做综合和上板。
3. 最后：缩小 CVA6 config，关闭暂不需要的复杂特性。

不要把“Vivado xsim 必须一次性跑完整 CVA6 Linux”当作第一目标。

### 6.3 Phase V2：committed event trace MVP

实现模块：

- `rtl/trace/trace_pkg.sv`
- `rtl/trace/trace_top.sv`
- `rtl/trace/retire_tap.sv`
- `rtl/trace/cf_tap.sv`
- `rtl/trace/syscall_tap.sv`
- `rtl/trace/trap_tap.sv`
- `rtl/trace/context_tap.sv`
- `rtl/trace/arg_shadow.sv`
- `rtl/trace/trace_fifo.sv`
- `rtl/trace/trace_filter.sv`

#### 关键修正 1：ECALL 不能只按普通 retire 捕获

原计划里容易出现一个漏洞：如果 `EVT_RETIRE` 条件写成：

```systemverilog
commit_valid && !commit_exception && !commit_killed
```

那么 `ecall` 可能被漏掉，因为 `ecall` 在 RISC-V 中会触发 exception/trap。

修复：

```text
EVT_SYSCALL_ENTRY 不从 normal retire path 捕获，而从 commit-stage exception/trap path 捕获：

if commit_exception
   && instr == 32'h00000073
   && priv == U-mode
   && cause == U_ECALL
then emit EVT_SYSCALL_ENTRY
```

RISC-V cause 一般对应：

- `8` = environment call from U-mode
- `9` = environment call from S-mode
- `11` = environment call from M-mode

对 Linux 用户态 syscall，`SYSCALL_ENTRY` 只接受 U-mode ECALL。S/M-mode
ECALL 仍作为普通 `TRAP` 记录，不能建立 outstanding syscall 状态，否则会让
后续 SRET-to-U 误配成 syscall return。

#### 关键修正 2：compressed instruction 长度

不能默认 `next_pc = pc + 4`。RISC-V 可能启用 C extension，16-bit compressed instruction 长度是 2 字节。

修复：

```systemverilog
instr_len     = (instr[1:0] == 2'b11) ? 4 : 2;
sequential_pc = pc + instr_len;
taken         = next_pc != sequential_pc;
```

#### 关键修正 3：JALR target 不要只靠 rs1+imm

JALR target 如果只靠寄存器影子恢复，会增加复杂度，也容易被 bypass/rename/writeback 时序影响。

修复：

1. 优先使用 core 内部 resolved target / `next_pc`。
2. 如果拿不到，则将 branch/jump event 延迟到下一条 committed instruction 出现后，用 next committed pc 作为实际 target。

但要注意：如果 branch 后立刻 trap，则 next committed pc 不一定是 branch target。

最终优先级：

1. CVA6 execute/commit stage resolved target。
2. commit `next_pc` 信号。
3. pending-branch + next committed pc，仅作为 fallback。

#### 关键修正 4：a0-a7 shadow 可能过期

只监听 writeback 更新 `a0-a7` 有一个隐藏假设：trace 从 reset 开始，所有寄存器写入都被完整观察到。

如果中途打开 trace，shadow 可能不知道当前 `a0-a7` 值。

修复：

- MVP：规定 trace 从 reset 开始，`arg_shadow` 一直有效。
- 上板：trace enable 之前先发 marker，并声明 `arg_shadow` warm-up。
- 增强：在 register file 增加只读 snapshot mux，`ecall` 时读取 `x10-x17`。

建议论文系统采用：`arg_shadow from reset + optional ecall-time RF snapshot`。RF snapshot 增加侵入性，但能消除 shadow stale 风险。

### 6.4 Phase V3：syscall return 捕获

NCScope 不只是知道函数入口，还要知道行为结果。RISC-V syscall 也必须捕获 return。

实现：

- `EVT_SYSCALL_ENTRY`：U-mode `ecall` trap into S-mode，record `a7`、`a0-a5`、user pc、`satp/asid`。
- `EVT_SYSCALL_RET`：S-mode `sret` back to U-mode，record `a0` return value、return pc、cycle delta。

检测 syscall return 的方法：

- detect committed `SRET` instruction
- and privilege transition S -> U
- and current thread/context has outstanding syscall

离线关联：

- `entry_id = monotonically increasing syscall sequence number`
- ret event matches latest outstanding syscall in same hart/context

通过标准：

```text
hello/write:
  entry: SYS_write(fd=1, buf, len)
  ret: len

openat:
  entry: pathname pointer
  ret: fd >= 0 或 errno
```

### 6.5 Phase V4：user-pointer memory snapshot 仿真验证

这是论文级创新的关键。

先不要直接上 Linux，先做 synthetic S-mode syscall handler：

```text
U-mode program:
  a7 = SYS_openat
  a1 = pointer to "/tmp/test.txt"
  ecall

S-mode handler:
  copy bytes from user pointer into kernel buffer
  return fake fd = 3
```

硬件 monitor：

```text
on EVT_SYSCALL_ENTRY:
  if syscall is openat:
    watch a1 as string pointer

during S-mode:
  if LSU load virtual address in watched range:
    capture address + data byte/word

offline:
  reconstruct "/tmp/test.txt"
```

通过标准：

- 捕获完整 null-terminated string。
- 捕获顺序正确。
- page boundary case 通过。
- max length 限制生效。
- watch timeout 生效。
- 不会捕获无关 S-mode load。

当前仓库状态：

- `arg_mem_tap.sv` 提供默认关闭的 syscall-scoped `ARG_MEM` pointer snapshot。
- `pointer_string` 回归验证 openat pathname 的 null-terminated 字符串捕获。
- `pointer_guardrails` 回归验证跨页顺序捕获、最大长度限制、多字节 load 裁剪、watch timeout、无关 S-mode load 不捕获。
- CVA6 LSU 真实信号接入与 Linux workload 验证仍作为后续 FPGA/Linux gate。

这一步如果做成，论文价值会明显上升。

### 6.6 Phase V5：Vivado regression

| Test            | 目的                         | 必须通过               |
| --------------- | ---------------------------- | ---------------------- |
| smoke           | trace tap 不影响程序结果     | final state 一致       |
| branch          | branch taken/target 正确     | 与 objdump/golden 一致 |
| compressed      | 16-bit instruction 长度      | PC delta 正确          |
| jal/jalr        | jump target                  | target 正确            |
| ecall           | syscall entry                | `a7/a0-a5` 正确        |
| syscall_ret     | syscall return               | `a0` return 正确       |
| illegal         | trap cause/tval/sepc         | cause 正确             |
| csr/satp        | context event                | CSR value 正确         |
| sret            | privilege transition         | S->U 捕获              |
| pointer_string  | user-pointer memory snapshot | string 正确            |
| pointer_guardrails | user-pointer snapshot guardrails | page boundary / max length / multi-byte clipping / timeout / unrelated load 正确 |
| fifo_overflow   | trace drop                   | `EVT_DROP` 正确        |
| no_backpressure | trace 不反压 core            | final state 不变       |

最终 Vivado 通过 gate：

- `[PASS] baseline CVA6 sim`
- `[PASS] trace-enabled CVA6 sim`
- `[PASS] all bare-metal tests`
- `[PASS] synthetic syscall tests`
- `[PASS] pointer string reconstruction tests`
- `[PASS] no architectural perturbation`
- `[PASS] no unknown X on trace-critical signals`
- `[PASS] automated regression report`

## 7. 上板阶段完整方案

### 7.1 Phase B0：板卡选择

如果已经有 Genesys 2，可以从 Genesys 2 开始。但要诚实：CVA6 + Linux + trace + DMA 对 FPGA 资源、DDR、时钟、约束都有要求。Genesys 2 未必是最终论文级平台。

建议路线：

- 首选：资源足够的 Xilinx FPGA board，例如 Genesys 2 / VCU118 / 其他 Kintex/UltraScale 平台。
- 最低目标：bare-metal + trace-enabled CVA6 上板。
- 论文目标：Linux boot + syscall trace + semantic reconstruction。

板卡 gate：

- `[PASS] Vivado license 支持目标器件`
- `[PASS] baseline CVA6 bitstream generated`
- `[PASS] timing met`
- `[PASS] UART/DDR 可用`
- `[PASS] bare-metal program 可运行`

如果 Genesys 2 资源不足：

1. 关闭 full retire，只保留 syscall/trap/context。
2. 减小 FIFO/BRAM。
3. 使用更小 CVA6 config。
4. 换更大 FPGA 板卡。

不要让“必须 Genesys 2”成为论文死点。

### 7.2 Phase B1：baseline 上板

顺序：

1. LED blink
2. UART hello
3. minimal memory test
4. unmodified CVA6 bare-metal boot
5. unmodified CVA6 simple Linux boot，若资源允许

不要一开始就带 trace。

通过标准：

- bitstream 可生成。
- board clock/reset 正常。
- UART 输出稳定。
- bare-metal `tohost` 或 UART PASS。
- DDR memory test 通过。

### 7.3 Phase B2：trace-enabled bare-metal 上板

第一版 trace sink 不要复杂：

```text
BRAM ring buffer + JTAG/ILA dump
```

只开：

- `EVT_SYSCALL_ENTRY`
- `EVT_SYSCALL_RET`
- `EVT_TRAP`
- `EVT_PRIV`
- `EVT_CSR`
- `EVT_DROP`

默认关闭：

- full retire trace
- full branch trace
- full memory trace

原因：带宽和 BRAM 容量不够。

通过标准：

- bare-metal `ecall` 程序 trace 正确。
- illegal instruction trap trace 正确。
- `sret` privilege transition trace 正确。
- BRAM dump 能被 host parser 解码。
- `drop_count` 可见。

### 7.4 Phase B3：Linux syscall trace

使用 Buildroot 或最小 Linux rootfs。

实验程序：

- hello
- open-read-close
- write file
- execve
- fork/clone
- mmap/mprotect
- socket/connect，若网络可控

硬件 trace 与 ground truth 对齐：

- RV-MalScope trace vs `strace`
- RV-MalScope trace vs known program behavior
- RV-MalScope return value vs program log

通过标准：

- syscall sequence 与 `strace` 一致。
- syscall return value 一致。
- pid/context 可关联。
- `mmap/mprotect/execve/openat` 等关键行为可恢复。

注意：`strace` 本身会 perturb 程序，所以对齐实验可以分两组：

- Run A：with `strace`，作为 semantic ground truth。
- Run B：without `strace`，RV-MalScope 独立采集。

不能拿 Run A 的性能结果代表真实运行。

### 7.5 Phase B4：trace 导出升级

BRAM/ILA 只适合 bring-up，不适合论文大实验。

论文级 trace sink 建议：

```text
AXI-Stream trace FIFO
    -> AXI DMA
    -> DDR trace buffer
    -> host dump via UART/JTAG/Ethernet
```

或者：

```text
trace FIFO
    -> UART streaming
```

但 UART 只能用于低频 syscall event，不适合 branch/control-flow。

最终建议：

- Bring-up：BRAM ring + ILA。
- Small experiments：UART compact packet。
- Paper experiments：AXI DMA to DDR + offline dump。

## 8. 离线分析方案

### 8.1 Trace decoder

输入：

- `trace.bin` / `trace.jsonl`
- ELF symbols
- syscall table
- kernel version metadata
- optional eBPF/kernel-helper log

输出：

- syscall timeline
- process/thread timeline
- file descriptor table
- file/path behavior
- network behavior
- memory permission behavior
- control-flow sketch
- malware behavior graph

### 8.2 行为图

行为图节点：

- Process
- File
- Socket
- MemoryRegion
- Syscall
- Trap
- ExecutableMapping

行为图边：

- process -> open -> file
- process -> read/write -> fd/file
- process -> execve -> executable
- process -> mmap/mprotect -> memory region
- process -> connect -> remote endpoint
- process -> fork/clone -> child process

示例输出：

```json
{
  "pid": 123,
  "events": [
    { "syscall": "openat", "path": "/etc/passwd", "ret": 3 },
    { "syscall": "read", "fd": 3, "len": 4096, "ret": 1024 },
    { "syscall": "mmap", "prot": "RWX", "ret": "0x40070000" },
    { "syscall": "execve", "path": "/tmp/dropper" }
  ]
}
```

### 8.3 行为检测规则

不要把论文主贡献写成“我训练了一个 malware classifier”。更稳的是：

```text
hardware-assisted semantic behavior tracing
```

检测只是应用。

规则示例：

- anti-debug：open/read `/proc/self/status`，search `TracerPid`，`ptrace(PTRACE_TRACEME)`。
- timing check：repeated `clock_gettime/gettimeofday`，abnormal delta comparison。
- packing/dynamic code：`mmap RW`，write/decode，`mprotect RX`，jump into mapped region。
- persistence/dropper-like：open/write executable，`chmod`，`execve`。
- reconnaissance：scan `/proc`，read `/etc/passwd`，enumerate directories。
- process injection-like：`ptrace` attach，process memory access。

## 9. 实验设计：面向 CCF-A

### 9.1 RQ 设计

建议论文围绕 6 个 RQ：

- RQ1 Correctness：RV-MalScope 能否准确捕获 committed syscall/control-flow/trap/context？
- RQ2 Semantic reconstruction：能否从硬件 trace 恢复 syscall 参数、返回值、文件路径、fd 行为图？
- RQ3 Low perturbation：相比 `strace`/eBPF/QEMU/DBI，运行时开销和 timing perturbation 如何？
- RQ4 Evasion resistance：对 anti-debug、timing check、direct syscall、packed code 是否更难被检测/绕过？
- RQ5 Hardware cost：LUT/FF/BRAM/Fmax/drop rate/trace bandwidth 开销是多少？
- RQ6 Malware behavior usefulness：对 malware-like / controlled malicious behaviors 能否恢复关键行为？

### 9.2 Baseline

至少比较：

- `strace` / `ptrace`
- eBPF-only
- QEMU plugin
- software instrumentation
- RV-MalScope event-only
- RV-MalScope + pointer snapshot
- RV-MalScope + kernel helper

如果能找到 RISC-V 上现成 DBI，则加入；如果找不到，不要硬凑。

### 9.3 Dataset

分三类：

- Class A：microbenchmark、syscall correctness、trap correctness、pointer reconstruction correctness。
- Class B：benign Linux programs、busybox、coreutils-like programs、file/network/process workloads。
- Class C：controlled malware-like programs、anti-debug、timing check、direct syscall、`mmap/mprotect` executable memory、`fork/exec` chain、file scanning、self-copy/dropper-like behavior。

真实恶意样本要谨慎。可以作为隔离环境下的附加实验，但不要把论文成败完全押在真实 RISC-V malware 数据集上，因为 RISC-V 生态下真实样本可能不足。

### 9.4 指标

- syscall precision / recall
- argument reconstruction accuracy
- path string reconstruction accuracy
- fd graph accuracy
- runtime overhead
- cycle-level perturbation
- trace drop rate
- trace bytes per syscall
- LUT/FF/BRAM overhead
- Fmax degradation
- anti-analysis detection success/failure

建议目标：

- syscall event accuracy：controlled tests 100%。
- syscall sequence match with `strace`：normal programs >= 99%，剩余差异人工解释。
- path reconstruction：`openat/execve` controlled tests 100%，Linux workloads measured separately。
- runtime overhead：event-only hardware mode 约等于 0 application-level slowdown if no backpressure，Fmax degradation measured and reported。
- trace drop：correctness mode 0 drop；performance mode 允许 drop，但必须显式记录 `EVT_DROP`。

## 10. 风险闭环：逐轮审查与修复

下面按“先找漏洞，再修复，再重新审查”的方式做可行性闭环。

### Round 0：原始方案

原始设想：

- 在 CVA6 RTL 里加 trace tap。
- Vivado 先验证再上板。
- 做 malware behavior trace。
- 目标 CCF-A。

问题：

1. 只做 trace tap，研究贡献不够。
2. syscall 参数很多是 pointer，只有 `a0-a7` 不够。
3. ECALL 可能不是普通 retire，容易漏。
4. branch target 受 compressed instruction 和 JALR 影响。
5. trace bandwidth 可能爆炸。
6. FPGA resource/timing 不确定。
7. Linux process context 不能只靠 `satp` 完整恢复。
8. malware dataset 不确定。
9. CCF-A 不能靠工程实现保证。

结论：不可直接作为 CCF-A 方案。

### Round 1：加入 syscall entry/return + context

修复：

1. ECALL 从 trap/exception path 捕获。
2. syscall return 从 SRET S->U 捕获。
3. 记录 `a0` return value。
4. 记录 `satp/ASID/privilege/CSR`。
5. 离线建立 syscall timeline。

剩余问题：

1. pointer 参数仍然没有语义。
2. pid/tgid/thread name 不一定能硬件恢复。
3. 仍可能只是 syscall tracer，创新不足。

结论：工程可行性提高，但论文贡献仍不够强。

### Round 2：加入硬件 user-pointer memory snapshot

修复：

1. 在 syscall entry 记录 pointer args。
2. S-mode syscall handler 期间监控 LSU load。
3. 捕获 kernel `copy_from_user` 读取的 user string / `sockaddr` / `argv`。
4. 离线恢复 path/network/exec semantics。

优点：

- 比 eBPF 更硬件化。
- 比 syscall number trace 更有语义。
- 更接近 NCScope 的“trace + memory semantic enrichment”。
- 有明确 CCF-A 研究点。

剩余问题：

1. CVA6 是否容易拿到 LSU virtual address / load data，需要查 signal map。
2. Linux `copy_from_user` 路径复杂，可能跨页、fault、copy 优化。
3. 长 buffer 捕获会带来 bandwidth 压力。

修复：

1. 先 synthetic S-mode handler 验证。
2. Linux 上先只恢复 null-terminated strings。
3. 限制每个 pointer 最大捕获长度，例如 256B 或 4KB。
4. 只 watch syscall-specific pointer，不做 full memory trace。
5. 捕获失败时 fallback 到 kernel helper/eBPF。

结论：有论文级创新，但真实 Linux 上仍需 fallback。

### Round 3：加入 trusted kernel helper/eBPF fallback

修复：

1. 若硬件 pointer snapshot 不稳定，用 kernel helper/eBPF 读取 user string。
2. helper 只做 semantic companion，不替代硬件 trace。
3. 威胁模型明确为 user-mode malware, trusted kernel。
4. 硬件-only 与 hardware+helper 两种模式分别评估。

剩余问题：

1. RISC-V Linux eBPF 支持依赖 kernel config。
2. malware 可能检测 eBPF 或 timing 变化。
3. 如果 helper 过重，会削弱硬件低扰动优势。

修复：

1. fallback 到轻量 kernel module，不强依赖 eBPF。
2. helper 只采集 pointer strings/pid，不采 full trace。
3. 单独报告 helper overhead。
4. hardware-only mode 保留低扰动和抗规避实验。

结论：技术路线稳健，有硬件创新，也有工程兜底。

### Round 4：检查上板和 CCF-A 风险

剩余不可消除风险：

1. 具体 FPGA 资源是否足够。
2. Vivado 是否能顺利仿真完整 CVA6。
3. Linux boot 是否稳定。
4. CCF-A 审稿人是否认可 novelty。
5. 真实 malware 数据集是否足够。

修复：

1. 资源不足：关闭 full branch/full retire，只保留 syscall/trap/context。
2. Vivado xsim 不稳：Verilator/Questa 验证功能，Vivado 做综合/上板。
3. Linux boot 不稳：先 bare-metal + synthetic S-mode，再 Buildroot minimal Linux。
4. novelty 不足：主打 hardware user-pointer semantic reconstruction + evasion resistance。
5. dataset 不足：用 controlled malware-like suite + real benign workloads，真实样本作为补充。

最终结论：

```text
没有发现无法修复的技术死点。
但不能声称“绝对 100% 可行”或“100% CCF-A”。

可以声称：
  在 CVA6 baseline 可仿真/可综合、板卡资源足够、Linux bring-up 成功的条件下，
  该方案每个阶段都有明确验证 gate 和 fallback，
  技术上是可推进的。
```

## 11. 最终技术路线图

### Stage 1：Vivado feasibility

目标：证明 RTL trace 可行。

- S1.1 baseline CVA6 xsim
- S1.2 trace tap integration
- S1.3 syscall entry/return
- S1.4 trap/context/CSR
- S1.5 branch/jump correctness
- S1.6 synthetic pointer snapshot
- S1.7 automated regression

交付物：

- trace RTL
- Vivado testbench
- bare-metal tests
- synthetic syscall tests
- Python decoder
- golden checker
- sim report

通过 gate：

- 所有 regression pass。
- trace tap 不改变程序最终状态。
- syscall entry/return 正确。
- pointer string synthetic reconstruction 正确。

### Stage 2：FPGA board bring-up

目标：证明真实硬件上能 trace。

- S2.1 baseline board boot
- S2.2 trace-enabled bare-metal
- S2.3 BRAM/ILA trace dump
- S2.4 UART/DDR trace export
- S2.5 Buildroot Linux boot
- S2.6 Linux syscall trace
- S2.7 semantic reconstruction

交付物：

- bitstream
- resource/timing report
- board trace logs
- host decoder
- Linux workload results

通过 gate：

- baseline bitstream timing pass。
- trace-enabled bitstream timing pass。
- bare-metal trace 正确。
- Linux syscall sequence 与 `strace` 对齐。
- trace drop 可控且显式记录。

### Stage 3：论文级增强

目标：把工程系统变成 CCF-A 论文。

- S3.1 hardware user-pointer memory snapshot
- S3.2 kernel helper/eBPF fallback
- S3.3 behavior graph reconstruction
- S3.4 evasion resistance suite
- S3.5 overhead/resource evaluation
- S3.6 comparison with `strace`/eBPF/QEMU/plugin
- S3.7 artifact packaging

交付物：

- paper-ready evaluation
- ablation study
- case studies
- open-source artifact
- reproducibility package

## 12. 论文主线建议

### 12.1 题目方向

可以考虑：

```text
RV-MalScope: Hardware-Assisted Semantic Behavior Tracing for RISC-V Malware Analysis
```

或：

```text
RVScope: Low-Perturbation Hardware-Assisted Syscall Semantic Tracing on RISC-V
```

如果主打 malware，就叫 RV-MalScope；如果想更稳、避免真实 malware 数据集风险，可以主打 semantic tracing，再把 malware analysis 作为应用。

### 12.2 论文故事线

- Problem：RISC-V 生态正在进入 IoT/edge/security-sensitive 场景，但现有 malware/runtime analysis 依赖软件插桩、模拟器或 OS hook，容易被规避且扰动大。
- Challenge：纯硬件 trace 只能看到控制流/syscall number，缺乏 syscall pointer 语义；纯 eBPF/`strace` 有可检测性和扰动问题。
- Insight：RISC-V syscall 入口暴露 `a0-a7`，kernel syscall handler 会读取 user pointer。在 commit/LSU 层捕获 syscall entry + privileged user-pointer loads，可以恢复高层语义。
- Design：CVA6 commit-level trace tap、syscall entry/return correlation、context tracking、selective user-pointer memory snapshot、offline behavior graph reconstruction。
- Results：low perturbation、accurate syscall/path reconstruction、resource overhead acceptable、harder to detect than `ptrace`/`strace`/QEMU。

## 13. 最需要优先解决的三个技术点

### 第一：signal map

必须先在 CVA6 中确认这些信号：

- `commit_valid`
- `commit_pc`
- `commit_instr`
- `commit_exception`
- `exception_cause`
- `trap_pc / epc`
- CSR write addr/data
- privilege mode
- `satp`
- writeback valid/rd/data
- `sret` commit
- LSU load virtual address
- LSU load physical address
- LSU load data
- LSU load valid
- load belongs to committed instruction or response valid

如果 LSU load data 很难拿，硬件 pointer snapshot 暂缓，使用 kernel helper fallback。

### 第二：ECALL/SRET 正确性

这是系统核心。

必须确保：

- entry 是 U-mode `ecall`。
- return 是 `SRET` back to U-mode。
- `a0-a7` 是用户态 syscall 参数。
- `a0` return 是 syscall 返回值。
- entry/return 可以按 context/hart 正确配对。

### 第三：trace sink 不影响 core

上板必须避免：

- trace FIFO full 反压 core。
- trace decode 进入 critical path。
- packet formatter 组合逻辑太长。
- full branch/retire trace 撑爆带宽。

修复原则：

- 所有 trace tap 旁路采样。
- packet formatting 打拍。
- FIFO full 时 drop，而不是 stall core。
- drop 必须输出 `EVT_DROP`。
- paper 中区分 lossless mode 和 drop mode。

## 14. 最终可行性判断

### 工程 MVP 可行性

- CVA6 commit-level syscall/trap/context trace：高可行。
- Vivado bare-metal simulation：中高可行，但依赖 Vivado 对 CVA6 SV 的支持。
- FPGA bare-metal trace：中高可行，依赖板卡资源和时序。
- Linux syscall trace：中等可行，依赖 Linux bring-up 和 trace bandwidth。

### 论文增强可行性

- syscall entry/return semantic reconstruction：高可行。
- fd/path/process behavior graph：中高可行，需要 pointer semantic support。
- hardware user-pointer memory snapshot：中等可行，高创新但需要深入 CVA6 LSU/Linux 路径。
- kernel helper/eBPF fallback：中高可行，但威胁模型要收窄。
- malware evasion evaluation：高可行，可以用 controlled malware-like suite。

### CCF-A 可行性

- 只做当前 MVP：不建议作为 CCF-A 主贡献。
- MVP + syscall return + behavior graph：有机会，但仍偏工程。
- MVP + hardware pointer semantic reconstruction + board Linux evaluation + evasion study：才是合理 CCF-A 路线。

最终策略：

```text
先按仓库计划完成 committed syscall/trap/context MVP；
然后必须把“syscall pointer semantic reconstruction”做成论文核心；
上板验证至少要覆盖 Linux syscall trace；
CCF-A 投稿前必须有对比实验、抗规避实验、资源/开销实验和 case study。
```

## 15. 最终版方案摘要

最终建议路线：

1. Phase 0：修复仓库，锁定版本，补齐 docs 和 reproducibility。
2. Phase 1：Vivado baseline CVA6 bare-metal simulation。
3. Phase 2：加 trace tap：
   - syscall entry
   - syscall return
   - trap
   - CSR/satp/priv
   - branch/jump
   - `a0-a7` shadow
4. Phase 3：修正关键语义：
   - ECALL from trap path
   - SRET return matching
   - compressed instruction length
   - JALR actual target
   - arg shadow validity
5. Phase 4：synthetic S-mode syscall handler，验证 pointer string snapshot。
6. Phase 5：FPGA baseline 上板，先不加 trace，跑通 bare-metal。
7. Phase 6：FPGA trace-enabled 上板，BRAM ring + ILA dump，验证 syscall/trap/context。
8. Phase 7：Linux bring-up，Buildroot minimal rootfs，跑 hello/open/exec/mmap/fork。
9. Phase 8：semantic reconstruction：
   - syscall return + fd graph + path recovery
   - Path A 硬件 pointer snapshot
   - Path B kernel helper/eBPF fallback
10. Phase 9：CCF-A 实验：
    - correctness
    - overhead
    - resource
    - trace bandwidth
    - anti-analysis
    - comparison
    - case studies
11. Phase 10：论文包装：
    - 主贡献不是“我加了 trace tap”，而是 RISC-V hardware-assisted semantic behavior tracing with low perturbation and syscall pointer reconstruction。

严格说，不能给出“100% 绝对可行”的承诺；但经过上面的修复后，这个方案已经没有明显的结构性死穴。真正决定它能不能冲 CCF-A 的，是能否完成硬件辅助 syscall pointer 语义恢复、Linux 板上验证、抗规避对比实验。这三个点做出来，才会从一个不错的工程项目变成有论文竞争力的系统安全/软硬件协同分析工作。
