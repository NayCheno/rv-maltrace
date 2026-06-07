# RISC-V/CVA6 硬件辅助 Malware Behavior Tracing 项目计划

## 1. 项目定位

### 1.1 项目名称

**RISC-V/CVA6 RTL-level Hardware-Assisted Malware Behavior Tracing**

### 1.2 核心目标

在 **CVA6 / CV64A6** 的 RTL 中加入轻量级 trace tap，从处理器提交点捕获程序行为事件，用于后续 malware behavior analysis。

第一版目标不是完整复现 NCScope，也不是先做 eBPF tracing，而是建立一个 **RISC-V commit-level hardware behavior tracing MVP**：

```text
CVA6 commit/CSR/trap/writeback signals
        ↓
hardware trace tap
        ↓
trace packet
        ↓
Vivado xsim / later FPGA sink
        ↓
Python parser + checker
        ↓
behavior event stream
```

### 1.3 与 NCScope 的关系

NCScope 的核心价值在于恢复 native code behavior，包括 control flow、syscall、memory object 等语义。当前项目第一阶段只取最稳妥、最适合硬件验证的部分：

```text
先做 committed control-flow / syscall / trap / context trace。
后期再评估 memory semantic enrichment。
eBPF 只作为后期语义补充，不作为 MVP 依赖。
```

## 2. 总体原则

### 2.1 MVP 不依赖 eBPF

第一版只依赖 RTL trace：

```text
Retire event
Branch / jump event
Ecall / syscall argument event
Trap / exception event
Privilege / CSR / satp context event
```

第一版不依赖：

```text
Linux kernel eBPF
kernel helper module
dynamic binary instrumentation
full memory object reconstruction
malware dataset
```

### 2.2 只记录 committed 行为

项目基本原则：

```text
只记录已经提交、真正影响 architectural state 的事件。
不记录 speculative instruction。
不记录被 flush / kill 的指令。
不记录错误路径上的控制流。
```

### 2.3 第一版不做 full load/store trace

第一版只做：

```text
control-flow trace
syscall trace
trap / exception trace
context / satp / privilege trace
a0-a7 syscall argument trace
```

第一版暂时不做：

```text
full load/store address trace
full load/store data trace
syscall pointer 指向的字符串 / buffer dump
malloc/free heap object reconstruction
JNI/native library boundary tracing
```

## 3. 项目阶段划分

```text
Phase 0：环境与 baseline 准备
Phase 1：Vivado 仿真 MVP
Phase 2：Vivado 仿真增强
Phase 3：综合前结构化
Phase 4：Genesys 2 baseline 上板
Phase 5：Genesys 2 trace-enabled 上板
Phase 6：Linux behavior experiment
Phase 7：memory semantic enrichment，可选 eBPF/kernel helper
```

当前优先级：

```text
先聚焦 Phase 0 + Phase 1。
Phase 4 + Phase 5 在仿真 MVP 稳定后推进。
Phase 6 + Phase 7 放到硬件 trace 正确性成立之后。
```

---

# Phase 0：环境与 Baseline 准备

## 0.1 固定代码版本

固定以下版本，避免后续不可复现：

```text
CVA6 commit hash
Vivado version
RISC-V GCC toolchain version
bare-metal runtime / crt0
testbench commit hash
Python checker version
```

建议记录到：

```text
docs/10-process/version_lock.md
```

内容模板：

```markdown
# Version Lock

## CVA6
- Repository: openhwgroup/cva6
- Commit: <commit_hash>
- Date: <date>

## Vivado
- Version: Vivado 202x.x
- OS: Ubuntu / Windows
- Simulator: xsim

## Toolchain
- riscv-none-elf-gcc: <version>
- riscv-none-elf-objdump: <version>
```

## 0.2 建议项目目录

```text
rv-maltrace/
  README.md
  docs/
    plan.md
    version_lock.md
    signal_map.md
    trace_format.md
    sim_results.md
    board_bringup.md
    risk_log.md

  rtl/
    cva6/                         # CVA6 submodule
    trace/
      trace_pkg.sv
      trace_top.sv
      retire_tap.sv
      branch_tap.sv
      syscall_tap.sv
      trap_tap.sv
      context_tap.sv
      arg_shadow.sv
      trace_fifo.sv
      trace_filter.sv

  sim/
    vivado/
      filelist.f
      run_xsim.tcl
      run_all.tcl
      waves.tcl
    tb/
      tb_cva6_trace_top.sv
      tb_trace_sink.sv
      tb_trace_scoreboard.sv
      tb_mem_model.sv
    programs/
      smoke/
      branch/
      jump/
      ecall/
      trap_illegal/
      csr/
      backpressure/
    golden/
      smoke.expected.json
      branch.expected.json
      ecall.expected.json
      trap.expected.json
      csr.expected.json

  tools/
    build_baremetal.py
    gen_golden_from_objdump.py
    parse_trace.py
    compare_trace.py
    summarize_results.py

  fpga/
    genesys2/
      constraints/
      scripts/
      ila/
      bitstreams/

  results/
    vivado_sim/
    synthesis/
    board/
```

## 0.3 建 Vivado baseline 仿真

目标：先跑 **未修改 CVA6 baseline**，确认 Vivado xsim 能编译、elaborate、运行 testbench。

最小 Tcl 流程：

```tcl
# sim/vivado/run_xsim.tcl

set TOP tb_cva6_trace_top
set SNAP ${TOP}_snap

file delete -force xsim.dir
file delete -force xvlog.log xelab.log xsim.log

xvlog -sv -f sim/vivado/filelist.f
xelab work.$TOP -s $SNAP -debug typical
xsim $SNAP -tclbatch sim/vivado/run_all.tcl
```

```tcl
# sim/vivado/run_all.tcl

log_wave -recursive /*
run -all
quit
```

Baseline 通过标准：

```text
[PASS] Vivado 能成功解析所有 SystemVerilog 文件
[PASS] xelab 能生成 snapshot
[PASS] reset 后 PC 正常变化
[PASS] bare-metal smoke 程序能执行到结束点
[PASS] 程序最终状态正确
[PASS] 没有关键控制信号 X-propagation
[PASS] waveform 中能定位 commit_valid / commit_pc / commit_instr
```

---

# Phase 1：Vivado 仿真 MVP

## 1.1 MVP 目标

第一阶段只证明：

```text
1. trace tap 不改变 CVA6 原始执行结果。
2. trace event 来自 committed instruction。
3. branch/jump event 正确。
4. syscall entry event 能捕获 U-mode syscall number 和 a0-a7。
5. trap event 能捕获 cause/tval/pc。
6. context event 能捕获 privilege/satp/CSR 变化。
7. trace output 可由 Python 工具自动解析和比对。
```

## 1.2 Trace 架构

```text
CVA6 internal commit / csr / trap / wb signals
        ↓
arg_shadow.sv
        ↓
retire_tap.sv
branch_tap.sv
syscall_tap.sv
trap_tap.sv
context_tap.sv
        ↓
trace_top.sv
        ↓
trace_packet_t
        ↓
simulation file sink
        ↓
trace.csv / trace.jsonl
        ↓
parse_trace.py
        ↓
compare_trace.py
```

## 1.3 Trace event 类型

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
  EVT_DROP          = 4'd11,
  EVT_MARKER        = 4'd12
} trace_evt_e;
```

## 1.4 第一版 trace packet

```systemverilog
typedef struct packed {
  logic        valid;
  trace_evt_e evt;
  logic [63:0] cycle;
  logic [63:0] pc;
  logic [31:0] instr;
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

第一版允许字段冗余，优先保证可验证性。后续再压缩 packet。

## 1.5 事件触发规则

### EVT_RETIRE

触发条件：

```text
commit_valid && !commit_exception && !commit_killed
```

记录：

```text
cycle
pc
instr
priv
```

### EVT_BRANCH

触发条件：

```text
committed instruction is conditional branch
```

记录：

```text
pc
instr
taken
target
```

第一版可以从 committed pc、instr、next pc 推导 taken/target，不直接深入 fetch/predictor。

### EVT_JUMP

触发条件：

```text
committed instruction is jal / jalr
```

记录：

```text
pc
instr
target
```

### EVT_SYSCALL_ENTRY / EVT_SYSCALL_RET

触发条件：

```text
SYSCALL_ENTRY: U-mode ECALL from the exception/trap path, cause == U_ECALL
SYSCALL_RET: S-mode SRET qualified as returning to U-mode with an outstanding syscall
```

记录：

```text
pc
a0-a7
priv
syscall_id
return target/duration/a0 on SYSCALL_RET
```

a7 作为 syscall number，a0-a5 作为主要 syscall 参数。第一版先只记录寄存器值和返回值，不解析指针指向内容。

### EVT_TRAP

触发条件：

```text
trap_valid / exception_valid / interrupt_valid
```

记录：

```text
trap_pc
cause
tval
priv
```

### EVT_CSR / EVT_SATP

触发条件：

```text
committed CSR write
CSR address in watched set
```

优先 watched CSR：

```text
mstatus
sstatus
satp
stvec
sepc
scause
stval
medeleg
mideleg
```

### EVT_PRIV

触发条件：

```text
privilege mode changes
```

记录：

```text
old_priv
new_priv
pc
cycle
```

---

# Phase 1A：实现顺序

## Step 1：定位 CVA6 内部信号

先建立：

```text
docs/02-trace-architecture/signal_map.md
```

模板：

```markdown
# Signal Map

## Commit Signals
- commit_valid:
- commit_pc:
- commit_instr:
- commit_exception:
- commit_kill:

## Register Writeback
- wb_valid:
- wb_rd:
- wb_data:

## Trap Signals
- trap_valid:
- trap_pc:
- trap_cause:
- trap_tval:

## CSR / Context
- priv_lvl:
- satp:
- csr_we:
- csr_addr:
- csr_wdata:
```

优先找这些信号：

```text
commit_valid
commit_pc
commit_instr
commit_exception
writeback rd / data
trap cause / tval
privilege level
satp CSR value
```

## Step 2：实现 `trace_pkg.sv`

内容：

```text
event enum
packet struct
common constants
watched CSR IDs
utility typedefs
```

## Step 3：实现 `retire_tap.sv`

输入：

```text
clk
rst_n
commit_valid
commit_pc
commit_instr
commit_exception
commit_kill
priv_lvl
satp
```

输出：

```text
trace_valid
trace_packet
```

验证：

```text
每条 committed instruction 产生一个 EVT_RETIRE。
被 kill/flush 的指令不能产生 EVT_RETIRE。
reset 后 cycle 计数正常。
```

## Step 4：实现 `branch_tap.sv`

做法：

```text
decode branch/jump opcode
使用 committed pc/instr/next committed pc 推导 taken/target
输出 EVT_BRANCH / EVT_JUMP
```

第一版 branch target 计算：

```text
BEQ/BNE/BLT/BGE/BLTU/BGEU: B-immediate + pc
JAL: J-immediate + pc
JALR: rs1 + I-immediate，需要从执行结果或寄存器影子获得
```

通过标准：

```text
branch not taken target = pc + 4
branch taken target = branch immediate target
jal target 正确
jalr target 正确
```

## Step 5：实现 `arg_shadow.sv`

原理：

```text
监听 writeback。
如果 rd 属于 x10-x17，则更新 a0-a7 shadow。
    syscall_tap 触发 U-mode syscall entry 时直接读取 shadow。
```

好处：

```text
不直接增加 register file 读端口。
降低对 CVA6 core 的侵入。
更容易综合。
```

注意：

```text
x0 写入必须忽略。
writeback flush/kill 必须过滤。
多写回端口时需要按 CVA6 实际结构处理。
```

## Step 6：实现 `syscall_tap.sv`

syscall entry 识别：

```text
commit_exception && instr == 32'h00000073 && priv == U && cause == U_ECALL
```

触发：

```text
commit exception/trap path, not normal retire
```

记录：

```text
pc
priv
a0-a7
```

第一版 syscall 语义：

```text
a7 = syscall number
a0-a5 = syscall arguments
SYSCALL_RET records a0 return value, return pc, and duration
```

## Step 7：实现 `trap_tap.sv`

记录内容：

```text
trap_pc
cause
tval
privilege level
cycle
```

测试用例：

```text
illegal instruction
ecall
ebreak
misaligned access，可后置
```

## Step 8：实现 `context_tap.sv`

事件来源：

```text
privilege level change
satp write
watched CSR write
```

为什么重要：

```text
malware behavior trace 后期需要区分 user/kernel/context。
Linux 上跑用户程序时，syscall/trap/context 边界必须可见。
```

## Step 9：实现 `trace_top.sv`

职责：

```text
实例化所有 tap。
仲裁多个 tap 同周期事件。
输出统一 trace_packet_t。
连接仿真 sink 或 FIFO。
```

仲裁顺序建议：

```text
TRAP > SYSCALL_ENTRY/SYSCALL_RET > CSR/PRIV > BRANCH/JUMP > RETIRE
```

第一版可以每周期只输出一个 event。若同周期多个 event，可用 FIFO 或多拍输出在 Phase 2 补强。

---

# Phase 1B：Vivado Testbench 设计

## 1B.1 Testbench 模块

```text
tb_cva6_trace_top.sv
tb_trace_sink.sv
tb_trace_scoreboard.sv
tb_mem_model.sv
```

职责：

```text
tb_cva6_trace_top.sv:
  实例化 CVA6 + trace_top。
  加载 bare-metal program。
  生成 reset/clock。

tb_trace_sink.sv:
  接收 trace_packet_t。
  写 trace.jsonl 或 trace.csv。

tb_trace_scoreboard.sv:
  检查程序最终状态。
  检查 trace event 数量和关键字段。

tb_mem_model.sv:
  提供最小 memory model。
  支持加载 ELF/HEX/MEM。
```

## 1B.2 Trace sink 输出格式

建议第一版输出 JSONL：

```json
{"cycle":100,"evt":"RETIRE","pc":"0x80000000","instr":"0x00000513","priv":"M"}
{"cycle":120,"evt":"BRANCH","pc":"0x80000010","taken":true,"target":"0x80000020"}
{"cycle":180,"evt":"SYSCALL_ENTRY","pc":"0x80000040","priv":"U","syscall_id":"0x0","a7":"0x40","a0":"0x1","a1":"0x80001000"}
{"cycle":190,"evt":"SYSCALL_RET","pc":"0x80000080","priv":"S","target":"0x80000044","syscall_id":"0x0","duration":10,"a0":"0x5"}
```

JSONL 比 CSV 更适合字段稀疏的 event。

## 1B.3 程序结束机制

第一版使用 MMIO magic address：

```c
#define TOHOST ((volatile unsigned long *)0x10000000)

int main(void) {
  *TOHOST = 1;
  while (1) {}
}
```

testbench 检测：

```text
write to 0x10000000 => finish simulation
write value 1 => pass
write value other => fail
```

---

# Phase 1C：Bare-metal 测试矩阵

## Test 0：baseline smoke

程序：

```c
int main(void) {
  volatile int x = 1;
  volatile int y = 2;
  volatile int z = x + y;
  return z == 3 ? 0 : 1;
}
```

期望：

```text
RETIRE events > 0
无 TRAP
最终 PASS
```

通过标准：

```text
trace tap 接入前后程序结果一致。
```

## Test 1：branch

程序：

```c
if (x == 1) {
  y = 10;
} else {
  y = 20;
}
```

期望：

```text
至少一个 EVT_BRANCH。
taken 字段与 golden 一致。
target 字段与 objdump 推导一致。
```

Golden：

```text
从 objdump 解析 branch pc 和 target。
```

## Test 2：jump

程序：

```c
void foo(void) {}
int main(void) {
  foo();
  return 0;
}
```

期望：

```text
JAL/JALR 对应 EVT_JUMP。
target 正确。
```

## Test 3：syscall entry/return

程序：

```asm
li a7, 64
li a0, 1
li a1, 0x80001000
li a2, 5
ecall
```

期望：

```text
EVT_SYSCALL_ENTRY
a7 = 64
a0 = 1
a1 = 0x80001000
a2 = 5
EVT_SYSCALL_RET records return a0, return pc, and duration when the test includes SRET-to-U
```

注意：

```text
第一版不解析 a1 指向的字符串。
```

## Test 4：illegal instruction trap

程序：

```asm
.word 0xffffffff
```

期望：

```text
EVT_TRAP
cause = illegal instruction
tval = offending instruction 或实现定义值
trap pc 正确
```

## Test 5：ebreak trap

程序：

```asm
ebreak
```

期望：

```text
EVT_TRAP
cause = breakpoint
```

## Test 6：CSR write

程序：

```asm
csrw satp, x0
csrw stvec, t0
```

期望：

```text
EVT_CSR 或 EVT_SATP
csr addr/value 正确
```

## Test 7：satp/context，后置

需要更完整 runtime 或 privilege transition，放在 Phase 1 后半段。

## Test 8：backpressure/FIFO

仿真构造：

```text
trace sink 每隔 N cycle ready=0。
检查 trace FIFO 是否 drop 或 backpressure。
```

两种策略都要测：

```text
lossless mode: 不允许 drop。
drop mode: 输出 EVT_DROP 并统计 drop_count。
```

第一版上板建议：

```text
优先 drop mode，避免 trace 影响 core timing 和执行。
```

---

# Phase 1D：Golden Reference 与 Checker

## 1D.1 Golden 来源

```text
objdump:
  branch/jump pc
  target
  instruction encoding

hand-written expected JSON:
  syscall args
  trap cause
  CSR events

simulation final state:
  PASS/FAIL MMIO
```

## 1D.2 Golden 文件格式

```json
{
  "test": "ecall",
  "required_events": [
    {
      "evt": "SYSCALL_ENTRY",
      "pc": "ANY",
      "priv": "U",
      "a7": "0x40",
      "a0": "0x1",
      "a1": "0x80001000",
      "a2": "0x5"
    }
  ]
}
```

## 1D.3 比对规则

严格比较：

```text
event type
pc
target
taken
syscall number
trap cause
```

宽松比较：

```text
cycle
部分 CSR side effect
trap tval，视 CVA6 实现而定
```

## 1D.4 Python checker 输出

```text
[PASS] smoke: 124 retired instructions
[PASS] branch: 3 branch events matched
[PASS] syscall_entry: syscall number/args matched
[PASS] trap_illegal: cause matched
[FAIL] jump: expected target 0x80000080, got 0x80000084
```

---

# Phase 1E：Vivado 仿真自动化

建议 Makefile 目标：

```makefile
sim-smoke:
	vivado -mode batch -source sim/vivado/run_xsim.tcl -tclargs smoke

sim-branch:
	vivado -mode batch -source sim/vivado/run_xsim.tcl -tclargs branch

sim-all:
	python tools/build_baremetal.py --all
	vivado -mode batch -source sim/vivado/run_all_tests.tcl
	python tools/summarize_results.py results/vivado_sim
```

Regression 输出：

```text
results/vivado_sim/
  smoke/
    trace.jsonl
    xsim.log
    waveform.wdb
    compare.log
  branch/
  ecall/
  summary.json
```

Phase 1 完成标准：

```text
[PASS] 5 个以上 bare-metal tests 全部通过
[PASS] trace tap 接入前后程序最终结果一致
[PASS] 所有 event 均来自 committed instruction
[PASS] branch/jump target 与 golden 一致
[PASS] syscall entry/return 与 golden 一致
[PASS] trap cause/tval/pc 可验证
[PASS] Python checker 可一键跑 regression
[PASS] docs/02-trace-architecture/signal_map.md 与 docs/02-trace-architecture/trace_format.md 完成
```

---

# Phase 2：Vivado 仿真增强

## 2.1 Trace filter

支持：

```text
enable_retire
enable_branch
enable_syscall
enable_trap
enable_context
pc_start / pc_end filter
privilege filter
```

## 2.2 Packet compression 原型

压缩策略：

```text
cycle delta
pc delta
event-specific payload
omit unchanged context
```

事件变长格式：

```text
header
payload length
payload
```

## 2.3 Selective memory trace，暂不启用

三种模式：

```text
Mode 0: no memory trace
Mode 1: trace only load/store address
Mode 2: trace selected address range
```

第一版默认：

```text
Mode 0
```

---

# Phase 3：综合前结构化

## 3.1 隔离仿真专用逻辑

必须区分：

```text
synthesizable trace RTL:
  trace_pkg.sv
  trace_top.sv
  *_tap.sv
  trace_fifo.sv
  trace_filter.sv

simulation-only:
  tb_trace_sink.sv
  file writer
  JSONL output
  assertions
```

## 3.2 Timing 原则

```text
trace 逻辑不得进入 CVA6 critical path。
从 commit/writeback/trap 信号只做旁路采样。
复杂 decode 和 packet formatting 尽量打一拍。
上板优先允许 drop，不反压 core。
```

## 3.3 资源报告

记录：

```text
LUT
FF
BRAM
Fmax
critical path
trace FIFO depth
drop count
```

---

# Phase 4：Genesys 2 Baseline 上板

## 4.1 上板前提

```text
Vivado baseline simulation pass
CVA6 original design synthesis pass
Genesys 2 constraints available
DDR / clock / reset / UART bring-up path clear
```

## 4.2 授权风险

需要提前确认：

```text
Vivado license 是否支持目标器件
Genesys 2 FPGA part 是否可综合/实现/生成 bitstream
board files 是否可用
```

## 4.3 Baseline bring-up 顺序

```text
1. LED blink / clock reset sanity
2. UART hello
3. minimal RISC-V core boot
4. CVA6 bare-metal boot
5. CVA6 simple Linux boot，若资源和环境允许
```

## 4.4 Baseline 通过标准

```text
[PASS] bitstream generated
[PASS] board clock/reset stable
[PASS] UART output visible
[PASS] bare-metal program can run
[PASS] no trace modification yet
```

---

# Phase 5：Genesys 2 Trace-enabled 上板

## 5.1 Trace 导出路径选择

### 方案 A：BRAM ring buffer + JTAG/ILA

优点：

```text
最容易 bring-up
不需要高速外设
适合第一版硬件验证
```

缺点：

```text
容量有限
不适合长时间 trace
```

### 方案 B：UART streaming

优点：

```text
简单直观
host parser 容易写
```

缺点：

```text
带宽低
需要强 filter/drop
```

### 方案 C：AXI DMA / Ethernet streaming

优点：

```text
带宽较高
适合长期目标
```

缺点：

```text
集成复杂
不适合第一版上板
```

推荐第一版：

```text
BRAM ring buffer + ILA/JTAG dump
```

## 5.2 上板 trace 最小功能

```text
只开 syscall/trap/context/branch。
默认关闭 full retire。
使用 trace_filter 限制 pc range 或 event type。
允许 drop 并记录 drop_count。
```

## 5.3 上板 trace 验证程序

程序 1：hello

```text
预期 syscall write。
```

程序 2：file open/read/write

```text
预期 openat/read/write/close。
```

程序 3：fork/exec

```text
预期 clone/execve/wait。
```

程序 4：trap/illegal instruction

```text
预期 trap event。
```

---

# Phase 6：Linux Malware-like Behavior Experiment

## 6.1 实验原则

```text
不直接跑真实恶意样本作为早期实验。
先跑 benign + malware-like synthetic behavior。
优先验证 trace 语义恢复能力。
```

## 6.2 Benign dataset

```text
hello
ls
cat
cp
sha256sum
small network client，若网络栈可用
```

## 6.3 Malware-like dataset

```text
大量文件扫描
批量 open/read/write
自复制行为模拟
异常 syscall sequence
非法指令或 trap 行为
进程创建链
```

## 6.4 行为恢复目标

```text
syscall sequence
control-flow segment
trap/context transition
privilege boundary
basic behavior graph
```

---

# Phase 7：Memory Trace / eBPF 可选增强

## 7.1 为什么后期可能还需要 eBPF

硬件 trace 很擅长：

```text
看到真实执行路径
看到 syscall/trap/context
不依赖 guest OS 插桩
抗部分软件规避
```

但硬件 trace 不擅长：

```text
理解 fd 对应的文件名
理解 pointer 指向的字符串
理解进程名和路径
理解 kernel object 语义
```

所以后期可以加入语义补充。

## 7.2 三条增强路线

### 路线 A：纯硬件 selective memory snapshot

```text
在 syscall 发生时，根据 a0-a5 指针抓取有限长度 memory。
例如 openat pathname、write buffer prefix。
```

风险：

```text
需要额外 memory read path。
可能影响 timing。
复杂度高。
```

### 路线 B：kernel helper

```text
Linux 内核模块或 small patch 暴露 pid/fd/path metadata。
硬件 trace 和软件 metadata 后处理对齐。
```

风险：

```text
侵入 OS。
影响“纯硬件”叙事。
```

### 路线 C：eBPF semantic enrichment

```text
eBPF 只记录高层 kernel semantic event。
硬件 trace 记录真实 committed execution event。
离线做 timestamp/cycle 对齐。
```

定位：

```text
不是 MVP。
不是核心贡献。
作为 semantic enrichment 和对照实验。
```

## 7.3 推荐策略

```text
MVP: no eBPF
After FPGA trace works: evaluate selective memory snapshot
After Linux experiments: optionally add eBPF metadata alignment
```

---

# Trace 格式文档模板

建议建立：

```text
docs/02-trace-architecture/trace_format.md
```

模板：

```markdown
# Trace Format

## Event Types

| Event | Meaning | Required Fields |
| --- | --- | --- |
| RETIRE | committed instruction | cycle, pc, instr |
| BRANCH | committed conditional branch | pc, instr, taken, target |
| JUMP | committed jal/jalr | pc, instr, target |
| SYSCALL_ENTRY | U-mode syscall instruction | pc, priv, syscall_id, a0-a7 |
| SYSCALL_RET | SRET returning to U-mode | pc, priv, target, syscall_id, duration, a0 |
| TRAP | trap/exception/interrupt | pc, cause, tval, priv |
| CSR | watched CSR write | pc, csr, value |
| PRIV | privilege change | old_priv, new_priv, pc |

## Packet Fields

| Field | Width | Meaning |
| --- | --- | --- |
| cycle | 64 | local cycle counter |
| pc | 64 | committed pc |
| instr | 32 | committed instruction |
| target | 64 | branch/jump target |
| priv | 2 | privilege mode |
| satp | 64 | address translation context |
| a0-a7 | 64 each | syscall argument shadow |
```

---

# Signal Map 文档模板

建议建立：

```text
docs/02-trace-architecture/signal_map.md
```

模板：

```markdown
# CVA6 Signal Map

## Commit Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | --- | --- |
| commit_valid | TBD | 1 | committed instruction valid |
| commit_pc | TBD | 64 | committed PC |
| commit_instr | TBD | 32 | committed instruction |
| commit_kill | TBD | 1 | flush/kill |

## Trap Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | --- | --- |
| trap_valid | TBD | 1 | trap visible |
| trap_cause | TBD | 64 | mcause/scause |
| trap_tval | TBD | 64 | mtval/stval |

## Writeback Signals

| Logical Name | CVA6 Signal | Width | Notes |
| --- | --- | --- | --- |
| wb_valid | TBD | 1 | committed register write |
| wb_rd | TBD | 5 | destination register |
| wb_data | TBD | 64 | writeback value |
```

---

# 实验结果文档模板

建议建立：

```text
docs/07-evaluation-evidence/reports/sim_results.md
```

模板：

```markdown
# Vivado Simulation Results

## Summary

| Test | Status | Retire | Branch | Ecall | Trap | Notes |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| smoke | PASS | 0 | 0 | 0 | 0 | TBD |
| branch | PASS | 0 | 0 | 0 | 0 | TBD |

## Artifacts

- results/vivado_sim/<test>/trace.jsonl
- results/vivado_sim/<test>/compare.log
- results/vivado_sim/<test>/xsim.log
- results/vivado_sim/<test>/waveform.wdb
```

---

# 风险与规避

## 风险 1：Vivado 仿真太慢

规避：

```text
先跑最小 bare-metal。
关闭不必要 waveform。
只对失败用例 dump full wave。
用 run-specific filelist。
```

## 风险 2：commit 信号不好定位

规避：

```text
先从 CVA6 commit stage / scoreboard / writeback 文档与源码定位。
建立 signal_map.md。
先做 RETIRE，再做复杂事件。
```

## 风险 3：a0-a7 获取影响 register file

规避：

```text
使用 writeback shadow。
不增加 register file read port。
```

## 风险 4：trace 影响 critical path

规避：

```text
tap 只旁路采样。
packet formatting 打拍。
上板默认不反压 core。
```

## 风险 5：trace 带宽爆炸

规避：

```text
第一版默认关闭 full retire。
优先 syscall/trap/context/branch。
加入 event filter 和 drop counter。
```

## 风险 6：Genesys 2 license / bitstream 卡住

规避：

```text
提前验证 baseline bitstream。
不要等 trace RTL 完成后才检查 license。
```

## 风险 7：eBPF 抢走项目贡献点

规避：

```text
论文/报告主线必须是 RTL-level committed behavior trace。
eBPF 只作为 optional semantic enrichment。
```

---

# 推荐执行顺序

## 当前立即做

```text
1. 固定 CVA6 commit
2. 固定 Vivado/toolchain version
3. 建 docs/10-process/version_lock.md
4. 建 docs/02-trace-architecture/signal_map.md
5. 跑未修改 CVA6 Vivado baseline
6. 找 commit_pc / commit_instr / commit_valid
7. 实现 trace_pkg.sv
8. 实现 retire_tap.sv
9. 接 tb_trace_sink.sv 输出 JSONL
10. 跑 smoke test
11. 实现 branch_tap.sv
12. 跑 branch/jump tests
13. 实现 arg_shadow.sv
14. 实现 syscall_tap.sv
15. 跑 ecall test
16. 实现 trap_tap.sv
17. 跑 illegal/ebreak tests
18. 实现 context_tap.sv
19. 写 Python parser/checker
20. 跑完整 Vivado regression
```

## 然后做

```text
21. 加 trace FIFO
22. 测 backpressure
23. 加 trace filter
24. 做 synthesis sanity check
25. 记录资源/timing
26. 准备 Genesys 2 baseline
27. 上板 boot 未修改系统
28. 上板 trace-enabled 系统
29. 采集 syscall/context/trap trace
30. 跑 benign 与 malware-like 行为样本
```

## 最后增强

```text
31. 加 syscall pointer metadata
32. 评估是否需要 memory snapshot
33. 评估 kernel helper
34. 评估 eBPF semantic enrichment
35. 做对照实验
36. 写论文/报告
```

---

# 最小可交付 MVP

MVP 范围压缩到：

```text
CVA6 + Vivado xsim
RetireTap
BranchTap
SyscallTap
TrapTap
a0-a7 shadow
trace JSONL output
Python checker
5 个 bare-metal tests
```

MVP 不包括：

```text
Linux 仿真
Genesys 2 上板
full memory trace
eBPF
DMA trace streaming
真实 malware
复杂 packet compression
```

---

# 最终判断

这套计划的核心路线应该是：

```text
先证明 RTL-level committed behavior trace 是正确的；
再证明它能在 Genesys 2 上对 Linux 用户态程序产生稳定 trace；
最后再决定是否加入 memory semantic enrichment。
```

对 eBPF 的定位应该明确：

```text
eBPF 不是 MVP 依赖。
eBPF 不是核心贡献。
eBPF 是后期可选语义补充。
```

一句话版本：

> 第一版应该做 “CVA6 commit-level hardware behavior tracing”，不是做 “RISC-V eBPF tracing”。先在 Vivado 中把 Retire / Branch / Syscall / Trap / Context trace 做准，再上 Genesys 2；memory data 和 eBPF 放到后期增强。
