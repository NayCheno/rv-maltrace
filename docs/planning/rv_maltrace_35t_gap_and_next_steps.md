# RV-MalTrace 35T 当前差距分析与下一步计划

生成日期：2026-05-20
建议仓库路径：`docs/planning/35t_trace_code_malware_gap_analysis.md`
适用范围：Artix-7 35T / LiteX / VexRiscv 原型链路

---

## 0. 一句话结论

当前项目已经完成 **35T 板级硬件 trace acquisition 原型**，并且 p0c 512 profile 可以在低 DROP 条件下完成上板采集；但它还没有形成可靠的：

```text
硬件 trace
  + 本地代码分析
  + malware-like / malware 行为分析
```

闭环。

核心短板不是“板子没跑起来”，而是：

```text
缺进程/地址空间归因
缺 PC -> ELF/symbol/source 的代码映射
缺 trace evidence 与 code evidence 的融合
缺稳定的 per-rep semantic/audit gate
缺可支撑 malware analysis 的行为链与置信度模型
```

因此当前可以写：

```text
35T/VexRiscv synthetic behavior tracing prototype is working.
p0c 512 is the current low-drop capacity candidate.
```

当前不能写：

```text
CVA6 board validation is complete.
Real malware detection has been validated.
Hardware trace + local code analysis malware analyzer is complete.
Syscall semantic recovery is mature.
```

---

## 1. 当前证据边界

### 1.1 已经成立的证据

| 项目 | 当前状态 | 说明 |
|---|---|---|
| 35T 板卡连接 | 已成立 | 板载 CH340，用户口误 `CMOS5` 已按本机枚举为 `COM5` 使用。 |
| 35T Linux / LiteX / VexRiscv 上板 | 已成立 | 已完成 Linux boot、实验 runner、trace dump、aggregate report。 |
| trace profile / mask | 已实现 | `p0`、`p0a`、`p0b`、`p0c` 等 profile 已进入 runner 和 `run_config.json`。 |
| p0c 512 上板容量 | 当前最佳 | DROP 约 1.9–2.5%，无 cap hit；但仍不是 semantic-detector 候选。 |
| ABBA runtime methodology | 已成立 | p0c 512 ABBA reps=10，trace ratio 约 1.006–1.012。 |
| resource/timing 报告 | 已有 | baseline、p0 256、p0 512、p0 1024 failure 均已记录。 |
| strict gate | 已有雏形 | `check_35t_next_gate.py` 能输出 sample status、DROP、event set、alignment、audit summary。 |

### 1.2 尚未成立的证据

| 项目 | 当前状态 | 风险 |
|---|---|---|
| CVA6 board claim | 未成立 | 当前证据只来自 35T / LiteX / VexRiscv。 |
| real malware claim | 未成立 | 当前样本是 synthetic malware-like，不是真实恶意样本。 |
| mature detector claim | 未成立 | 语义恢复与规则稳定性不足。 |
| full matrix promotion | 被阻断 | microbench semantic/audit gate 尚未通过。 |
| case-study promotion | 被阻断 | `prototype_only` 下 case-study 生成器拒绝推广是正确行为。 |

---

## 2. 目标拆解：当前离“硬件 trace + 本地代码分析 + malware 分析”差在哪

目标可以拆成三层：

```text
Layer A: Hardware Trace
Layer B: Local Code Analysis
Layer C: Malware Behavior Analysis
```

### 2.1 Layer A：硬件 trace

| 子目标 | 当前状态 | 缺口 |
|---|---|---|
| 非侵入式 trace capture | 基本成立 | 35T trace ring 可采集 syscall/trap/context/drop。 |
| 低 DROP profile | 部分成立 | p0c 512 低 DROP；p0 256/512 DROP 高，p0 1024 放置失败。 |
| process-scoped trace | 未成立 | 当前是 CPU-wide 时间窗采集，不是目标进程采集。 |
| context-rich trace | 未成立 | p0 context 流量过大；p0c 去掉 context 后语义归因变弱。 |
| 可扩展 ring capacity | 未成立 | 512 已 LUT 翻倍，1024 因 LUT-as-memory / RAMD64E over-utilization 失败。 |

### 2.2 Layer B：本地代码分析

| 子目标 | 当前状态 | 缺口 |
|---|---|---|
| trace disassembly annotation | 有雏形 | `annotate_trace_disasm.py` 可把 trace PC 与 objdump join。 |
| PC -> ELF 映射 | 未建立 | 不能判断 PC 属于 sample、runner、libc、kernel 还是其他用户态进程。 |
| PC -> symbol/function 映射 | 未建立 | 不能把 syscall/trap 归因到具体函数或 callsite。 |
| syscall site / trap site 识别 | 未建立 | `illegal_trap` 等规则不能证明 trap 来自目标样本代码。 |
| code evidence 进入 audit | 未建立 | 当前规则主要看 syscall/trap shape，不看代码证据。 |

### 2.3 Layer C：malware 行为分析

| 子目标 | 当前状态 | 缺口 |
|---|---|---|
| synthetic behavior audit | 有雏形 | 已有 file scan、batch read/write、self copy、anti-debug 等规则。 |
| 行为链恢复 | 不稳定 | fd flow、path、exec chain、process tree、mmap/mprotect 语义不足。 |
| malware family / IOC 分析 | 未建立 | 目前不是 malware family classifier，也不能输出 IOC。 |
| 置信度模型 | 未建立 | 不能区分 strong evidence、weak evidence、noise、blocked by DROP。 |
| real malware workflow | 未建立 | 尚无隔离、法律/伦理、样本 provenance、containment、artifact gate。 |

---

## 3. 当前主要缺陷

## 3.1 缺陷一：trace 没有绑定目标进程

当前 `rvmt_exp_runner` 的执行窗口是：

```text
trace_set_mode(on)
  fork()
  child: chdir / setenv / execl(sample)
  parent: waitpid(child)
trace dump
trace_set_mode(off)
```

这意味着 trace 不是“样本进程 trace”，而是“CPU-wide 时间窗 trace”。

因此 trace 中可能混入：

```text
runner 自身事件
fork / exec / waitpid 路径
shell / console / UART 相关事件
kernel trap / scheduler / privilege transition
非目标用户态代码
```

直接后果：

| 现象 | 解释 |
|---|---|
| `hello` 误报 `illegal_instruction_trap` | 系统窗口中出现的 trap 被错误归因到 benign 样本。 |
| `illegal_trap` 漏报自身 expected rule | trap/write 没有被稳定归因到同一目标样本执行窗口。 |
| alignment recall / LCS 低 | QEMU strace 是单进程视角；board trace 是系统时间窗视角。 |
| audit false positive / false negative | 规则没有进程边界，容易把噪声当证据。 |

这是当前最高优先级问题。

---

## 3.2 缺陷二：PC 不知道属于谁

当前 semantic recovery 能看到：

```json
{
  "evt": "SYSCALL_ENTRY",
  "pc": "0x...",
  "a7": "0x..."
}
```

但不知道：

```text
这个 PC 属于目标样本 ELF 吗？
属于 runner 吗？
属于 libc/static binary 吗？
属于 kernel/S-mode 吗？
属于哪个 function？
是不是一个 syscall callsite？
是不是 illegal instruction site？
```

没有这些信息，本地代码分析无法进入规则判定。

### 应增加的字段

```json
{
  "pc_owner": "target_sample | runner | libc | kernel | unknown",
  "elf": "...",
  "section": ".text",
  "symbol": "handle_sigill",
  "symbol_offset": "0x14",
  "source_file": "illegal_trap.c",
  "source_line": 17,
  "callsite_kind": "syscall_site | trap_site | normal_code | unknown",
  "code_confidence": "pc_in_target_elf"
}
```

---

## 3.3 缺陷三：p0c 解决容量，但牺牲上下文

p0c 512 的好处：

```text
DROP 低
无 cap hit
适合 syscall/trap/drop low-bandwidth microbench
```

但 p0c 禁用了 context，代价是：

```text
缺少 CSR / SATP / PRIV 事件
缺地址空间线索
缺 user/kernel 转换细节
缺进程归因辅助信息
复杂行为链难恢复
```

所以 p0c 应定位为：

```text
current capacity candidate
```

不能定位为：

```text
semantic detector candidate
```

---

## 3.4 缺陷四：trace ring 资源形态不合理

资源报告显示：

```text
baseline LiteX/VexRiscv: 7181 LUT, 6758 FF, 27 BRAM18
p0 trace 512:          14663 LUT, 8175 FF, 27 BRAM18
p0 trace 1024:         LUT-as-memory / RAMD64E over-utilization
```

关键异常：

```text
512 depth trace 增加 +7482 LUT，但 BRAM18 增量是 0。
```

这说明 trace ring 很可能主要落在 distributed RAM / LUT RAM，而不是 BRAM。

当前 `RVMTTraceRing` 使用：

```python
mem = Memory(32, depth * entry_words, name="rvmt_trace_mem")
read_port = mem.get_port(async_read=True)
```

异步读口通常不利于推断 block RAM。下一步应该把 ring 改成 synchronous BRAM-backed ring。

---

## 3.5 缺陷五：decoder 会隐藏坏包

当前 raw record decoder 中未知 event code 被处理成 `DROP` 的风险很高：

```python
evt = event_names.get(header & 0xf, "DROP")
```

这会把以下问题掩盖成正常 DROP：

```text
UART corruption
header corruption
packet layout mismatch
parser bug
未定义 event code
```

正确做法是输出：

```json
{
  "evt": "UNKNOWN",
  "evt_code": 15,
  "raw_header": "0x...",
  "raw_words": [...],
  "parser_warning": "unknown_event_code"
}
```

然后 gate 中直接 fail：

```text
UNKNOWN event count must be 0.
```

---

## 3.6 缺陷六：audit rules 还是启发式 shape，不是 malware analysis

当前规则能表达：

```text
是否出现了某些 syscall/trap pattern
是否大致符合 synthetic behavior
```

但不能稳定表达：

```text
该行为是否来自目标样本代码
是否来自同一进程/地址空间
是否构成完整行为链
证据置信度是多少
是否属于 malware family / IOC / TTP
```

例如当前 `illegal_instruction_trap` 规则如果只要求：

```text
有 write
有 illegal instruction trap
```

就会误报 benign。它应该要求：

```text
trap cause == 0x2
trap PC 属于目标样本 ELF
trap PC 对应 illegal instruction site
trap privilege / context 表明是用户态异常
handler write 属于同一目标进程执行窗口
```

---

## 4. 下一步路线

## 4.1 总体策略

不要立即跑 full matrix。下一步应先修归因和语义，再上板小矩阵验证。

推荐路线：

```text
P1: 离线失败归因报告
P2: decoder UNKNOWN/raw packet 修复
P3: target-scoped trace 最小闭环
P4: code map / 本地代码分析层
P5: trace evidence + code evidence 融合 audit
P6: per-rep stability gate
P7: BRAM-backed trace ring
P8: 小矩阵上板复验
P9: 达标后再 full matrix
```

---

## 4.2 P1：新增 semantic failure triage

### 目标

复用当前 p0c 512 ABBA artifacts，不上板，先把失败拆清楚。

### 新增工具

```text
tools/triage_35t_semantic_failures.py
```

### 输入

```text
results/experiments/35t/35t-p0c-abba-r512-20260520-com5/
```

### 输出

```text
aggregate/semantic_failure_triage.json
aggregate/semantic_failure_triage.md
```

### 报告字段

```json
{
  "sample": "hello",
  "observed_failure": "unexpected illegal_instruction_trap",
  "failure_class": "trap_rule_false_positive_or_missing_target_attribution",
  "suspected_root_cause": "CPU-wide trace window",
  "required_fix": "target/process/code attribution"
}
```

### 必须覆盖的样本

| 样本 | 当前问题 | 归因方向 |
|---|---|---|
| `hello` | unexpected `illegal_instruction_trap` | trap rule 误报 / 目标归因缺失 |
| `batch_open_read_write` | missing `batch_file_read_write` | syscall sequence / fd flow / target filter 问题 |
| `illegal_trap` | missing `illegal_instruction_trap` | trap PC/cause/handler write 归因失败 |
| `anti_debug_like` | 当前较好 | 保持为 positive regression |

### 验收命令

```powershell
uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-abba-r512-20260520-com5
uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
```

---

## 4.3 P2：修 decoder，不再隐藏坏包

### 修改点

```text
src/rv_maltrace/cli.py
tools/experiment_35t.py
```

### 必做修改

1. 未知 event code 输出 `UNKNOWN`，不要默认 `DROP`。
2. 每条 decoded event 保留 raw record 信息。
3. parser warning 单独落盘。
4. gate 对 `UNKNOWN` / corrupt packet / forbidden event 直接 FAIL。

### 建议 event schema

```json
{
  "record_index": 12,
  "evt": "UNKNOWN",
  "evt_code": 15,
  "raw_header": "0x0000000f",
  "raw_words": ["0x..."],
  "parser_warnings": ["unknown_event_code"]
}
```

### 验收标准

| 检查项 | PASS 条件 |
|---|---|
| self-test | `tools/experiment_35t.py --stage self-test` 通过。 |
| gate self-test | `tools/check_35t_next_gate.py --self-test` 通过。 |
| UNKNOWN visibility | 离线重解析旧 run 后，UNKNOWN 不被 DROP 吞掉。 |
| gate behavior | UNKNOWN count > 0 时 run 标为 FAIL。 |

---

## 4.4 P3：target-scoped trace 最小闭环

### 短期方案：MARKER + PC range

在硬件或 CSR 层支持 `MARKER` 事件，runner 在样本执行边界写 marker：

```text
MARKER sample_begin <sample_id>
MARKER sample_end <sample_id>
```

semantic recovery 只分析 marker 范围内事件。

同时生成目标样本 ELF load range：

```json
{
  "sample_id": "illegal_trap",
  "elf": "build/illegal_trap.riscv",
  "text_ranges": [
    {"start": "0x00010000", "end": "0x00018000"}
  ]
}
```

只把 `pc` 落入目标 ELF range 的 U-mode syscall/trap 作为 strong evidence。

### 长期方案：PID / TGID / SATP / context attribution

后续需要记录：

```json
{
  "pid": 123,
  "tgid": 123,
  "comm": "illegal_trap",
  "satp": "0x...",
  "asid": "...",
  "target_process": true
}
```

可选实现路径：

| 路径 | 说明 | 适合阶段 |
|---|---|---|
| kernel helper / eBPF companion | 记录 pid/tgid/comm、context switch、syscall pointer string | 近期可行 |
| hardware context trace | 捕获 SATP/priv/context 并离线 join | 长期论文路线 |

---

## 4.5 P4：建立本地代码分析层

### 新增工具

```text
tools/build_code_map.py
tools/join_trace_code_map.py
```

### stage_groundtruth 应生成

```text
build/<sample>.riscv
build/<sample>.riscv.dump
build/<sample>.symbols.json
build/<sample>.sections.json
build/<sample>.syscall_sites.json
build/<sample>.trap_sites.json
build/<sample>.code_map.json
```

### 建议编译参数

```bash
riscv64-linux-gnu-gcc -O2 -static -fno-pie -no-pie -o <sample>.riscv <source>.c
```

如果 `-no-pie` 不兼容，则记录失败并改用 ELF program header / load map 校正 PC。

### `code_map.json` 最小 schema

```json
{
  "schema": "rvmt.code_map.v1",
  "sample_id": "illegal_trap",
  "elf": "results/.../build/illegal_trap.riscv",
  "sha256": "...",
  "load_ranges": [
    {"start": "0x...", "end": "0x...", "segment": "text"}
  ],
  "symbols": [
    {"name": "handle_sigill", "start": "0x...", "end": "0x..."}
  ],
  "syscall_sites": [
    {"pc": "0x...", "symbol": "handle_sigill", "asm": "ecall"}
  ],
  "trap_sites": [
    {"pc": "0x...", "symbol": "main", "kind": "illegal_instruction", "asm": ".word 0xffffffff"}
  ]
}
```

### join 后 semantic event 应包含

```json
{
  "evt": "TRAP",
  "pc": "0x...",
  "pc_owner": "target_sample",
  "symbol": "main",
  "callsite_kind": "illegal_instruction_site",
  "code_confidence": "pc_in_target_elf"
}
```

---

## 4.6 P5：重写 audit rules，让规则同时依赖 trace evidence 和 code evidence

### `illegal_instruction_trap`

当前过宽。应改为 strong / weak 两级。

#### strong match

```text
trap cause == 0x2
AND trap PC owner == target_sample
AND trap PC site == illegal_instruction_site
AND trap privilege/context shows user-mode exception
AND handler write is in same target execution window
```

#### weak evidence

```text
trap cause == 0x2
AND write exists
BUT no target PC / no code map / no same-process evidence
```

weak evidence 只能写入报告，不能算 matched expected behavior。

---

### `batch_file_read_write`

不要只看 syscall count。应加入 fd-flow：

```text
openat(input_i) -> fd_i
read(fd_i) -> buffer
close(fd_i)
openat(output) -> fd_o
write(fd_o)
close(fd_o)
```

没有 pointer/path semantics 时，只能标为：

```text
batch_file_read_write_shape
```

不能标为完整 `batch_file_read_write`。

---

### `anti_analysis_indicator`

当前要求 `ptrace` 是合理的。继续保持 `clock_gettime` alone 不算 anti-analysis。

建议增加：

```text
ptrace syscall must belong to target sample
return value / failure semantics should be recorded
```

---

## 4.7 P6：gate 改成 per-rep stability

当前 aggregate/gate 容易被跨 rep union 掩盖不稳定性。下一步必须输出 per-rep 矩阵。

### 新增字段

```json
{
  "per_rep_rule_matrix": {
    "rep_00": {"illegal_instruction_trap": false},
    "rep_01": {"illegal_instruction_trap": true}
  },
  "rule_stability": {
    "illegal_instruction_trap": {
      "matched_reps": 8,
      "total_reps": 10,
      "stability": 0.8
    }
  }
}
```

### 建议晋级标准

| 指标 | 晋级门槛 |
|---|---:|
| benign unexpected matched | 0 / rep |
| malware expected matched | ≥ 80% reps |
| `hello` ordered_lcs_ratio | ≥ 0.5 |
| `illegal_trap` expected matched | ≥ 80% reps |
| p0c median DROP | ≤ 5% |
| UNKNOWN / corrupt event | 0 |
| forbidden event | 0 |

---

## 4.8 P7：把 35T trace ring 改成 BRAM-backed

### 修改目标

```text
fpga/artix7_35t/litex/rvmt_trace.py
```

当前 ring 很可能因为 async read 被推成 LUT RAM。建议改为同步读，并增加 RAM style hint。

### 方向示例

```python
mem = Memory(32, depth * entry_words, name="rvmt_trace_mem")
mem.attr.add("ram_style", "block")
read_port = mem.get_port(async_read=False)
```

CSR dump 端需要适配一拍读延迟：

```text
write read_index
wait / dummy read
read stable read_word
```

### 验收目标

| 配置 | PASS 条件 |
|---|---|
| p0 trace 512 | LUT delta 明显下降，BRAM delta 上升。 |
| p0 trace 1024 | Vivado place 至少能通过，或记录新的非 LUT-memory blocker。 |
| timing | WNS ≥ 0 at 50 MHz。 |
| board dump | trace dump 与旧 parser 兼容或提供迁移说明。 |

---

## 4.9 P8：小矩阵上板复验

不要直接 full matrix。先复验 4 个样本：

```text
hello
batch_open_read_write
illegal_trap
anti_debug_like
```

### p0c 512 semantic-fix run

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-p0c-r512-semantic-fix-<date> --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-r512-semantic-fix-<date> --reps 5
uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-r512-semantic-fix-<date> --reps 5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like
```

### 晋级要求

```text
hello unexpected rules == 0
illegal_trap expected matched >= 80% reps
batch_open_read_write at least weak shape matched
anti_debug_like remains matched
median DROP <= 5%
UNKNOWN/corrupt events == 0
```

---

## 4.10 P9：full matrix 的触发条件

只有满足以下条件才允许跑 full matrix：

| 条件 | 要求 |
|---|---|
| microbench bundle | 4/4 samples complete。 |
| DROP | p0c 512 median DROP ≤ 5%，或 p0 1024 context profile 达标。 |
| false positive | `hello`、`cat`、`cp`、`sha256sum` 不出现 unexpected malware-like rules。 |
| expected behavior | 关键 malware-like samples expected matched ≥ 80% reps。 |
| code attribution | 至少 `illegal_trap`、`anti_debug_like`、`batch_open_read_write` 有 target code evidence。 |
| gate claim | 不再是 `prototype_only`，至少达到 `microbench_ready`。 |

full matrix 命令：

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-full-semantic-<date> --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop
uv run python tools/check_35t_experiment_bundle.py --run-id 35t-full-semantic-<date> --reps 5
uv run python tools/check_35t_next_gate.py --run-id 35t-full-semantic-<date> --reps 5
```

如果 BRAM ring 后 p0 1024 通过，应优先选择 p0 1024：

```powershell
uv run rvmt exp:35t --stage all --run-id 35t-full-p0-r1024-<date> --port COM5 --baud 921600 --reps 5 --trace-records 1024 --trace-profile p0_syscall_trap_context
```

---

## 5. 建议写入论文/报告的当前表述

### 5.1 可以写

```text
We implemented and validated a low-cost Artix-7 35T / LiteX / VexRiscv prototype path.
The 35T route can collect syscall/trap/drop traces on board.
The p0c profile at 512 records is the current low-drop capacity candidate.
The current bottleneck is target attribution and semantic reconstruction, not board bring-up.
```

### 5.2 不应该写

```text
The system detects real malware.
The semantic recovery is mature.
The 35T profile validates CVA6 behavior.
The p0c result proves full behavior reconstruction.
The current audit accuracy reflects real malware detection accuracy.
```

### 5.3 推荐术语

| 不推荐 | 推荐 |
|---|---|
| malware detector | synthetic malware-like behavior audit prototype |
| real malware accuracy | controlled synthetic behavior-rule result |
| CVA6 board result | 35T/LiteX/VexRiscv board result |
| complete semantic reconstruction | preliminary trace-derived semantic recovery |
| hardware trace is enough | hardware trace requires target/code attribution |

---

## 6. 最短执行清单

### 立即做

```text
1. 写 semantic_failure_triage 工具。
2. 修 decoder UNKNOWN/raw_words/parser_warnings。
3. 生成 target ELF code_map。
4. recover_behavior 加 pc_owner / symbol / callsite_kind。
5. illegal_instruction_trap 规则收紧。
6. gate 加 per-rep stability。
7. p0c 512 四样本上板复验。
```

### 并行做

```text
1. trace ring 改同步 BRAM。
2. 重新生成 512/1024 resource report。
3. 如果 1024 place 通过，再跑 p0 1024 microbench。
```

### 暂时不要做

```text
1. 不要直接跑 full matrix。
2. 不要生成 case study promotion。
3. 不要加入真实恶意样本。
4. 不要写 detector claim。
5. 不要把 p0c 512 说成 complete semantic profile。
```

---

## 7. 预期完成后的能力边界

完成上述 P1–P8 后，合理目标是：

```text
在 35T/VexRiscv 上，证明硬件 trace 可以结合本地 ELF/code map，
对少量 synthetic malware-like 行为给出可归因、可复验、低 DROP 的行为证据。
```

这会把当前状态从：

```text
hardware trace acquisition prototype
```

推进到：

```text
hardware trace + local code attribution + synthetic behavior audit prototype
```

但仍然不是：

```text
real malware analysis system
```

要进入 real malware analysis，还需要额外增加：

```text
隔离环境
样本 provenance
法律/伦理流程
恶意样本执行策略
IOC extraction
family/TTP mapping
baseline comparison
artifact release policy
```

---

## 8. 参考依据

本分析基于以下仓库文档、代码和 agent 执行记录整理：

```text
README.md
docs/planning/next-plan.md
docs/research/evaluation_plan.md
docs/planning/35t_next_strict_plan.md
docs/reports/35t_next_strict_status.md
docs/reports/artix7_35t_resource_report.md
docs/board/artix7_35t_trace_profiles.md
docs/architecture/trace_format.md
src/rv_maltrace/trace_profiles.py
src/rv_maltrace/cli.py
tools/experiment_35t.py
tools/check_35t_next_gate.py
tools/recover_behavior.py
tools/audit_behavior.py
tools/annotate_trace_disasm.py
fpga/artix7_35t/litex/rvmt_trace.py
fpga/artix7_35t/litex/rvmt_trace_patch.py
board/artix7_35t/linux/rvmt_exp_runner.c
experiments/linux_behavior/behavior_audit_rules.json
experiments/linux_behavior/benign/manifest.json
experiments/linux_behavior/malware_like/manifest.json
```
