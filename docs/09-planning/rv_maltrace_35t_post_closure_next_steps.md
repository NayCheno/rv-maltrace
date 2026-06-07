# RV-MalTrace 35T Post-Closure Next Steps 与 Agent 执行规格

生成日期：2026-05-21
适用范围：**Artix-7 35T / LiteX / VexRiscv**
明确不包含：**CVA6**、真实恶意样本执行、真实 malware detection accuracy、mature detector claim

---

## 1. 当前状态基线

当前仓库已经完成了 35T 应用闭环收口文档：

```text
docs/08-publication/rv_maltrace_35t_application_closure.md
docs/08-publication/rv_maltrace_35t_application_case_studies.md
```

当前可成立的 claim level 是：

```text
35T hardware-trace-assisted synthetic malware-like behavior audit prototype
```

也就是：

```text
35T / LiteX / VexRiscv 上已经形成 hardware trace、runtime process attribution、
local ELF/code-map assisted trace analysis、synthetic malware-like behavior audit
的受控原型闭环。
```

当前不能声称：

```text
real malware detector
real malware detection accuracy
mature detector
CVA6 validation
complete semantic reconstruction
real malware family / IOC / TTP coverage
```

当前主证据基线应保持为：

```text
run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records: 512
trace_profile_policy: 35t_small_capacity
samples: 13
gate: 13/13 PASS
full_matrix_ready: True
```

---

## 2. 本阶段总目标

本阶段不是继续扩大 claim，而是把 35T 结果从：

```text
文档已完成 + 本地 evidence 路径可引用
```

提升为：

```text
远程仓库可复核的 35T evidence snapshot + 自动一致性检查 + 更强解释层能力
```

核心任务分三类：

| 类别 | 目标 | 为什么重要 |
|---|---|---|
| Evidence 可复核 | 提交轻量 evidence snapshot | 让 GitHub 上的读者能复核 result card，不依赖本地 results 目录 |
| Claim 防漂移 | 增加 closure checker | 防止文档后续误写成 real malware detector / CVA6 validation |
| 解释层增强 | fd/path、process tree、source/function attribution | 把应用从 syscall-shape audit 提升到更可解释的 malware-like behavior analysis prototype |

---

## 3. P0：提交轻量 evidence snapshot

### 3.1 目标

创建一个可提交到 GitHub 的轻量证据目录，只包含 summary、JSON、Markdown、hash manifest，不提交大 trace dump、bitstream、build 目录或板端原始大文件。

推荐路径：

```text
docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/
```

### 3.2 推荐目录结构

```text
docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/
  README.md
  evidence_manifest.json
  run_config.json
  gate_report.json
  gate_report.md
  semantic_failure_triage.json
  semantic_failure_triage.md
  process_chain_capacity_debug.json
  process_chain_capacity_debug.md
  command_log.md
  sample_matrix_summary.json
  sample_matrix_summary.md
  case_study_artifact_index.json
```

如某些文件在本地 run 中不存在，不要伪造。写入：

```text
MISSING in current evidence bundle
```

并在 `README.md` 和 `evidence_manifest.json` 中记录缺口。

### 3.3 必须从本地结果中复制或生成的来源

优先从以下路径复制小型 summary 文件：

```text
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.json
results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md
```

如果原始文件过大，只保留 summary 字段，并在 `evidence_manifest.json` 中记录：

```json
{
  "source_path": "...",
  "committed_path": "...",
  "mode": "summary_only",
  "reason": "avoid committing large generated artifacts"
}
```

### 3.4 evidence_manifest.json 必填字段

```json
{
  "schema": "rvmt.35t.evidence_snapshot.v1",
  "run_id": "35t-smallcap-r512-full-synthetic-matrix-20260521",
  "scope": "Artix-7 35T / LiteX / VexRiscv",
  "trace_records": 512,
  "trace_profile_policy": "35t_small_capacity",
  "samples": 13,
  "gate": "13/13 PASS",
  "full_matrix_ready": true,
  "real_malware": false,
  "cva6_in_scope": false,
  "non_claims": [
    "no CVA6 board claim",
    "no real malware detection claim",
    "no mature detector claim",
    "no classifier accuracy claim",
    "no complete semantic reconstruction claim"
  ],
  "committed_artifacts": [],
  "missing_artifacts": [],
  "source_results_root": "results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521"
}
```

### 3.5 README.md 必须包含

```markdown
# 35T Evidence Snapshot: 35t-smallcap-r512-full-synthetic-matrix-20260521

## Scope
## Claim Level
## What Is Included
## What Is Not Included
## How To Re-check
## Artifact Index
## Non-claims
```

### 3.6 验收标准

- [ ] `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/` 存在。
- [ ] `evidence_manifest.json` 存在，并且字段与 closure 文档一致。
- [ ] 至少包含 `run_config`、`gate_report`、`semantic_failure_triage` 的 summary 或 missing 记录。
- [ ] 不提交大 trace dump、bitstream、Vivado build、board build 目录。
- [ ] `docs/08-publication/rv_maltrace_35t_application_closure.md` 中的 evidence path 更新为优先指向 committed snapshot。
- [ ] 保留原始本地结果路径作为 source path，而不是唯一证据路径。

---

## 4. P1：新增 35T application closure checker

### 4.1 目标

新增一个自动检查脚本，确保 result card、case studies、evidence snapshot 三者一致，并防止 claim 越界。

推荐文件：

```text
tools/check_35t_application_closure.py
```

### 4.2 检查内容

脚本至少检查：

1. 必要文件存在：

```text
docs/08-publication/rv_maltrace_35t_application_closure.md
docs/08-publication/rv_maltrace_35t_application_case_studies.md
docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/evidence_manifest.json
```

2. 必要字段一致：

```text
run_id == 35t-smallcap-r512-full-synthetic-matrix-20260521
trace_records == 512
trace_profile_policy == 35t_small_capacity
samples == 13
gate == 13/13 PASS
full_matrix_ready == True
```

3. 必要 case studies 覆盖：

```text
illegal_trap
process_chain
dynamic_executable_memory
file_scan 或 batch_open_read_write
```

4. 必要 non-claims 存在：

```text
no CVA6 board claim
no real malware detection claim
no mature detector claim
no classifier accuracy claim
no complete semantic reconstruction claim
```

5. 禁止越界表述。

禁止或至少警告以下表达：

```text
real malware detector
real malware detection accuracy
validated CVA6
CVA6 validation
mature detector
complete semantic reconstruction
malware family coverage
IOC coverage
TTP coverage
```

注意：脚本应允许这些词出现在 `Forbidden Wording` 或 `What This Does Not Prove` 之类的否定上下文中。实现上可以先做保守 warning，再人工检查。

### 4.3 输出

推荐输出：

```text
docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/application_closure_check.json
docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/application_closure_check.md
```

JSON schema 建议：

```json
{
  "schema": "rvmt.35t.application_closure_check.v1",
  "status": "PASS",
  "checked_files": [],
  "required_fields": {},
  "case_study_coverage": {},
  "non_claims": {},
  "warnings": [],
  "failures": []
}
```

### 4.4 命令

```bash
uv run python tools/check_35t_application_closure.py --self-test
uv run python tools/check_35t_application_closure.py \
  --repo-root . \
  --evidence-root docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521
```

### 4.5 验收标准

- [ ] 脚本有 `--self-test`。
- [ ] 脚本能在没有硬件、没有 Vivado、没有完整 `results/` 的环境下运行。
- [ ] 脚本只依赖 committed docs / snapshot。
- [ ] 检查失败时退出非零码。
- [ ] 检查结果输出 JSON 和 Markdown。
- [ ] 文档中记录该 checker 的命令和 PASS/FAIL 状态。

---

## 5. P2：把 self-test / compile check 纳入轻量 CI 或本地 regression

### 5.1 目标

让当前 35T closure 不只停留在文档层面，而是有可重复的轻量检查链。

### 5.2 推荐命令

```bash
uv run python tools/experiment_35t.py --stage self-test
uv run python tools/check_35t_next_gate.py --self-test
uv run python tools/triage_35t_semantic_failures.py --self-test
uv run python tools/recover_behavior.py --self-test
uv run python tools/audit_behavior.py --self-test
uv run python tools/build_code_map.py --self-test
uv run python tools/join_trace_code_map.py --self-test
uv run python tools/check_35t_application_closure.py --self-test
uv run python tools/check_35t_application_closure.py --repo-root .
uv run python -m compileall tools src/rv_maltrace
```

### 5.3 可选 GitHub Actions

如仓库当前没有 CI，可新增：

```text
.github/workflows/35t_docs_and_tools.yml
```

只运行不需要硬件的命令：

```yaml
name: 35T docs and tooling checks

on:
  push:
  pull_request:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - name: Install dependencies
        run: uv sync
      - name: Compile Python
        run: uv run python -m compileall tools src/rv_maltrace
      - name: Self-tests
        run: |
          uv run python tools/experiment_35t.py --stage self-test
          uv run python tools/check_35t_next_gate.py --self-test
          uv run python tools/triage_35t_semantic_failures.py --self-test
          uv run python tools/recover_behavior.py --self-test
          uv run python tools/audit_behavior.py --self-test
          uv run python tools/build_code_map.py --self-test
          uv run python tools/join_trace_code_map.py --self-test
          uv run python tools/check_35t_application_closure.py --self-test
          uv run python tools/check_35t_application_closure.py --repo-root .
```

如果 `uv sync` 或某些工具在 CI 中缺依赖，先不要硬凹 PASS；记录失败原因，必要时缩小 CI 到 compile + closure checker。

### 5.4 验收标准

- [ ] 本地 regression 命令状态记录到 `command_log.md`。
- [ ] 如果新增 CI，workflow 不要求硬件、不要求 Vivado、不要求 board artifacts。
- [ ] CI 失败不隐藏；在最终回复中说明失败命令和原因。

---

## 6. P3：实现 fd/path flow recovery

### 6.1 目标

把当前 syscall-shape audit 提升为可解释的文件行为流：

```text
openat(path) -> fd -> read/write/getdents64/close
execve(path)
```

这一步最直接增强：

```text
file_scan
batch_open_read_write
self_copy_sim
anti_debug_like
```

### 6.2 推荐实现位置

优先扩展现有工具：

```text
tools/recover_behavior.py
src/rv_maltrace/
```

如果现有结构不适合，可新增：

```text
src/rv_maltrace/fd_path_flow.py
tools/recover_fd_path_flow.py
```

### 6.3 输入

应支持从现有 behavior recovery / trace summaries 中读取 syscall events。至少需要字段：

```text
pid 或 runtime process identity
syscall number/name
syscall entry/return
arguments, if available
return value, if available
timestamp/order index
marker scope / sample identity
```

如果当前 trace 不含完整 syscall arguments，则必须在输出中标明：

```text
argument-level fd/path recovery unavailable in current evidence
```

不要伪造 path 或 fd。

### 6.4 输出

推荐输出：

```text
fd_path_flow_summary.json
fd_path_flow_summary.md
```

JSON schema 建议：

```json
{
  "schema": "rvmt.fd_path_flow.summary.v1",
  "sample": "file_scan",
  "status": "PASS_OR_PARTIAL_OR_UNAVAILABLE",
  "flows": [
    {
      "process": "...",
      "path": "...",
      "fd": 3,
      "events": ["openat", "getdents64", "close"],
      "confidence": "strong|medium|weak",
      "limitations": []
    }
  ],
  "unresolved_fds": [],
  "unresolved_paths": [],
  "limitations": []
}
```

### 6.5 Self-test

新增或扩展：

```bash
uv run python tools/recover_behavior.py --self-test
# 或
uv run python tools/recover_fd_path_flow.py --self-test
```

测试至少覆盖：

- `openat` 返回 fd，然后 `read(fd)` / `close(fd)`；
- `openat` 失败返回负值，不应创建有效 fd flow；
- fd 被关闭后再次使用，应标记为 unresolved 或 reopened；
- path argument 不可用时，输出 partial/unavailable，不编造路径。

### 6.6 验收标准

- [ ] 至少对 synthetic fixture 通过 fd/path flow recovery self-test。
- [ ] 对 `file_scan` 或 `batch_open_read_write` 生成 summary。
- [ ] case study 文档更新，说明 fd/path flow 是否 strong、partial 或 unavailable。
- [ ] 不把 fd/path flow 结果写成 real malware detection。

---

## 7. P4：实现 process tree explanation

### 7.1 目标

把 `process_chain` 从 syscall-shape evidence 提升为显式 parent-child 行为解释。

需要恢复或解释：

```text
clone/fork/vfork
child PID
exec boundary
wait/wait4/waitpid
parent-child relation
target sample ownership
```

### 7.2 推荐实现位置

优先扩展：

```text
tools/recover_behavior.py
src/rv_maltrace/
```

或新增：

```text
src/rv_maltrace/process_tree.py
tools/recover_process_tree.py
```

### 7.3 输出

推荐输出：

```text
process_tree_summary.json
process_tree_summary.md
```

JSON schema 建议：

```json
{
  "schema": "rvmt.process_tree.summary.v1",
  "sample": "process_chain",
  "status": "PASS_OR_PARTIAL_OR_UNAVAILABLE",
  "root_process": "...",
  "processes": [
    {
      "pid": 123,
      "ppid": 1,
      "exec": "...",
      "observed_events": ["clone", "execve", "wait4"],
      "confidence": "strong|medium|weak"
    }
  ],
  "edges": [
    {
      "parent_pid": 123,
      "child_pid": 124,
      "evidence": ["clone_return", "runtime_process_map"],
      "confidence": "strong|medium|weak"
    }
  ],
  "limitations": []
}
```

### 7.4 Self-test

```bash
uv run python tools/recover_process_tree.py --self-test
# 或扩展：
uv run python tools/recover_behavior.py --self-test
```

测试至少覆盖：

- parent clone 返回 child pid；
- child execve；
- parent wait4 child；
- 缺失 return value 时输出 partial，而不是强行闭合 parent-child；
- 多子进程顺序不稳定时仍可按 PID 建边。

### 7.5 验收标准

- [ ] `process_chain` case study 中 `Boundary closed` 或等价字段更新为 strong/partial/unavailable。
- [ ] 输出 process tree summary。
- [ ] 明确说明它是 synthetic process-chain explanation，不是真实 malware process-tree coverage。

---

## 8. P5：实现 function/source-line attribution

### 8.1 目标

把本地代码分析从：

```text
ELF section / symbol / syscall site / trap site
```

提升为：

```text
function-level 或 source-line-level attribution
```

这一步用于增强 local code analysis claim，但仍不能声称完整 semantic reconstruction。

### 8.2 推荐实现

扩展：

```text
tools/build_code_map.py
tools/join_trace_code_map.py
src/rv_maltrace/
```

可选引入：

```text
addr2line
llvm-addr2line
objdump
DWARF debug info
```

如果样本二进制没有 debug info，输出应标为：

```text
source-line attribution unavailable: binary has no DWARF debug info
```

### 8.3 code_map schema 扩展建议

新增字段：

```json
{
  "source_locations": [
    {
      "pc": "0x...",
      "function": "main",
      "file": "samples/.../file_scan.c",
      "line": 42,
      "confidence": "debug_info|symbol_only|unavailable"
    }
  ],
  "function_ranges": [
    {
      "function": "main",
      "start": "0x...",
      "end": "0x...",
      "source_file": "...",
      "confidence": "symbol_table|dwarf|fallback"
    }
  ]
}
```

### 8.4 join 输出扩展建议

```json
{
  "schema": "rvmt.trace_code_join.summary.v1",
  "source_attribution": {
    "available": true,
    "events_with_function": 0,
    "events_with_source_line": 0,
    "limitations": []
  }
}
```

### 8.5 Self-test

```bash
uv run python tools/build_code_map.py --self-test
uv run python tools/join_trace_code_map.py --self-test
```

测试至少覆盖：

- 有符号表但无 DWARF：function-level 可用，source-line unavailable；
- 有 DWARF：source file/line 可用；
- 无符号表：降级到 section/range；
- 地址不在 ELF range：标记 unresolved。

### 8.6 验收标准

- [ ] `build_code_map.py` 兼容旧 schema 或清楚 bump schema。
- [ ] `join_trace_code_map.py` 能显示 function/source attribution summary。
- [ ] case study 文档更新：source-line available / unavailable / partial。
- [ ] 不把 source-line attribution 写成完整代码理解。

---

## 9. P6：strong / weak / benign-overlap 分层

### 9.1 目标

防止把良性重叠行为写成 malware detection success。

尤其是：

```text
ls 与 file_scan 都可能触发 many_file_scan 形状
cp 与 self_copy_sim 可能有文件复制行为重叠
```

### 9.2 推荐实现

扩展：

```text
experiments/linux_behavior/behavior_audit_rules.json
tools/audit_behavior.py
docs/04-runtime-linux/linux_behavior_audit.md
```

为每个 rule hit 加上：

```text
strength: strong | weak | overlap | expected_benign_overlap
explanation: ...
claim_allowed: synthetic_behavior_audit_only
```

### 9.3 输出建议

```json
{
  "schema": "rvmt.behavior_audit.summary.v2",
  "rule_hits": [
    {
      "rule": "many_file_scan",
      "sample": "file_scan",
      "strength": "strong",
      "benign_overlap": true,
      "allowed_claim": "controlled synthetic file-discovery behavior evidence",
      "forbidden_claim": "real malware detection"
    }
  ]
}
```

### 9.4 验收标准

- [ ] `ls` 的 file scan overlap 被明确标为 benign overlap 或 expected overlap。
- [ ] `file_scan` 的 hit 被表述为 controlled synthetic behavior evidence。
- [ ] audit summary 不输出 real malware detection 成功表述。
- [ ] case studies 使用 strong/weak/overlap 语言。

---

## 10. P7：BRAM ring / 1024 records / CVA6 的定位

### 10.1 BRAM ring / 1024 records

可以作为工程增强继续推进，但不能作为当前 35T full synthetic matrix 的 blocker 或通过原因。

正确定位：

```text
engineering/resource-efficiency improvement
```

错误定位：

```text
35T full synthetic matrix passed because trace capacity was increased
```

### 10.2 CVA6

本阶段不启动 CVA6。如果后续要做 CVA6，应单独写新的 planning 文档，不能把 35T result card 改写成 CVA6 结果。

---

## 11. 推荐提交顺序

建议分成 4 个小提交，避免一次提交混在一起：

```text
1. Add committed 35T evidence snapshot
2. Add 35T application closure checker
3. Add fd/path flow recovery and tests
4. Add process tree / source attribution backlog updates or initial implementation
```

如果时间有限，优先完成 1 和 2。

---

## 12. Agent 完成后的最终回复格式

Agent 最终回复必须包含：

```text
修改文件列表
新增 evidence snapshot 文件列表
新增/更新脚本
运行命令与状态
未运行命令与原因
失败命令与原因
当前 claim level
下一步剩余 backlog
```

不能只说“已完成”。

---

## 13. 可直接交给 Agent 的提示词

将下面整段复制给 agent：

```text
你正在修改 GitHub 仓库 NayCheno/rv-maltrace。请只处理 35T / Artix-7 35T / LiteX / VexRiscv 当前阶段；不要开始 CVA6，不要声称真实 malware detection、真实 malware accuracy、mature detector 或 complete semantic reconstruction。

当前状态：仓库已经有 35T 应用闭环收口文档：
- docs/08-publication/rv_maltrace_35t_application_closure.md
- docs/08-publication/rv_maltrace_35t_application_case_studies.md

当前允许的 claim level 只有：
35T hardware-trace-assisted synthetic malware-like behavior audit prototype。

当前主证据必须保持：
- run_id: 35t-smallcap-r512-full-synthetic-matrix-20260521
- trace_records: 512
- trace_profile_policy: 35t_small_capacity
- samples: 13
- gate: 13/13 PASS
- full_matrix_ready: True

本次任务的优先级如下。

P0：提交轻量 evidence snapshot。
创建目录：
- docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/

优先加入这些文件；如果本地结果里不存在，就写 MISSING/TODO，不要伪造：
- README.md
- evidence_manifest.json
- run_config.json
- gate_report.json
- gate_report.md
- semantic_failure_triage.json
- semantic_failure_triage.md
- process_chain_capacity_debug.json
- process_chain_capacity_debug.md
- command_log.md
- sample_matrix_summary.json
- sample_matrix_summary.md
- case_study_artifact_index.json

从这些本地结果路径复制或生成轻量 summary：
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/run_config.json
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.json
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/gate_report.md
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.json
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/semantic_failure_triage.md
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.json
- results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521/aggregate/process_chain_capacity_debug.md

不要提交大 trace dump、bitstream、Vivado build、board build 或完整 results 目录。只提交轻量 summary / JSON / Markdown / manifest。

P1：新增 35T closure checker。
创建：
- tools/check_35t_application_closure.py

它必须能检查：
- closure 文档存在；
- case study 文档存在；
- evidence_manifest.json 存在；
- run_id、trace_records、trace_profile_policy、samples、gate、full_matrix_ready 与文档一致；
- case studies 覆盖 illegal_trap、process_chain、dynamic_executable_memory，以及 file_scan 或 batch_open_read_write；
- non-claims 存在：no CVA6 board claim、no real malware detection claim、no mature detector claim、no classifier accuracy claim、no complete semantic reconstruction claim；
- 禁止 claim 漂移：不能把当前结果写成 real malware detector、CVA6 validation、mature detector、complete semantic reconstruction 或 real malware accuracy。

脚本要求：
- 支持 --self-test；
- 支持 --repo-root .；
- 不依赖硬件、不依赖 Vivado、不依赖完整 results/；
- 只依赖 committed docs / evidence snapshot；
- 失败时退出非零码；
- 输出 application_closure_check.json 和 application_closure_check.md。

P2：把以下命令记录到 command_log.md；能运行就运行，不能运行就说明原因，不要伪造 PASS：
- uv run python tools/experiment_35t.py --stage self-test
- uv run python tools/check_35t_next_gate.py --self-test
- uv run python tools/triage_35t_semantic_failures.py --self-test
- uv run python tools/recover_behavior.py --self-test
- uv run python tools/audit_behavior.py --self-test
- uv run python tools/build_code_map.py --self-test
- uv run python tools/join_trace_code_map.py --self-test
- uv run python tools/check_35t_application_closure.py --self-test
- uv run python tools/check_35t_application_closure.py --repo-root .
- uv run python -m compileall tools src/rv_maltrace

P3：如果 P0/P1 完成后还有时间，开始 fd/path flow recovery。优先扩展 tools/recover_behavior.py 或新增 src/rv_maltrace/fd_path_flow.py。目标是恢复 openat(path) -> fd -> read/write/getdents64/close 和 execve(path) 关系。输出 fd_path_flow_summary.json / .md。若当前 trace 不含 syscall arguments 或 return value，必须输出 partial/unavailable，不要编造 path/fd。

P4：如果 P3 完成或已有基础，再做 process tree explanation。目标是为 process_chain 输出 clone/fork/exec/wait parent-child explanation，生成 process_tree_summary.json / .md。缺少 return value 或 PID 证据时输出 partial，不要强行闭合 parent-child。

P5：后续再做 function/source-line attribution。扩展 build_code_map.py 和 join_trace_code_map.py，支持 function-level 或 source-line-level attribution。无 DWARF 时明确写 unavailable，不要声称完整代码理解。

P6：后续增强 strong/weak/benign-overlap 分层。尤其要把 ls 与 file_scan 的 many_file_scan overlap 写清楚，不能把 benign overlap 写成 malware detection success。

完成后请给出：
1. 修改文件列表；
2. 新增 evidence snapshot 文件列表；
3. 新增/更新脚本；
4. 每条命令的 PASS / FAIL / NOT_RUN 状态；
5. 当前 claim level；
6. 仍未完成的 backlog；
7. 是否仍只限 35T，是否没有引入 CVA6 / real malware detector claim。
```

---

## 14. 最小可接受完成标准

如果 agent 时间有限，最低限度必须完成：

- [ ] `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/evidence_manifest.json`
- [ ] `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/README.md`
- [ ] `docs/07-evaluation-evidence/evidence/35t-smallcap-r512-full-synthetic-matrix-20260521/command_log.md`
- [ ] `tools/check_35t_application_closure.py --self-test`
- [ ] `tools/check_35t_application_closure.py --repo-root .`
- [ ] closure 文档更新为优先引用 committed evidence snapshot
- [ ] 最终回复中明确：35T synthetic prototype only；no real malware detector；no CVA6 claim

如果只能做一个方向，优先顺序是：

```text
evidence snapshot > closure checker > regression log > fd/path flow > process tree > source-line attribution
```
