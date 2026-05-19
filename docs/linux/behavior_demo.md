# Behavior Demo Evidence Bundle

The behavior demo turns an RV-MalTrace JSONL trace into a small audit bundle
for repository-authored malware-like synthetic samples. It is a presentation and
review aid for the simulation MVP. It is not malware detection quality
evidence, Linux-on-board evidence, or physical hardware validation.

## Commands

Default fixture demo:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture
```

Smoke output under `build/`:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend fixture --run-id smoke --out-dir build/demo_behavior_smoke
```

User-provided trace:

```powershell
uv run rvmt demo:behavior --sample anti_debug_like --backend trace --trace results/vivado_sim/<case>/trace.jsonl
```

Ground truth with the isolated Linux behavior Docker service:

```powershell
uv run rvmt demo:groundtruth --sample anti_debug_like
uv run rvmt demo:groundtruth --sample file_scan --run-id smoke --out-dir build/demo_behavior_smoke
```

Checker:

```powershell
uv run python tools/render_behavior_demo.py --self-test
uv run python tools/check_behavior_demo.py
uv run python tools/check_behavior_demo.py --self-test
```

Related full-SoC simulation gate:

```powershell
uv run rvmt sim:cva6-full-soc-tohost
```

This gate validates a normal full-SoC tohost/MMIO completion path in
repository-local Vivado simulation. It is separate from the synthetic behavior
demo and does not upgrade demo artifacts into board, Linux, or malware
detection evidence.

## Output Layout

The default root is:

```text
results/demo/<run-id>/<sample-id>/
```

The demo bundle contains:

```text
00_build/
  source.sha256
  host_elf.sha256
  riscv64_elf.sha256
  compiler.txt
01_ground_truth/
  host.strace.log
  qemu-riscv64.strace.log
  exit-codes.txt
02_trace/
  trace.jsonl
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

`demo:behavior` writes `02_trace/`, `03_semantic/`, `04_audit/`, and
`05_visual/`. `demo:groundtruth` writes `00_build/` and `01_ground_truth/`.

## Backends

`--backend fixture` copies a checked-in synthetic RV-MalTrace JSONL fixture from
`sim/golden/demo_behavior/<sample-id>.trace.jsonl`. This is deterministic and
does not require Vivado, Linux-on-CVA6, or a board.

`--backend trace --trace <path>` copies a user-provided trace into the same
bundle layout. Use this when a real simulation, Linux workload, or board trace
exists. The backend does not upgrade the evidence claim by itself.

`demo:groundtruth` uses Docker service `linux-behavior`. It builds and runs the
ordinary Linux C sample under host `strace` and `qemu-riscv64 -strace`. These
transcripts are behavior ground truth candidates, not RV-MalTrace circuit trace.

## Supported Samples

The first demo fixtures cover:

| Sample | Expected rule |
| --- | --- |
| `anti_debug_like` | `anti_analysis_indicator` |
| `file_scan` | `many_file_scan` |
| `dynamic_executable_memory` | `dynamic_executable_memory` |
| `illegal_trap` | `illegal_instruction_trap` |

## Non-Claim Policy

The scorecard must say:

```text
Matched malware-like behavior rule: <rule>
```

It must not say `malware detected: yes`. This demo is synthetic behavior audit
evidence, not malware detection quality evidence.
