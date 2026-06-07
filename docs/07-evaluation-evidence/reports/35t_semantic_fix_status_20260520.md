# 35T p0c Semantic Fix Status (2026-05-20)

Scope: existing p0c 512 ABBA artifacts only. No full matrix was run. No board
microbench was run because the offline promotion checks did not all pass.

Boundary: this is a 35T/LiteX/VexRiscv synthetic malware-like behavior audit
prototype result. It is not a CVA6 board result, not real malware detection, and
not a mature detector claim.

## Input Artifact

- Run ID: `35t-p0c-abba-r512-20260520-com5`
- Root: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5`
- Profile: `p0c_syscall_trap_drop`
- Records: `512`
- Runtime order: `abba`
- Reps: `10`
- Samples: `hello`, `batch_open_read_write`, `illegal_trap`, `anti_debug_like`

## Implemented Offline Changes

- Raw trace decoder now preserves `record_index`, `evt_code`, `raw_header`,
  `raw_words`, and `parser_warnings`.
- Unknown event codes decode as `UNKNOWN` instead of being folded into `DROP`.
- Corrupt raw records are surfaced as `UNKNOWN` with parser warnings; the UART
  parser now repairs timestamp-split record-index/first-word joins.
- `tools/build_code_map.py` generates target ELF code maps from existing
  `.riscv` artifacts without requiring host objdump/readelf.
- `tools/join_trace_code_map.py` annotates trace events with target/code-map
  attribution.
- `tools/recover_behavior.py` carries code attribution and parser warning
  summaries into semantic artifacts.
- `illegal_instruction_trap` audit matching now requires strong target
  illegal-instruction code-site evidence; weak trap/write evidence is reported
  but does not count as matched expected behavior.
- `batch_file_read_write` can report weak `batch_file_read_write_shape`
  evidence when full fd-flow/path semantics are not recoverable.
- `tools/check_35t_next_gate.py` now reports per-rep rule matrices, rule
  stability, weak-rule stability, and UNKNOWN/corrupt counts.
- `tools/triage_35t_semantic_failures.py` writes semantic failure triage
  artifacts for the four p0c focus samples.

## Commands And Return Codes

| Command | RC | Notes |
| --- | ---: | --- |
| `uv run python -m compileall src\rv_maltrace tools` | 0 | Syntax check after implementation. |
| `uv run python tools/build_code_map.py --self-test` | 0 | Code-map self-test passed. |
| `uv run python tools/join_trace_code_map.py --self-test` | 0 | Trace/code-map join self-test passed. |
| `uv run python tools/triage_35t_semantic_failures.py --self-test` | 0 | Triage self-test passed. |
| `uv run python tools/recover_behavior.py --self-test` | 0 | Behavior recovery self-test passed. |
| `uv run python tools/audit_behavior.py --self-test` | 0 | Audit self-test passed with tightened illegal-trap fixture. |
| `uv run python tools/analyze_trace_lightweight.py --self-test` | 0 | Lightweight analysis self-test passed. |
| `uv run python tools/check_35t_next_gate.py --self-test` | 0 | Gate self-test passed. |
| `uv run python tools/check_artix7_raw_trace.py` | 0 | Raw trace converter self-test passed. |
| `uv run python tools/experiment_35t.py --stage self-test` | 0 | 35T experiment script self-test passed. |
| `uv run python tools/experiment_35t.py --stage analyze --run-id 35t-p0c-abba-r512-20260520-com5 --port COM5 --baud 921600 --reps 10 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | Re-decoded existing raw UART logs, regenerated code-map join, recovery, audit, lightweight, and alignment artifacts. |
| `uv run python tools/experiment_35t.py --stage report --run-id 35t-p0c-abba-r512-20260520-com5 --port COM5 --baud 921600 --reps 10 --trace-records 512 --trace-profile p0c_syscall_trap_drop --runtime-order abba --warmup 1 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | Rewrote aggregate metrics/reports. |
| `uv run python tools/check_35t_next_gate.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | Rewrote strict gate report. |
| `uv run python tools/triage_35t_semantic_failures.py --run-id 35t-p0c-abba-r512-20260520-com5 --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | 0 | Wrote triage report; marked board promotion blocked. |
| `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10` | 1 | Initial checker rejected new gate schema `rvmt.35t.next_gate.v2`; checker was updated to accept v1/v2. |
| `uv run python tools/check_35t_experiment_bundle.py --self-test` | 0 | Bundle checker self-test passed after schema compatibility update. |
| `uv run python tools/check_35t_experiment_bundle.py --run-id 35t-p0c-abba-r512-20260520-com5 --reps 10` | 0 | Existing p0c bundle is complete after report regeneration. |
| `uv run rvmt exp:35t --stage all --run-id 35t-p0c-r512-semantic-fix-20260520 --port COM5 --baud 921600 --reps 5 --trace-records 512 --trace-profile p0c_syscall_trap_drop --sample hello --sample batch_open_read_write --sample illegal_trap --sample anti_debug_like` | N/A | Not run. Blocked by offline promotion checks. |

## Recomputed Gate Summary

| Sample | Gate | Missing expected | Stable matched expected | Weak expected | Unexpected matched | UNKNOWN/corrupt | Drop rate median | Ordered LCS ratio median |
| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: |
| `hello` | PASS | none | none | none | none | 0/0 | 0.023633729556125742 | 0.38461538461538464 |
| `batch_open_read_write` | FAIL | `batch_file_read_write` | none | `batch_file_read_write` | none | 0/0 | 0.018593117266095693 | 0.2916666666666667 |
| `illegal_trap` | FAIL | `illegal_instruction_trap` | none | none | none | 0/0 | 0.02406020478309635 | 0.35714285714285715 |
| `anti_debug_like` | PASS | none | `anti_analysis_indicator` | none | none | 0/0 | 0.01881720430107527 | 0.3888888888888889 |

Promotion checks:

- `hello_no_illegal_instruction_trap_false_positive`: true
- `batch_open_read_write_at_least_weak`: true
- `unknown_and_corrupt_events_zero`: true
- `illegal_trap_stable_expected_rule`: false
- `ready_for_35t_microbench`: false

## Blocked Reason

35T COM5/921600 p0c r512 four-sample microbench is blocked because
`illegal_trap` does not stably match the expected `illegal_instruction_trap`
rule under the tightened code-evidence requirement.

The generated code map identifies the illegal instruction site at
`illegal_trap.riscv` PC `0x00000000000104c4`, symbol `main+0x30`, but the
existing p0c trace reps do not contain a TRAP event at that exact
`illegal_instruction_site`. Observed trap records remain attributable to
kernel or non-site target text, so counting them as expected behavior would
reintroduce the false-positive class that previously affected `hello`.

## Artifact Paths

- Gate JSON: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/gate_report.json`
- Gate Markdown: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/gate_report.md`
- Triage JSON: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/semantic_failure_triage.json`
- Triage Markdown: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/semantic_failure_triage.md`
- Metrics JSON: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/metrics.json`
- Metrics CSV: `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/aggregate/metrics.csv`
- Code maps:
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/benign/hello/build/hello.code_map.json`
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/batch_open_read_write/build/batch_open_read_write.code_map.json`
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/illegal_trap/build/illegal_trap.code_map.json`
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/malware_like_synthetic/anti_debug_like/build/anti_debug_like.code_map.json`
- Per-rep trace/code-map join artifacts:
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/<class>/<sample>/board/trace-on/rep_XX/trace_code_map/trace.code_map.jsonl`
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/<class>/<sample>/board/trace-on/rep_XX/trace_code_map/trace_code_map_summary.json`
- Per-rep parser warnings:
  - `results/experiments/35t/35t-p0c-abba-r512-20260520-com5/samples/<class>/<sample>/board/trace-on/rep_XX/parser_warnings.json`

## Next Required Fix Before Board Revalidation

Add target-scoped trap evidence for `illegal_trap`: either emit target boundary
markers or add OS/process/context attribution sufficient to prove that the
illegal instruction trap PC corresponds to the target sample's
`illegal_instruction_site`, then rerun the same offline analyze/report/gate
sequence. Only after `illegal_trap_stable_expected_rule` becomes true should
the COM5/921600 microbench be run.
