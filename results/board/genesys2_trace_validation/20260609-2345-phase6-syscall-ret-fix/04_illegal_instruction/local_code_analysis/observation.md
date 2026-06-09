# illegal_instruction Local Code Analysis Observation

Status: LOCAL_CODE_MAP_GENERATED_PROCESS_NOT_PROVEN

## Requested Full ELF Map

- ELF: `build/board/genesys2_cva6_phase6_linux_user/illegal_instruction.riscv64`
- Code map: `local_code_analysis/code_map.json`
- Source attribution: `local_code_analysis/source_attribution.json`
- Source attribution summary: `local_code_analysis/source_attribution_summary.json`

## Actual Runtime Support Map

- ELF: `build/board/genesys2_cva6_phase6_linux_user_minimal/illegal_instruction.riscv64`
- Code map: `runtime_minimal_code_analysis/code_map.json`
- Source attribution summary: `runtime_minimal_code_analysis/source_attribution_summary.json`

## Behavior Recovery

- Report: `behavior/recovery_report.md`
- Semantic events: `behavior/semantic_events.json`
- Behavior graph: `behavior/behavior_graph.json`

## Attribution Boundary

- Trace events: 21
- Full ELF target-attributed events: 1
- Minimal runtime target-attributed events: 1
- Minimal runtime callsite kinds: `{"syscall_site": 1, "unknown": 20}`
- Process attribution: `not_proven`
- Runtime process map: `MISSING`
- Marker scope: `MISSING`
- Function/source-line attribution is unavailable in these code maps.

This local analysis is code/trace correlation evidence, not malware detection evidence.
