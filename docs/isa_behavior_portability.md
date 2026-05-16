# ISA Behavior Portability

Phase 10.1 records how RV-MalTrace treats x86-to-RISC-V malware differences.
This is a motivation and experiment-rubric artifact, not malware detection
quality evidence and not an x86 instruction translation plan.

The portability specification is:

```text
experiments/analysis/isa_behavior_portability.json
```

## Principle

Instruction-level malware signatures are architecture-dependent. RV-MalTrace
therefore captures RISC-V-specific committed events and recovers
architecture-neutral behavior semantics: syscall activity, control-flow edges,
privilege boundaries, anti-analysis indicators, dynamic-code behavior, and the
behavior graph.

## Mapping Rubric

| Order | Mapping | x86 signal | RISC-V signal | Normalized behavior | Status |
| ---: | --- | --- | --- | --- | --- |
| 1 | syscall_abi | `syscall` plus x86-64 register convention | `ecall` plus `a7`/`a0-a5`/`a0` convention | syscall name, arguments, return value, fd/path/process relationship | TODO(EXPERIMENT) |
| 2 | control_flow | `call`, `jmp`, `ret`, conditional branch | `jal`, `jalr`, branch | control-flow edge with kind, pc, target, taken state | TODO(EXPERIMENT) |
| 3 | privilege_transition | user/kernel ring transition | U/S/M transition plus trap and `sret` context | privilege boundary and trap/context transition | TODO(EXPERIMENT) |
| 4 | anti_analysis | `ptrace`, proc, timing behavior | RISC-V syscall ABI for `ptrace`, proc, timing behavior | anti-analysis indicator in semantic events and behavior graph | TODO(EXPERIMENT) |
| 5 | dynamic_code | `mmap`/`mprotect` plus executable mapping transfer | `mmap`/`mprotect` plus `jalr`/branch when available | memory permission transition and executable mapping relationship | TODO(EXPERIMENT) |

The comparison unit is behavior semantics, not raw opcodes. This artifact must
not be used to claim real malware corpus coverage, malware detection quality, or
successful cross-ISA binary translation.

## Validation Command

```powershell
uv run python tools/check_isa_behavior_portability.py
uv run python tools/check_isa_behavior_portability.py --self-test
```
