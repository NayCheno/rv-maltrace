# illegal_trap Genesys2/CVA6 Safe Surrogate Observation

Status: PASS_SAFE_SURROGATE_EVIDENCE_CHAIN_WITH_LIMITATIONS

This sample is repository-authored `malware_like_synthetic`, not real malware. The executable used on the board is a syscall-only safe reimplementation of `experiments/linux_behavior/malware_like/programs/illegal_trap.c` so it remains small enough for UART transfer and exposes deterministic syscall/trap boundaries.

Evidence chain:

- Board execution: `hardware_trace/program.log` shows `synthetic SIGILL` and shell return.
- Hardware trace: `hardware_trace/trace.jsonl` includes `SYSCALL_ENTRY a7=0x40` at `0x000100f8` and `TRAP cause=0x2` in a separate ILA window.
- Local code analysis: `local_code_analysis/code_map.json` and `source_attribution.json` map one target code-site event to the ELF text range.
- Behavior analysis: `malware_analysis/behavior_mapping.json` maps the evidence to `illegal_instruction_trap` as safe synthetic/surrogate behavior.

Limitations:

- Captures are multi-window, not one continuous target invocation.
- Runtime process attribution is not proven without marker/PID/SATP/ASID evidence.
- The trap event PC is kernel/supervisor context; the adapter does not expose the target user faulting PC for that event.
- This is not real malware validation or malware detection evidence.
