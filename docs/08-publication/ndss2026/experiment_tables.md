# NDSS Experiment Tables

## Evaluation Matrix

| RQ | Measurement | Current Evidence | Status | Checker |
| --- | --- | --- | --- | --- |
| RQ1 trace correctness | event schema, trap/retire separation, syscall entry/return pairing, same-cycle ordering, strict SRET return qualification | directed corpus plus RTL/static timing-principle gate | PASS_DIRECTED_FIXTURES | `uv run python tools/check_trace_correctness_directed.py --root .` |
| RQ2 semantic provenance | field source labels for hardware, exact ELF, runtime map, and oracle data | semantic provenance summary and local fixture package | PASS_LOCAL_CHECKER | `uv run python tools/check_genesys2_semantic_provenance.py --root .` |
| RQ3 code attribution | exact ELF, PIE/ASLR load bias, dynamic libraries, fork/exec, stripped ELF, sidecar boundary | local code-analysis fixtures | PASS_LOCAL_FIXTURES | `uv run python tools/check_genesys2_local_code_analysis_fixtures.py --root .` |
| RQ4 board semantics | board-native DWARF source lines and scoped full hardware pointer strings | accepted external summaries under `external_closure/` | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED | `uv run python tools/check_genesys2_external_closure_intake.py --root .` |
| RQ5 board benign controls | same-environment non-network benign false-positive controls | accepted Genesys2/CVA6 board benign-control summary | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED | `uv run python tools/check_genesys2_external_closure_intake.py --root .` |
| RQ6 software tracer visibility | native/no-tracer, native/strace, qemu-user, and qemu-user-strace visibility/oracle comparison | Docker software baseline | PASS_LOCAL_SOFTWARE_TRACER_BASELINE | `uv run python tools/check_genesys2_tracer_visibility_baseline.py --root .` |
| RQ7 board cycle overhead | cycle-source availability for trace-on/off overhead | live board probes plus Linux counter-path preflight | BLOCKED_SD_CARD_LINUX_SOURCE_MISSING | `uv run python tools/check_genesys2_linux_counter_path_preflight.py --root .` |
| RQ8 non-SD kernel update | JTAG RAM-write/hart-control feasibility | read-only Vivado Hardware Manager probe | BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL | `uv run python tools/check_genesys2_jtag_ram_boot_probe.py --root .` |
| RQ9 production transport | non-BRAM streaming/DMA throughput and noninterference | readiness summary and external template only | BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED | `uv run python tools/check_genesys2_external_closure_intake.py --root .` |

## Baselines

| Baseline | Role | Status | Boundary |
| --- | --- | --- | --- |
| Host native | runtime reference | PASS_LOCAL_SUMMARY | Not hardware trace evidence |
| Host strace | syscall oracle and perturbation comparison | PASS_LOCAL_SUMMARY | Oracle only |
| QEMU user strace | RISC-V syscall oracle | PASS_LOCAL_SUMMARY | Oracle only |
| Safe tracer visibility probe | anti-analysis visibility baseline | PASS_LOCAL_SOFTWARE_TRACER_BASELINE | Docker software-only; no board/hardware invisibility claim |
| eBPF | optional Linux baseline | OPTIONAL_DEFERRED_EBPF | Not required for current PASS |
| Event-only hardware | ablation | PASS_CURRENT_LOCAL | No pointer semantics |
| Bounded ARG_MEM hardware | ablation | PASS_CURRENT_LOCAL | Prefix-only ablation; full strings are only the accepted scoped hardware summary |
| Scoped full hardware strings | semantic enrichment | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED | Limited to accepted groups; no full dump or companion substitution |
| Board benign control | false-positive control | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED | Limited to accepted board benign summary |
| Board cycle source | overhead baseline | BLOCKED_SD_CARD_LINUX_SOURCE_MISSING | Needs rebuilt SD image boot plus board `--require-pass` cycle-source probes |
| JTAG RAM boot | remote kernel-update feasibility | BLOCKED_JTAG_RAM_BOOT_NO_MEMORY_CONTROL | Needs a future memory-control/hart-control bitstream before RAM-load experiments |
| Production streaming/DMA | transport baseline | BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED | Requires the eight artifact kinds named in the external template |

## Ablations

| Ablation | Expected Question | Status |
| --- | --- | --- |
| Trace off vs event only | runtime perturbation of basic trace | PASS_CURRENT_LOCAL |
| Trace off vs trace on with board cycle source | cycle-level overhead on Genesys2/CVA6 | BLOCKED_SD_CARD_LINUX_SOURCE_MISSING |
| Event only vs bounded ARG_MEM | semantic gain from pointer prefixes | PASS_CURRENT_LOCAL |
| Bounded prefix vs accepted full strings | semantic gain from full hardware pointer groups | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED |
| BRAM ring vs production streaming/DMA | transport capacity and noninterference | BLOCKED_EXTERNAL_ARTIFACTS_REQUIRED |
| No runtime map vs runtime map | fork/exec and dynamic-object attribution | PASS_LOCAL_FIXTURES |
| No tracer vs strace vs qemu-user-strace | software tracer visibility and oracle boundary | PASS_LOCAL_SOFTWARE_TRACER_BASELINE |
| Sidecar source map vs board-native DWARF | source-line provenance boundary | EXTERNAL_SUMMARY_ACCEPTED_SCOPE_LIMITED / SIDECAR_NONCLAIM |
