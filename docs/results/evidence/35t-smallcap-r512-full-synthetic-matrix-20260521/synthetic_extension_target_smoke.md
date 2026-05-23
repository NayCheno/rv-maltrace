# 35T Synthetic Extension Target Smoke: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: TARGET_COMPILE_SMOKE_PASS_35T_GATING_DEFERRED

Extension plan: `experiments/linux_behavior/malware_like/extension_plan.json`

## Target

- environment: docker_linux_behavior
- compiler: /usr/bin/riscv64-linux-gnu-gcc
- compiler_version: riscv64-linux-gnu-gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
- readelf: /usr/bin/riscv64-linux-gnu-readelf
- link_mode: static
- execution_attempted: False

## Checks

- plan_schema: PASS
- candidates_declared: PASS
- candidate_statuses_implemented: PASS
- candidate_sources_declared: PASS
- candidate_sources_exist: PASS
- container_command_passed: PASS
- container_json_present: PASS
- target_compiler_available: PASS
- target_readelf_available: PASS
- compile_result_count_matches: PASS
- compiled_all_candidates: PASS
- riscv_elf_all_candidates: PASS
- static_link_requested_all_candidates: PASS
- no_execution_attempted: PASS
- no_35t_gating_claim: PASS

## Compile Results

- `direct_syscall_open_read`: PASS bytes=556072 machine=RISC-V sha256=508f94aa988bc1e426c9e42b4df37578ad9c6eb246cfffcf6e576ff7a029c715
- `timing_anti_analysis_loop`: PASS bytes=556072 machine=RISC-V sha256=e3f9421e4dcc9bb0ae57a60460ff85e9fbe5f15fe248fa38de46ff1db2c02c29
- `proc_status_tracerpid_check`: PASS bytes=556112 machine=RISC-V sha256=5d5d079aa9bb6381ca75892e5ce19333102795696c4da6151f31c2a6761f0146
- `obfuscated_syscall_wrapper`: PASS bytes=556080 machine=RISC-V sha256=8d7e3e42c687975572b0cea0f3ca31a7a9135d1d7728728b81c8ce13c4c3b10a
- `self_modifying_code_sim`: PASS bytes=556072 machine=RISC-V sha256=bfc93b52c4e5fd83d53a4538772b7d422d6a428361a398a707c245bc057fa072
- `mprotect_exec_variant`: PASS bytes=556072 machine=RISC-V sha256=49e10354a6470864de2a316e9b29c17d2adae4d83add6d9a3ae06c9222e49f2d
- `multi_level_process_chain`: PASS bytes=556136 machine=RISC-V sha256=20945ed099f8750ec60a93d9c86d7e687d5d4ba10cbe31ec592bb67c23a58a95
- `loopback_network_client`: PASS bytes=556072 machine=RISC-V sha256=17ce92c32f368f75daded33aea79faa4416b934f1715a279158a3525591bb0df
- `file_encryption_sim_non_destructive`: PASS bytes=556088 machine=RISC-V sha256=f7fee07ef99129863bd7d8fc1dba78c5ed7ed734ca62ec3061fa51d98b70e6b5

## Interpretation

- this is a target cross-compile-only smoke check for repository-owned synthetic extension sources
- the checker builds static RISC-V Linux ELF candidates in Docker and validates ELF machine headers
- the checker never executes target binaries and does not install them into a 35T rootfs
- a PASS reduces the target-build gap but is still not a 35T run or expanded coverage claim
- expanded 35T coverage remains deferred until these candidates are explicitly enabled, deployed, and run through the same gates

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- no expanded 35T coverage claim
- no 35T execution or gate pass claim
