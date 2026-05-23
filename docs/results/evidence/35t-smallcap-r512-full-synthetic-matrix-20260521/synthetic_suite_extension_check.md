# 35T Synthetic Suite Extension Check: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: IMPLEMENTED_EXTENSION_SOURCES_READY_FOR_35T_GATING

Manifest: `experiments/linux_behavior/malware_like/manifest.json`

Extension plan: `experiments/linux_behavior/malware_like/extension_plan.json`

## Checks

- manifest_schema: PASS
- current_suite_exact_8: PASS
- current_suite_synthetic_only: PASS
- current_suite_non_destructive: PASS
- current_suite_network_free: PASS
- plan_schema: PASS
- plan_synthetic_only: PASS
- plan_default_disabled: PASS
- candidate_topics_complete: PASS
- candidate_count: PASS
- candidate_safety: PASS
- network_candidates_default_disabled: PASS
- network_policy_bounded: PASS
- real_malware_policies_listed: PASS
- real_malware_policies_deferred: PASS
- no_expanded_claims: PASS
- plan_status_implemented_source: PASS
- candidate_sources_declared: PASS
- candidate_sources_exist: PASS
- candidate_sources_under_extension_dir: PASS
- candidate_statuses_implemented: PASS
- candidate_commands_bound: PASS
- candidate_expected_syscalls_recorded: PASS
- candidate_expected_behaviors_recorded: PASS
- implementation_sources_non_destructive: PASS
- non_network_sources_network_free: PASS
- optional_network_sources_loopback_only: PASS

## Candidate Topics

- /proc/self/status TracerPid check
- direct-syscall
- file encryption simulation without destructive payload
- fork/exec chains
- mmap/mprotect executable memory variants
- network workloads
- packed code
- self-modifying code
- timing checks

## Implemented Source Files

- `experiments/linux_behavior/malware_like/extension_programs/direct_syscall_open_read.c`
- `experiments/linux_behavior/malware_like/extension_programs/file_encryption_sim_non_destructive.c`
- `experiments/linux_behavior/malware_like/extension_programs/loopback_network_client.c`
- `experiments/linux_behavior/malware_like/extension_programs/mprotect_exec_variant.c`
- `experiments/linux_behavior/malware_like/extension_programs/multi_level_process_chain.c`
- `experiments/linux_behavior/malware_like/extension_programs/obfuscated_syscall_wrapper.c`
- `experiments/linux_behavior/malware_like/extension_programs/proc_status_tracerpid_check.c`
- `experiments/linux_behavior/malware_like/extension_programs/self_modifying_code_sim.c`
- `experiments/linux_behavior/malware_like/extension_programs/timing_anti_analysis_loop.c`

## Optional Network Candidates

- loopback_network_client

## Real Malware Policy Gates

- artifact_sanitization: REQUIRED_BEFORE_SCOPE_EXPANSION
- containment_environment: REQUIRED_BEFORE_SCOPE_EXPANSION
- legal_ethical_policy: REQUIRED_BEFORE_SCOPE_EXPANSION
- network_isolation: REQUIRED_BEFORE_SCOPE_EXPANSION
- non_destructive_replay_mode: REQUIRED_BEFORE_SCOPE_EXPANSION
- sample_source_policy: REQUIRED_BEFORE_SCOPE_EXPANSION

## Interpretation

- current 35T claim remains limited to the existing 8 synthetic malware-like samples
- extension candidates are source-implemented, synthetic-only, non-destructive, and disabled by default when implementation checks pass
- implemented extension sources are not counted as expanded 35T coverage until they are explicitly selected and run through the same gates
- network behavior remains optional and disabled by default until a loopback fixture is explicitly provided
- real malware remains out of scope until source, legal, containment, replay, isolation, and sanitization policies are complete

## Failures

- none

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
