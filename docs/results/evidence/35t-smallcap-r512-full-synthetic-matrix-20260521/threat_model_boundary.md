# 35T Threat Model Boundary: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: TRUSTED_KERNEL_USER_MODE_THREAT_MODEL_BOUNDARY_SPECIFIED

Spec: `experiments/linux_behavior/semantic_threat_model.json`
Document: `docs/research/semantic/semantic_threat_model.md`

## Checks

- spec_schema: PASS
- spec_status: PASS
- claim_level: PASS
- trusted_components: PASS
- user_mode_attacker_in_scope: PASS
- kernel_rootkit_out_of_scope: PASS
- routes_have_expected_status: PASS
- helper_and_ebpf_are_optional_companions: PASS
- required_wording_in_spec: PASS
- required_wording_in_doc: PASS
- non_claims_present: PASS
- no_forbidden_positive_claims: PASS

## In Scope

- user_mode_file_process_memory_mapping_behavior
- user_mode_malware_like_workload
- user_mode_ptrace_or_tracerpid_checks
- user_mode_syscall_behavior
- user_mode_timing_checks

## Out Of Scope

- compromised_board_runner
- compromised_ebpf_program
- firmware_or_bitstream_tampering
- kernel_rootkit
- malicious_kernel
- malicious_kernel_module
- real_malware_detection_accuracy

## Routes

| Route | Status | Trust Dependency | Boundary |
| --- | --- | --- | --- |
| `ebpf_metadata_alignment` | `OPTIONAL_DEFERRED_COMPANION` | trusted_linux_kernel_and_ebpf_runtime | comparison or enrichment only; not an MVP dependency and not a replacement for RTL trace evidence |
| `event_only_hardware_trace` | `CURRENT_35T_CLAIM` | hardware_trace_tap | authoritative for committed event, syscall, return, trap, marker, drop, and capacity evidence in the bounded 35T prototype |
| `kernel_helper_metadata` | `OPTIONAL_DEFERRED_COMPANION` | trusted_linux_kernel_and_helper | metadata companion only; cannot be used to claim resistance to a malicious kernel or kernel rootkit |
| `selective_memory_snapshot` | `DEFERRED` | hardware_trace_tap_and_gated_memory_capture | must remain default-disabled until timing, bandwidth, noninterference, and pointer-safety evidence exists |

## Interpretation

- current 35T semantic evidence assumes a trusted kernel and user-mode malware-like workload
- kernel helper and eBPF routes are optional deferred companions and cannot support malicious-kernel or kernel-rootkit resistance claims
- hardware event-only trace remains the current authoritative 35T claim while pointer snapshot/helper/eBPF enrichment is deferred

## Failures

- none

## Non-claims

- no kernel rootkit resistance claim
- no malicious kernel resistance claim
- no eBPF tamper resistance claim
- no real malware detection claim
- no complete pointer semantic reconstruction claim
- no helper or eBPF MVP dependency claim
