# 35T Extension Evidence Snapshot: 35t-extension-r512-nonnetwork-20260523

Status: PASS

This snapshot records the network-free synthetic extension 35T gate separately from the primary 13-sample gate.

## Expected Samples

- `direct_syscall_open_read`
- `file_encryption_sim_non_destructive`
- `mprotect_exec_variant`
- `multi_level_process_chain`
- `obfuscated_syscall_wrapper`
- `proc_status_tracerpid_check`
- `self_modifying_code_sim`
- `timing_anti_analysis_loop`

## Excluded

- `loopback_network_client` remains excluded by default.

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
- extension gate is reported separately from the primary 13-sample gate
