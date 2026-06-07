# 35T Sample Matrix Summary: 35t-smallcap-r512-full-synthetic-matrix-20260521

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

| Sample | Class | Profile | Gate | Expected rules | Matched expected | Benign overlap |
|---|---|---|---|---|---|---|
| hello | benign | p0a_syscall_drop | PASS | none | none | none |
| ls | benign | p0a_syscall_drop | PASS | none | none | many_file_scan |
| cat | benign | p0a_syscall_drop | PASS | none | none | none |
| cp | benign | p0a_syscall_drop | PASS | none | none | none |
| sha256sum | benign | p0a_syscall_drop | PASS | none | none | none |
| file_scan | malware_like_synthetic | p0a_syscall_drop | PASS | many_file_scan | many_file_scan | none |
| batch_open_read_write | malware_like_synthetic | p0a_syscall_drop | PASS | batch_file_read_write | batch_file_read_write | none |
| self_copy_sim | malware_like_synthetic | p0a_syscall_drop | PASS | self_copy_simulation | self_copy_simulation | none |
| abnormal_syscall_sequence | malware_like_synthetic | p0a_syscall_drop | PASS | abnormal_syscall_sequence | abnormal_syscall_sequence | none |
| illegal_trap | malware_like_synthetic | p0c_syscall_trap_drop | PASS | illegal_instruction_trap | illegal_instruction_trap | none |
| process_chain | malware_like_synthetic | p0a_syscall_drop | PASS | process_creation_chain | process_creation_chain | none |
| dynamic_executable_memory | malware_like_synthetic | p0a_syscall_drop | PASS | dynamic_executable_memory | dynamic_executable_memory | none |
| anti_debug_like | malware_like_synthetic | p0a_syscall_drop | PASS | anti_analysis_indicator | anti_analysis_indicator | none |

Non-claims: no CVA6 board claim; no real malware detection claim; no mature detector claim; no classifier accuracy claim; no complete semantic reconstruction claim.
