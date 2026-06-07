# 35T Trusted Helper Alignment: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: TRUSTED_HELPER_ALIGNMENT_PASS_REPRESENTATIVE_DUAL_CHANNEL

Semantic run: `35t-targeted-board-validation-20260522`

Route: `trusted_linux_kernel_syscall_side_channel_dual_channel`

## Checks

- board_smoke_schema: PASS
- board_smoke_status: PASS
- board_smoke_hardware_validated: PASS
- final_smoke_pass: PASS
- final_smoke_side_channel_files: PASS
- strict_follow_up_pass: PASS
- strict_fd_path_pass: PASS
- strict_process_tree_pass: PASS
- strict_source_attribution_partial_recorded: PASS
- bundle_schema: PASS
- bundle_status_pass: PASS
- bundle_checker_pass: PASS
- bundle_hardware_validated: PASS
- bundle_dual_channel: PASS
- bundle_trace_gate_run_id: PASS
- bundle_semantic_run_id: PASS
- bundle_fd_path_pass: PASS
- bundle_process_tree_pass: PASS
- bundle_source_attribution_partial: PASS
- fd_path_case_studies_pass: PASS
- process_tree_case_study_pass: PASS
- selected_sources_from_side_channel: PASS
- selected_sources_exist_and_have_events: PASS
- semantic_results_root_exists: PASS
- threat_model_schema: PASS
- threat_model_status: PASS
- trusted_kernel_boundary: PASS
- user_mode_scope: PASS
- kernel_rootkit_out_of_scope: PASS
- helper_route_recorded: PASS
- ebpf_route_recorded: PASS

## Selected Side-Channel Sources

- `batch_open_read_write`: `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/batch_open_read_write/board/trace-on/rep_00/syscall_side_channel.json` (24 events)
- `file_scan`: `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/syscall_side_channel.json` (8 events)
- `self_copy_sim`: `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/self_copy_sim/board/trace-on/rep_00/syscall_side_channel.json` (12 events)
- `process_chain`: `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/syscall_side_channel.json` (40 events)

## Current Condition

- representative fd/path and process-tree helper evidence is aligned with 35T hardware trace evidence through the targeted dual-channel board validation bundle

## Remaining Work

- hardware user-pointer memory snapshot remains deferred and default-disabled
- source-line attribution remains partial until DWARF or equivalent source-location evidence is added
- helper or eBPF evidence must remain a trusted-kernel companion rather than a hardware-only tracing claim

## No-Substitution Rules

- not a hardware user-pointer memory snapshot
- not hardware-only tracing evidence
- not complete semantic reconstruction
- not a QEMU-plugin or eBPF baseline substitute
- not a malicious-kernel or kernel-rootkit resistance claim

## Failures

- none
