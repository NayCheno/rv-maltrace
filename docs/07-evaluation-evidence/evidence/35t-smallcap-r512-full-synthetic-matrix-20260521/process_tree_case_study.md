# 35T Process Tree Case Study: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

Sample: `process_chain`
Source run: `35t-targeted-board-validation-20260522`

## Checks

- source_results_root_exists: PASS
- candidate_available: PASS
- selected_status_pass: PASS
- positive_child_pid_recovered: PASS
- child_execve_boundary_associated: PASS
- execve_path_string_recovered: PASS
- parent_wait_pid_associated: PASS
- parent_child_graph_output: PASS
- selected_from_board_side_channel: PASS

## Selected Candidate

- source_type: `syscall_side_channel`
- source: `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/process_chain/board/trace-on/rep_00/syscall_side_channel.json`
- rep: `rep_00`

## Graph

- `parent(pid=target_parent_unresolved) --clone--> child(pid=203)`
- `child(pid=203) --execve("/bin/true")--> image`
- `parent(pid=target_parent_unresolved) --waitid(203)--> child_exit`
- `parent(pid=target_parent_unresolved) --clone--> child(pid=204)`
- `child(pid=204) --execve("/bin/true")--> image`
- `parent(pid=target_parent_unresolved) --waitid(204)--> child_exit`

## Recovered Evidence

- positive clone child PIDs: [203, 204]
- wait PID candidates: [203, 204]
- edge count: 2
- exec paths:
  - pid=203, path=`/bin/true`, source=board_syscall_side_channel
  - pid=204, path=`/bin/true`, source=board_syscall_side_channel

## Interpretation

- process_chain has a targeted 35T board syscall side-channel candidate with clone return child PIDs, execve path evidence, wait PID evidence, and graph output
- parent PID remains intentionally unresolved because the current trace does not prove OS parent ownership with PID/SATP/ASID context
- this is synthetic process-chain behavior explanation evidence, not real malware process ownership or kernel-rootkit resistance evidence

## Failures

- none

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete OS process ownership claim
