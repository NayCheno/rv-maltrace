# 35T fd/path Case Studies: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: PASS

Source run: `35t-targeted-board-validation-20260522`

## Checks

- source_results_root_exists: PASS
- all_required_samples_present: PASS
- all_required_samples_pass: PASS
- all_have_closed_flows: PASS
- all_selected_from_board_side_channel: PASS
- all_keep_unresolved_fields_explicit: PASS

## Samples

| Sample | Status | PASS Candidates | Closed Flows | Selected Source |
| --- | --- | ---: | ---: | --- |
| `file_scan` | `PASS` | 5/10 | 1 | `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/file_scan/board/trace-on/rep_00/syscall_side_channel.json` |
| `batch_open_read_write` | `PASS` | 5/10 | 4 | `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/batch_open_read_write/board/trace-on/rep_00/syscall_side_channel.json` |
| `self_copy_sim` | `PASS` | 5/10 | 2 | `results/experiments/35t/35t-targeted-board-validation-20260522/samples/malware_like_synthetic/self_copy_sim/board/trace-on/rep_00/syscall_side_channel.json` |

## Flow Examples

### `file_scan`
- path=`experiments/linux_behavior/malware_like/fixtures/scan_root`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=getdents64, getdents64, close

### `batch_open_read_write`
- path=`experiments/linux_behavior/malware_like/fixtures/batch_input_0.txt`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=read, close
- path=`/tmp/rvmt_batch_output.txt`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=write, close
- path=`experiments/linux_behavior/malware_like/fixtures/batch_input_1.txt`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=read, close
- path=`/tmp/rvmt_batch_output.txt`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=write, close

### `self_copy_sim`
- path=`/usr/bin/self_copy_sim`, fd=3, status=closed, path_source=board_syscall_side_channel, ops=read, close
- path=`/tmp/rvmt_self_copy_sim.bin`, fd=4, status=closed, path_source=board_syscall_side_channel, ops=write, close

## Interpretation

- file_scan, batch_open_read_write, and self_copy_sim each have at least one board syscall side-channel candidate with closed fd/path flows
- path strings come from the targeted board syscall side-channel, not from raw hardware user-pointer snapshots
- canonical fd_path_flow_summary.json remains the selected compact file_scan explanation; this artifact records the broader P1 case-study coverage

## Failures

- none

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
