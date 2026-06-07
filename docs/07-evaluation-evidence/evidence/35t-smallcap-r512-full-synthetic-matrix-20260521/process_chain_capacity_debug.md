# Process Chain Capacity Debug

- Run ID: `35t-smallcap-r512-full-synthetic-matrix-20260521`
- Artifact root: `results/experiments/35t/35t-smallcap-r512-full-synthetic-matrix-20260521`

| Rep | Events | DROP | DROP rate | Cap | SYSCALL_ENTRY | SYSCALL_RET | TRAP | Dominant TRAP source | Strong | Weak | Boundary closed |
| --- | ---: | ---: | ---: | --- | ---: | ---: | ---: | --- | --- | --- | --- |
| `rep_00` | 154 | 0 | 0.000000 | False | 76 | 76 | 0 | none | True | False | False |
| `rep_01` | 154 | 0 | 0.000000 | False | 76 | 76 | 0 | none | True | False | False |
| `rep_02` | 154 | 0 | 0.000000 | False | 76 | 76 | 0 | none | True | False | False |
| `rep_03` | 154 | 0 | 0.000000 | False | 76 | 76 | 0 | none | True | False | False |
| `rep_04` | 154 | 0 | 0.000000 | False | 76 | 76 | 0 | none | True | False | False |

## Boundary Evidence

### `rep_00`

- Clone parent return candidates: `[]`
- Wait pid args: `[2635873000, 463, 464, 2635873000]`
- Overlap: `[]`
- Reason: missing positive parent-side clone return candidate

| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |
| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |
| 3 | `waitid` | 95 | 0x00000000000001ce | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |
| 4 | `execve` | 221 | 0x0000000000000000 | 0x000000009d1c3a58 | 0x00000000010aafb0 | 0x0000000000000000 | return_only_register_snapshot | kernel |
| 21 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | 0x0000000000000000 | paired_target_ecall_return | target_sample |
| 23 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001cf | 0x000000009d353c8c | None | target_ecall_boundary | target_sample |
| 24 | `execve` | 221 | 0x0000000000065904 | 0x000000009d353c8c | 0x000000009d353ddc | None | target_ecall_boundary | target_sample |
| 73 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 75 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001d0 | 0x000000009d353c8c | None | target_ecall_boundary | target_sample |
| 77 | `execve` | 221 | 0x0000000000065904 | 0x000000009d353c8c | 0x000000009d353ddc | None | target_ecall_boundary | target_sample |
| 127 | `waitid` | 95 | 0x0000000000000001 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |

- Raw clone-parent-like values: `[]`
- Raw wait-pid-like values: `[463, 464]`
- Raw overlap: `[]`
- Raw hint note: raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership

| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 7 | 7 | `SYSCALL_ENTRY` | 0x0000084c | 0x9d353d2c | 0x00000000 | 0x00000002 | pid_like_register_snapshot |
| 19 | 19 | `SYSCALL_ENTRY` | 0x00094698 | 0x0000002f | 0x62cad2d1 | 0x00000116 | pid_like_register_snapshot |
| 27 | 27 | `SYSCALL_ENTRY` | 0x0008e000 | 0x00003000 | 0x0008edc4 | 0x00095d20 | pid_like_register_snapshot |
| 29 | 29 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x00000010 | pid_like_register_snapshot |
| 31 | 31 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001cf | 0x00000004 | 0x9d353c8c | waitid_pid_arg_like |
| 33 | 33 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d353c8c | 0x00000000 | 0x000000dc | a7_clone |
| 89 | 89 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x0000005f | a7_waitid |
| 91 | 91 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001d0 | 0x00000004 | 0x9d353c8c | waitid_pid_arg_like |
| 93 | 93 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d353c8c | 0x00000000 | 0x000000dc | a7_clone |

### `rep_01`

- Clone parent return candidates: `[221]`
- Wait pid args: `[2635873000, 466, 467, 2635873000]`
- Overlap: `[]`
- Reason: no clone parent return candidate appears in wait pid args

| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |
| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |
| 3 | `waitid` | 95 | 0x00000000000001d1 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |
| 4 | `execve` | 221 | 0x0000000000000000 | 0x000000009d1c3a58 | 0x00000000010aafb0 | 0x0000000000000000 | return_only_register_snapshot | kernel |
| 21 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 23 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001d2 | 0x000000009d139c8c | None | target_ecall_boundary | target_sample |
| 25 | `execve` | 221 | 0x0000000000065904 | 0x000000009d139c8c | 0x000000009d139ddc | None | target_ecall_boundary | target_sample |
| 73 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | 0x00000000000000dd | paired_target_ecall_return | target_sample |
| 75 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001d3 | 0x000000009d139c8c | None | target_ecall_boundary | target_sample |
| 76 | `execve` | 221 | 0x0000000000065904 | 0x000000009d139c8c | 0x000000009d139ddc | None | target_ecall_boundary | target_sample |
| 127 | `waitid` | 95 | 0x0000000000000001 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |

- Raw clone-parent-like values: `[]`
- Raw wait-pid-like values: `[466, 467]`
- Raw overlap: `[]`
- Raw hint note: raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership

| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 7 | 7 | `SYSCALL_ENTRY` | 0x0000084c | 0x9d139d2c | 0x00000000 | 0x00000002 | pid_like_register_snapshot |
| 19 | 19 | `SYSCALL_ENTRY` | 0x00094698 | 0x0000002f | 0x62ec72d1 | 0x00000116 | pid_like_register_snapshot |
| 27 | 27 | `SYSCALL_ENTRY` | 0x0008e000 | 0x00003000 | 0x0008edc4 | 0x00095d20 | pid_like_register_snapshot |
| 29 | 29 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x00000010 | pid_like_register_snapshot |
| 31 | 31 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001d2 | 0x00000004 | 0x9d139c8c | waitid_pid_arg_like |
| 33 | 33 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d139c8c | 0x00000000 | 0x000000dc | a7_clone |
| 89 | 89 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x0000005f | a7_waitid |
| 91 | 91 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001d3 | 0x00000004 | 0x9d139c8c | waitid_pid_arg_like |
| 93 | 93 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d139c8c | 0x00000000 | 0x000000dc | a7_clone |

### `rep_02`

- Clone parent return candidates: `[]`
- Wait pid args: `[2635873000, 475, 476, 2635873000]`
- Overlap: `[]`
- Reason: missing positive parent-side clone return candidate

| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |
| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |
| 3 | `waitid` | 95 | 0x00000000000001da | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |
| 4 | `execve` | 221 | 0x0000000000000000 | 0x000000009d1c3a58 | 0x00000000010aafb0 | 0x0000000000000000 | return_only_register_snapshot | kernel |
| 22 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 24 | `execve` | 221 | 0x0000000000065904 | 0x000000009d736c8c | 0x000000009d736ddc | None | target_ecall_boundary | target_sample |
| 26 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001db | 0x000000009d736c8c | None | target_ecall_boundary | target_sample |
| 74 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | 0x0000000000000000 | paired_target_ecall_return | target_sample |
| 76 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001dc | 0x000000009d736c8c | None | target_ecall_boundary | target_sample |
| 77 | `execve` | 221 | 0x0000000000065904 | 0x000000009d736c8c | 0x000000009d736ddc | None | target_ecall_boundary | target_sample |
| 126 | `waitid` | 95 | 0x0000000000000001 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |

- Raw clone-parent-like values: `[]`
- Raw wait-pid-like values: `[475, 476]`
- Raw overlap: `[]`
- Raw hint note: raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership

| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 7 | 7 | `SYSCALL_ENTRY` | 0x0000084c | 0x9d736d2c | 0x00000000 | 0x00000002 | pid_like_register_snapshot |
| 19 | 19 | `SYSCALL_ENTRY` | 0x00094698 | 0x0000002f | 0x628ca2d1 | 0x00000116 | pid_like_register_snapshot |
| 27 | 27 | `SYSCALL_ENTRY` | 0x0008e000 | 0x00003000 | 0x0008edc4 | 0x00095d20 | pid_like_register_snapshot |
| 29 | 29 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x00000010 | pid_like_register_snapshot |
| 31 | 31 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d736c8c | 0x00000000 | 0x000000dc | a7_clone |
| 33 | 33 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001db | 0x00000004 | 0x9d736c8c | waitid_pid_arg_like |
| 89 | 89 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x0000005f | a7_waitid |
| 91 | 91 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001dc | 0x00000004 | 0x9d736c8c | waitid_pid_arg_like |
| 93 | 93 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d736c8c | 0x00000000 | 0x000000dc | a7_clone |

### `rep_03`

- Clone parent return candidates: `[]`
- Wait pid args: `[2635873000, 478, 479, 2635873000]`
- Overlap: `[]`
- Reason: missing positive parent-side clone return candidate

| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |
| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |
| 3 | `waitid` | 95 | 0x00000000000001dd | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |
| 4 | `execve` | 221 | 0x0000000000000000 | 0x000000009d1c3a58 | 0x00000000010aafb0 | 0x0000000000000000 | return_only_register_snapshot | kernel |
| 22 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 24 | `execve` | 221 | 0x0000000000065904 | 0x000000009d60ec8c | 0x000000009d60eddc | None | target_ecall_boundary | target_sample |
| 26 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001de | 0x000000009d60ec8c | None | target_ecall_boundary | target_sample |
| 74 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 76 | `execve` | 221 | 0x0000000000065904 | 0x000000009d60ec8c | 0x000000009d60eddc | None | target_ecall_boundary | target_sample |
| 78 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001df | 0x000000009d60ec8c | None | target_ecall_boundary | target_sample |
| 130 | `waitid` | 95 | 0x0000000000000001 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |

- Raw clone-parent-like values: `[]`
- Raw wait-pid-like values: `[478, 479]`
- Raw overlap: `[]`
- Raw hint note: raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership

| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 7 | 7 | `SYSCALL_ENTRY` | 0x0000084c | 0x9d60ed2c | 0x00000000 | 0x00000002 | pid_like_register_snapshot |
| 19 | 19 | `SYSCALL_ENTRY` | 0x00094698 | 0x0000002f | 0x629f22d1 | 0x00000116 | pid_like_register_snapshot |
| 27 | 27 | `SYSCALL_ENTRY` | 0x0008e000 | 0x00003000 | 0x0008edc4 | 0x00095d20 | pid_like_register_snapshot |
| 29 | 29 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x00000010 | pid_like_register_snapshot |
| 31 | 31 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d60ec8c | 0x00000000 | 0x000000dc | a7_clone |
| 33 | 33 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001de | 0x00000004 | 0x9d60ec8c | waitid_pid_arg_like |
| 89 | 89 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x0000005f | a7_waitid |
| 91 | 91 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d60ec8c | 0x00000000 | 0x000000dc | a7_clone |
| 93 | 93 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001df | 0x00000004 | 0x9d60ec8c | waitid_pid_arg_like |

### `rep_04`

- Clone parent return candidates: `[]`
- Wait pid args: `[2635873000, 487, 488, 2635873000]`
- Overlap: `[]`
- Reason: missing positive parent-side clone return candidate

| Seq | Name | Nr | a0 | a1 | a2 | Return | Confidence | Owner |
| ---: | --- | ---: | --- | --- | --- | --- | --- | --- |
| 3 | `waitid` | 95 | 0x00000000000001e6 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |
| 4 | `execve` | 221 | 0x0000000000000000 | 0x000000009d1c3a58 | 0x00000000010aafb0 | 0x0000000000000000 | return_only_register_snapshot | kernel |
| 21 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | 0x0000000000000000 | paired_target_ecall_return | target_sample |
| 23 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001e7 | 0x000000009d377c8c | None | target_ecall_boundary | target_sample |
| 24 | `execve` | 221 | 0x0000000000065904 | 0x000000009d377c8c | 0x000000009d377ddc | None | target_ecall_boundary | target_sample |
| 73 | `clone` | 220 | 0x0000000000000011 | 0x0000000000000000 | 0x0000000000000000 | None | target_ecall_boundary | target_sample |
| 75 | `execve` | 221 | 0x0000000000065904 | 0x000000009d377c8c | 0x000000009d377ddc | None | target_ecall_boundary | target_sample |
| 77 | `waitid` | 95 | 0x0000000000000001 | 0x00000000000001e8 | 0x000000009d377c8c | None | target_ecall_boundary | target_sample |
| 127 | `waitid` | 95 | 0x0000000000000001 | 0x000000009d1c3ae8 | 0x000000009d1c3a00 | None | entry_only | unknown |

- Raw clone-parent-like values: `[]`
- Raw wait-pid-like values: `[487, 488]`
- Raw overlap: `[]`
- Raw hint note: raw pid-like snapshots exist, but clone parent return and wait pid argument do not close under strict semantic ownership

| Event | Record | Evt | a0 | a1 | a3 | a7 | Annotation |
| ---: | ---: | --- | --- | --- | --- | --- | --- |
| 7 | 7 | `SYSCALL_ENTRY` | 0x0000084c | 0x9d377d2c | 0x00000000 | 0x00000002 | pid_like_register_snapshot |
| 19 | 19 | `SYSCALL_ENTRY` | 0x00094698 | 0x0000002f | 0x62c892d1 | 0x00000116 | pid_like_register_snapshot |
| 27 | 27 | `SYSCALL_ENTRY` | 0x0008e000 | 0x00003000 | 0x0008edc4 | 0x00095d20 | pid_like_register_snapshot |
| 29 | 29 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x00000010 | pid_like_register_snapshot |
| 31 | 31 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001e7 | 0x00000004 | 0x9d377c8c | waitid_pid_arg_like |
| 33 | 33 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d377c8c | 0x00000000 | 0x000000dc | a7_clone |
| 89 | 89 | `SYSCALL_ENTRY` | 0x00000011 | 0x00000000 | 0x00000000 | 0x0000005f | a7_waitid |
| 91 | 91 | `SYSCALL_ENTRY` | 0x00065904 | 0x9d377c8c | 0x00000000 | 0x000000dc | a7_clone |
| 93 | 93 | `SYSCALL_ENTRY` | 0x00000001 | 0x000001e8 | 0x00000004 | 0x9d377c8c | waitid_pid_arg_like |

## Debug Artifacts

- JSON: `aggregate/process_chain_capacity_debug.json`
- Markdown: `aggregate/process_chain_capacity_debug.md`
