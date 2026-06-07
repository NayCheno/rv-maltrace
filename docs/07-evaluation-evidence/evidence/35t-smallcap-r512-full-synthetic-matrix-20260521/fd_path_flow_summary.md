# fd/path Flow Summary: file_scan

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Flows

- fd 3 gen 1: status=closed, path=experiments/linux_behavior/malware_like/fixtures/scan_root, path_source=board_syscall_side_channel, path_pointer=unavailable, ops=getdents64, getdents64, close, events=openat, getdents64, getdents64, close, confidence=strong

## Execve

- none

## Return-only fd snapshots

- none

## Limitations


## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
