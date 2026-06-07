# 35T Explanation Readiness: 35t-smallcap-r512-full-synthetic-matrix-20260521

Status: READY_FOR_TARGETED_BOARD_VALIDATION

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

Closure check: PASS

## Local Assessment

sufficient for the current 35T synthetic behavior-audit prototype; not sufficient for real malware detection or complete semantic reconstruction

## fd/path Flow

Overall: PARTIAL

- file_scan: PARTIAL; reps=5; flows=3
- batch_open_read_write: PARTIAL; reps=5; flows=16
- self_copy_sim: PARTIAL; reps=5; flows=6

## Process Tree

Overall: PARTIAL

- process_chain: PARTIAL; reps=5; strict_edges=0

## Function / Source Attribution

Overall: PARTIAL

- illegal_trap: function=available; source_line=unavailable
- process_chain: function=available; source_line=unavailable
- dynamic_executable_memory: function=available; source_line=unavailable
- file_scan: function=available; source_line=unavailable
- batch_open_read_write: function=available; source_line=unavailable
- self_copy_sim: function=available; source_line=unavailable

## Strong / Weak / Benign-overlap Separation

Overall: PASS
- ls: many_file_scan; expected benign overlap

## Targeted Board Validation Requirements

- capture reliable target syscall entry/return pairing for fd operations
- capture or side-channel dereferenced path strings for openat and execve
- capture parent-side positive clone/fork return child PID and wait PID in the same evidence window
- capture child runtime process map or equivalent PID/SATP/ASID ownership evidence across exec
- retain DWARF/debug-line metadata or an addr2line-compatible source-location side channel for source-line attribution

## Non-claims

- no CVA6 board claim
- no real malware detection claim
- no mature detector claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
