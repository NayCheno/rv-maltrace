# Process Tree Summary: process_chain

Status: PASS

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Observed Counts

- clone_or_fork: 2
- execve: 4
- wait: 2

## Edges

- target_parent_unresolved -> 203: edge_confidence=strong, evidence=clone_return, waitid
- target_parent_unresolved -> 204: edge_confidence=strong, evidence=clone_return, waitid

## Partial Edges

- none

## Unclosed Edges

- none

## PID Candidates

- clone seq 12: child_pid=203, wait_matched=yes
- clone seq 14: child_pid=204, wait_matched=yes
- wait PID candidates: 203, 204

## Limitations


## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
