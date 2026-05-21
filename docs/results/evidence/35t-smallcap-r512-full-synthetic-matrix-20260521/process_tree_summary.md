# Process Tree Summary: process_chain

Status: PARTIAL

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Observed Counts

- clone_or_fork: 2
- execve: 2
- wait: 2

## Edges

- none strictly closed

## Limitations

- clone/wait shape exists, but strict parent-child edge closure is unavailable
- execve path strings are unavailable; pointers are not dereferenced
- one or more clone/fork events lack a positive child PID return

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
