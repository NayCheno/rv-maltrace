# fd/path Flow Summary: file_scan

Status: PARTIAL

Scope: Artix-7 35T / LiteX / VexRiscv only.

Claim level: 35T hardware-trace-assisted synthetic malware-like behavior audit prototype.

## Flows

- none fully linked

## Execve

- none

## Limitations

- argument-level path strings are unavailable in current evidence; pointers are not dereferenced
- some fd operations cannot be linked to a prior successful openat return
- some openat entries do not have paired successful fd return evidence

## Non-claims

- no real malware detection claim
- no classifier accuracy claim
- no complete semantic reconstruction claim
